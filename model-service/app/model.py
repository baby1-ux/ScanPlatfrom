"""ScanMan 推理核心。

职责
----
1. **懒加载**两个 checkpoint（检测 / 分类），首次调用时才 import torch/transformers 并加载
   权重，进程内缓存；用 ``threading.Lock`` 保证并发请求下只加载一次。
2. 提供 **头尾截断（head+tail 6:4）** 的 token 级实现（与训练侧 ``src/utils.py::truncate_code``
   保持一致），保证不切断 token、长度不超过 max_length。
3. torch / transformers / checkpoint 任意缺失时进入 **降级模式（degraded）**，用一套确定性
   启发式规则给出 mock 结果，并在响应里明确标注 —— 绝不假装那是模型输出。
"""

from __future__ import annotations

import logging
import math
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .config import SERVICE_DIR, Settings, load_label_map, settings as global_settings, unwrap_label_map

logger = logging.getLogger("model_service.model")

# --------------------------------------------------------------------------- #
# CWE 名称表（内置，未知 id → None）
# --------------------------------------------------------------------------- #
_CWE_NAMES: Dict[str, Tuple[str, str]] = {
    # cwe id: (English short name, 中文名)
    "CWE-79": ("Cross-site Scripting (XSS)", "跨站脚本"),
    "CWE-89": ("SQL Injection", "SQL 注入"),
    "CWE-125": ("Out-of-bounds Read", "越界读取"),
    "CWE-787": ("Out-of-bounds Write", "越界写入"),
    "CWE-119": ("Buffer Overflow", "缓冲区溢出"),
    "CWE-120": ("Buffer Copy without Checking Size of Input", "不检查长度的缓冲区拷贝"),
    "CWE-20": ("Improper Input Validation", "输入校验不当"),
    "CWE-22": ("Path Traversal", "路径遍历"),
    "CWE-78": ("OS Command Injection", "操作系统命令注入"),
    "CWE-416": ("Use After Free", "释放后使用"),
    "CWE-476": ("NULL Pointer Dereference", "空指针解引用"),
    "CWE-94": ("Code Injection", "代码注入"),
    "CWE-502": ("Deserialization of Untrusted Data", "不可信数据反序列化"),
    "CWE-352": ("Cross-Site Request Forgery (CSRF)", "跨站请求伪造"),
    "CWE-434": ("Unrestricted Upload of File with Dangerous Type", "任意文件上传"),
    "CWE-798": ("Use of Hard-coded Credentials", "硬编码凭证"),
    "CWE-190": ("Integer Overflow or Wraparound", "整数溢出"),
    "CWE-200": ("Exposure of Sensitive Information", "敏感信息泄露"),
    "CWE-287": ("Improper Authentication", "认证不当"),
    "CWE-306": ("Missing Authentication for Critical Function", "关键功能缺少认证"),
    "CWE-862": ("Missing Authorization", "缺少授权"),
    "CWE-918": ("Server-Side Request Forgery (SSRF)", "服务端请求伪造"),
    "CWE-611": ("Improper Restriction of XML External Entity Reference", "XML 外部实体注入"),
    "CWE-732": ("Incorrect Permission Assignment for Critical Resource", "关键资源权限分配不当"),
    "CWE-400": ("Uncontrolled Resource Consumption", "资源消耗不受控"),
    "CWE-269": ("Improper Privilege Management", "权限管理不当"),
    "CWE-77": ("Command Injection", "命令注入"),
    "CWE-918 ": ("Server-Side Request Forgery (SSRF)", "服务端请求伪造"),
}


def cwe_name(cwe_id: Optional[str]) -> Optional[str]:
    """CWE id → 英文短名；未知返回 None（契约要求未知 id 时 name 为 null）。"""
    if not cwe_id:
        return None
    entry = _CWE_NAMES.get(str(cwe_id).strip().upper())
    return entry[0] if entry else None


def cwe_name_zh(cwe_id: Optional[str]) -> Optional[str]:
    """CWE id → 中文名；未知返回 None。"""
    if not cwe_id:
        return None
    entry = _CWE_NAMES.get(str(cwe_id).strip().upper())
    return entry[1] if entry else None


def normalize_cwe(raw: Any) -> Optional[str]:
    """把 label_map 里的值规整成 ``CWE-xxx`` 形式。

    支持 ``"CWE-787"`` / ``"cwe-787"`` / ``"CWE787"`` / ``"787"`` / ``79``。
    非 CWE 形式（例如 ``OTHER``）返回 None。
    """
    if raw is None:
        return None
    text = str(raw).strip().upper()
    if not text:
        return None
    if text.startswith("CWE-"):
        return text
    if text.startswith("CWE"):
        digits = text[3:].strip("- ").strip()
        if digits.isdigit():
            return f"CWE-{int(digits)}"
        return None
    if text.isdigit():
        return f"CWE-{int(text)}"
    return None


# --------------------------------------------------------------------------- #
# 头尾截断
# --------------------------------------------------------------------------- #
def head_tail_truncate(
    token_ids: Sequence[int],
    max_length: int,
    head_ratio: float = 0.6,
) -> List[int]:
    """头尾截断：保留前 ``head_ratio`` 与后 ``1-head_ratio`` 的 token。

    * 输入是 **已经分好的 token id**，因此天然不会切断 token；
    * 返回长度恒 ``<= max_length``（超长时恰好等于 ``max_length``）；
    * 长度不超限时原样返回副本（不修改入参）。

    与训练侧一致：60% 头 + 40% 尾。漏洞代码的关键信息（参数校验、循环边界、``free()``）
    常出现在函数首尾，比单纯截尾保留更多有效信息。
    """
    ids = list(token_ids)
    if max_length <= 0:
        return []
    if len(ids) <= max_length:
        return ids
    ratio = head_ratio if 0.0 <= head_ratio <= 1.0 else 0.6
    head_len = int(max_length * ratio)
    head_len = max(0, min(head_len, max_length))
    tail_len = max_length - head_len
    if head_len == 0:
        return ids[-tail_len:]
    if tail_len == 0:
        return ids[:head_len]
    return ids[:head_len] + ids[-tail_len:]


# --------------------------------------------------------------------------- #
# 降级启发式规则（HEURISTIC-MOCK）
# --------------------------------------------------------------------------- #
DEGRADED_ENGINE_TAG = "HEURISTIC-MOCK/v1"

#: 无任何信号时的低置信先验（保证分类模式总能给出一个 Top-K）
_PRIOR_WEIGHT = 0.03
_PRIOR_CWES: Tuple[str, ...] = (
    "CWE-79",
    "CWE-89",
    "CWE-787",
    "CWE-125",
    "CWE-119",
    "CWE-20",
    "CWE-22",
    "CWE-78",
    "CWE-416",
    "CWE-476",
    "CWE-94",
    "CWE-502",
    "CWE-352",
    "CWE-434",
    "CWE-798",
)


@dataclass(frozen=True)
class HeuristicRule:
    """一条启发式规则：命中即给对应 CWE 加分。"""

    rule_id: str
    cwe: str
    weight: float
    description: str
    patterns: Tuple[str, ...]
    flags: int = re.IGNORECASE


_RULES: Tuple[HeuristicRule, ...] = (
    HeuristicRule(
        rule_id="unsafe-string-copy",
        cwe="CWE-787",
        weight=0.60,
        description="未做长度校验的字符串拷贝/格式化（strcpy/strcat/sprintf/vsprintf）写入固定缓冲区",
        patterns=(
            r"\bstrcpy\s*\(",
            r"\bstrcat\s*\(",
            r"\bsprintf\s*\(",
            r"\bvsprintf\s*\(",
            r"\bwcscpy\s*\(",
            r"\blstrcpy\s*\(",
        ),
    ),
    HeuristicRule(
        rule_id="unbounded-read",
        cwe="CWE-119",
        weight=0.55,
        description="无边界检查的输入读取（gets/scanf %s）",
        patterns=(
            r"\bgets\s*\(",
            r"\bscanf\s*\([^)]*%s",
        ),
    ),
    HeuristicRule(
        rule_id="raw-memory-copy",
        cwe="CWE-787",
        weight=0.40,
        description="memcpy/memmove/copy 使用未经校验的长度参数",
        patterns=(
            r"\bmemcpy\s*\(",
            r"\bmemmove\s*\(",
            r"\bRtlCopyMemory\s*\(",
        ),
    ),
    HeuristicRule(
        rule_id="sql-string-concat",
        cwe="CWE-89",
        weight=0.70,
        description="SQL 语句由字符串拼接 / 格式化构造（存在注入）",
        patterns=(
            r"[\"'][^\"'\n]{0,200}?\b(SELECT|INSERT|UPDATE|DELETE)\b[\s\S]{0,200}?[\"']\s*(?:\+|\.)\s*\w",
            r"\b(SELECT|INSERT|UPDATE|DELETE)\b[\s\S]{0,200}?[\"']\s*\+",
            r"(execute|exec|query|Query|rawQuery)\s*\(\s*[\"'][^\"']*\b(SELECT|INSERT|UPDATE|DELETE)\b",
            r"(execute|exec|query)\s*\([^)]*%\s*\(",
            r"(execute|exec|query)\s*\([^)]*\.format\s*\(",
            r"f[\"'][^\"']*\b(SELECT|INSERT|UPDATE|DELETE)\b[^\"']*\{",
            r"\bconcat\s*\([^)]*\b(SELECT|INSERT|UPDATE|DELETE)\b",
        ),
    ),
    HeuristicRule(
        rule_id="code-injection",
        cwe="CWE-94",
        weight=0.70,
        description="动态执行代码（eval/exec/Function 构造）",
        patterns=(
            r"\beval\s*\(",
            r"\bexec\s*\(",
            r"\bassert\s*\(\s*eval\b",
            r"new\s+Function\s*\(",
            r"\bScriptEngine\b[\s\S]{0,200}?\.eval\s*\(",
        ),
    ),
    HeuristicRule(
        rule_id="xss-sink",
        cwe="CWE-79",
        weight=0.70,
        description="把不可信数据写入 HTML/JS 输出汇点（innerHTML/document.write/未转义回显）",
        patterns=(
            r"\.innerHTML\s*=",
            r"\bdocument\.write\s*\(",
            r"dangerouslySetInnerHTML",
            r"\becho\s+\$_(GET|POST|REQUEST)",
            r"<\?=\s*\$_(GET|POST|REQUEST)",
            r"\.html\s*\(\s*[^)]*\$_(GET|POST|REQUEST)",
            r"print\s*\(\s*request\.(args|form|GET|POST)",
        ),
    ),
    HeuristicRule(
        rule_id="command-injection",
        cwe="CWE-78",
        weight=0.70,
        description="命令拼接执行（system/popen/shell=True/Runtime.exec）",
        patterns=(
            r"\bsystem\s*\(",
            r"\bpopen\s*\(",
            r"\bos\.system\s*\(",
            r"\bos\.popen\s*\(",
            r"subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True",
            r"Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(",
            r"\bProcessBuilder\b",
            r"child_process[\s\S]{0,80}?\bexec\s*\(",
        ),
    ),
    HeuristicRule(
        rule_id="unsafe-deserialization",
        cwe="CWE-502",
        weight=0.70,
        description="反序列化不可信数据（pickle/yaml.load/unserialize/readObject）",
        patterns=(
            r"\bpickle\.loads?\s*\(",
            r"\bcPickle\.loads?\s*\(",
            r"\byaml\.load\s*\(",
            r"\bunserialize\s*\(",
            r"\breadObject\s*\(",
            r"\bObjectInputStream\b",
            r"\bMarshal\.load\b",
            r"\bdeserialize\s*\(",
        ),
    ),
    HeuristicRule(
        rule_id="hardcoded-credentials",
        cwe="CWE-798",
        weight=0.60,
        description="源码中硬编码口令/密钥/token",
        patterns=(
            r"(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|private[_-]?key)\s*[:=]\s*[\"'][^\"']{3,}[\"']",
            r"(PASSWORD|SECRET|API_KEY|TOKEN)\s*[:=]\s*[\"'][^\"']{3,}[\"']",
            r"BEGIN\s+(RSA|OPENSSH|PRIVATE)\s+PRIVATE\s+KEY",
        ),
    ),
    HeuristicRule(
        rule_id="path-traversal",
        cwe="CWE-22",
        weight=0.55,
        description="用外部输入直接拼接文件路径（路径遍历）",
        patterns=(
            r"os\.path\.join\([^)]*(request|params|args|input|user)",
            r"\bopen\s*\([^)]*(request|params|args|user_input|filename)",
            r"(readFile|createReadStream|sendFile|fopen)\s*\([^)]*(req\.|request\.|params|query)",
            r"\bFile\s*\([^)]*(request|params|getParameter)",
        ),
    ),
    HeuristicRule(
        rule_id="file-upload",
        cwe="CWE-434",
        weight=0.45,
        description="文件上传未校验类型/后缀",
        patterns=(
            r"\bsave\s*\([^)]*filename",
            r"MultipartFile\b",
            r"\bmove_uploaded_file\s*\(",
            r"getOriginalFilename\s*\(",
        ),
    ),
    HeuristicRule(
        rule_id="weak-random",
        cwe="CWE-330",
        weight=0.30,
        description="使用非密码学安全随机数",
        patterns=(r"\brand\s*\(\s*\)", r"\bMath\.random\s*\(", r"\bjava\.util\.Random\b"),
    ),
    HeuristicRule(
        rule_id="ssrf",
        cwe="CWE-918",
        weight=0.50,
        description="用外部输入直接构造请求地址（SSRF）",
        patterns=(
            r"\brequests\.(get|post)\s*\([^)]*(request|params|args|url_from_user)",
            r"(HttpClient|URL|fetch|axios)\s*[\.(][^)]*(request|params|query|req\.)",
        ),
    ),
    HeuristicRule(
        rule_id="xxe",
        cwe="CWE-611",
        weight=0.50,
        description="XML 解析未禁用外部实体",
        patterns=(
            r"DocumentBuilderFactory[\s\S]{0,300}?newDocumentBuilder\s*\(",
            r"\betree\.parse\s*\(",
            r"\blxml\.etree\b",
        ),
    ),
    HeuristicRule(
        rule_id="input-validation",
        cwe="CWE-20",
        weight=0.30,
        description="直接使用未经校验的外部输入（atoi/request 取值）",
        patterns=(
            r"\batoi\s*\(",
            r"request\.(GET|POST|args|form)\s*[\[\.]",
            r"\$_REQUEST\s*\[",
        ),
    ),
    HeuristicRule(
        rule_id="info-exposure",
        cwe="CWE-200",
        weight=0.30,
        description="异常/堆栈直接回显给调用方",
        patterns=(
            r"printStackTrace\s*\(",
            r"traceback\.print_exc\s*\(",
            r"(response|res)\.(write|send)\s*\([^)]*(exception|err|stack)",
        ),
    ),
    HeuristicRule(
        rule_id="missing-auth",
        cwe="CWE-306",
        weight=0.35,
        description="关键接口未见鉴权（需要人工确认）",
        patterns=(
            r"@(app|router)\.(get|post|put|delete)\s*\(\s*[\"']/(admin|delete|update|upload|exec)",
            r"(app|router)\.(get|post|put|delete)\s*\(\s*[\"']/(admin|delete|update|upload|exec)",
        ),
    ),
)

#: 动态规则（需要跨语句判定），在 :func:`_dynamic_hits` 中实现
_DYNAMIC_RULES: Tuple[Tuple[str, str, float, str], ...] = (
    ("use-after-free", "CWE-416", 0.65, "free/delete 之后仍引用同一对象（释放后使用）"),
    ("null-deref", "CWE-476", 0.40, "malloc/返回值未判空即解引用（空指针）"),
    ("small-buffer", "CWE-787", 0.15, "定长小缓冲区（<=32）配合拷贝函数，越界风险高"),
    ("missing-bounds-check", "CWE-125", 0.25, "数组下标来自外部输入且未见边界检查"),
)


@dataclass
class HeuristicHit:
    rule_id: str
    cwe: str
    weight: float
    description: str
    evidence: str = ""


@dataclass
class HeuristicVerdict:
    """降级模式的确定性结果。"""

    vulnerable_probability: float
    safe_probability: float
    cwe_scores: Dict[str, float] = field(default_factory=dict)
    hits: List[HeuristicHit] = field(default_factory=list)

    @property
    def top_cwe(self) -> Optional[str]:
        if not self.cwe_scores:
            return None
        return max(self.cwe_scores.items(), key=lambda kv: (kv[1], kv[0]))[0]


_DYNAMIC_PATTERNS = {
    # free(x) ... 之后再出现 x->  / x[  / *x
    "use-after-free": re.compile(
        r"\b(?:free|delete|kfree)\s*\(?\s*&?(\w+)\s*\)?\s*;[\s\S]{0,400}?\b\1\s*(?:->|\[|\.|\)|\*|;)",
        re.IGNORECASE,
    ),
    # p = malloc(...) 且全文没有对 p 的判空
    "null-deref-alloc": re.compile(
        r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc|new)\s*[\(\[]",
        re.IGNORECASE,
    ),
    "small-buffer-decl": re.compile(
        r"\b(?:char|wchar_t|unsigned\s+char|uint8_t)\s+\w+\s*\[\s*(\d{1,3})\s*\]",
        re.IGNORECASE,
    ),
    "buffer-copy-call": re.compile(
        r"\b(?:strcpy|strcat|sprintf|vsprintf|memcpy|memmove|gets)\s*\(",
        re.IGNORECASE,
    ),
    "index-from-input": re.compile(
        r"\w+\s*\[\s*(?:atoi\s*\(|\$_?(?:GET|POST|REQUEST)|request\.|req\.|params|argv)",
        re.IGNORECASE,
    ),
    "bounds-check": re.compile(
        r"(?:if\s*\([^)]*(?:<|<=|>|>=)[^)]*\)|\blen\s*\(|\bsizeof\b|\bmin\s*\(|\bassert\s*\()",
        re.IGNORECASE,
    ),
    "null-check": re.compile(
        r"(?:!\s*{var}|{var}\s*==\s*(?:NULL|null|nullptr)|{var}\s*!=\s*(?:NULL|null|nullptr)|if\s*\(\s*{var}\s*\))",
        re.IGNORECASE,
    ),
}


def _first_match_evidence(pattern: str, code: str, flags: int = re.IGNORECASE) -> str:
    """取第一条命中的片段（截断到 80 字符），作为"证据"，便于人工核对。"""
    try:
        match = re.search(pattern, code, flags)
    except re.error:  # pragma: no cover - 规则写错时不应崩服务
        return ""
    if not match:
        return ""
    snippet = match.group(0).replace("\n", " ").strip()
    if pattern in (p for rule in _RULES for p in rule.patterns) and len(snippet) > 80:
        snippet = snippet[:80] + "…"
    return snippet


def _dynamic_hits(code: str) -> List[HeuristicHit]:
    """跨语句的启发式判定（UAF / 空指针 / 小缓冲区 / 缺边界检查）。"""
    hits: List[HeuristicHit] = []

    uaf = _DYNAMIC_PATTERNS["use-after-free"].search(code)
    if uaf:
        hits.append(
            HeuristicHit(
                rule_id="use-after-free",
                cwe="CWE-416",
                weight=0.65,
                description="free/delete 之后仍引用同一对象（释放后使用）",
                evidence=uaf.group(0).replace("\n", " ")[:80],
            )
        )

    alloc_names = {m.group(1) for m in _DYNAMIC_PATTERNS["null-deref-alloc"].finditer(code)}
    for name in sorted(alloc_names):
        deref = re.search(rf"\b{re.escape(name)}\s*->", code) or re.search(
            rf"\*\s*{re.escape(name)}\b", code
        )
        if not deref:
            continue
        check = re.search(
            _DYNAMIC_PATTERNS["null-check"].pattern.replace("{var}", re.escape(name)),
            code,
            re.IGNORECASE,
        )
        if not check:
            hits.append(
                HeuristicHit(
                    rule_id="null-deref",
                    cwe="CWE-476",
                    weight=0.40,
                    description="malloc/返回值未判空即解引用（空指针）",
                    evidence=deref.group(0).replace("\n", " ")[:80],
                )
            )
            break

    has_copy = _DYNAMIC_PATTERNS["buffer-copy-call"].search(code)
    if has_copy:
        small = [
            m
            for m in _DYNAMIC_PATTERNS["small-buffer-decl"].finditer(code)
            if m.group(1).isdigit() and int(m.group(1)) <= 32
        ]
        if small:
            hits.append(
                HeuristicHit(
                    rule_id="small-buffer",
                    cwe="CWE-787",
                    weight=0.15,
                    description="定长小缓冲区（<=32）配合拷贝函数，越界风险高",
                    evidence=small[0].group(0).strip()[:80],
                )
            )

    idx = _DYNAMIC_PATTERNS["index-from-input"].search(code)
    if idx and not _DYNAMIC_PATTERNS["bounds-check"].search(code):
        hits.append(
            HeuristicHit(
                rule_id="missing-bounds-check",
                cwe="CWE-125",
                weight=0.25,
                description="数组下标来自外部输入且未见边界检查",
                evidence=idx.group(0).replace("\n", " ")[:80],
            )
        )
    return hits


def heuristic_analyze(code: str) -> HeuristicVerdict:
    """**降级模式**的确定性启发式分析。

    注意：这是 mock，**不是** ScanMan 模型。它只做高信号正则匹配 + 简单打分，
    目的是在 checkpoint/torch 不可用时让整条链路（前端 → Node → 本服务）仍可演示。
    """
    text = code or ""
    hits: List[HeuristicHit] = []
    cwe_scores: Dict[str, float] = {cwe: _PRIOR_WEIGHT for cwe in _PRIOR_CWES}

    for rule in _RULES:
        for pattern in rule.patterns:
            evidence = _first_match_evidence(pattern, text, rule.flags)
            if evidence:
                hits.append(
                    HeuristicHit(
                        rule_id=rule.rule_id,
                        cwe=rule.cwe,
                        weight=rule.weight,
                        description=rule.description,
                        evidence=evidence,
                    )
                )
                cwe_scores[rule.cwe] = cwe_scores.get(rule.cwe, 0.0) + rule.weight
                break  # 同一规则只计一次

    for hit in _dynamic_hits(text):
        hits.append(hit)
        cwe_scores[hit.cwe] = cwe_scores.get(hit.cwe, 0.0) + hit.weight

    raw_score = sum(hit.weight for hit in hits)
    # 0 → 0.02；随信号强度饱和到 0.98。确定性、可复现。
    probability = 0.02 + 0.96 * (1.0 - math.exp(-3.2 * raw_score))
    probability = max(0.0, min(0.98, probability))
    probability = round(probability, 4)
    return HeuristicVerdict(
        vulnerable_probability=probability,
        safe_probability=round(1.0 - probability, 4),
        cwe_scores=cwe_scores,
        hits=hits,
    )


# --------------------------------------------------------------------------- #
# 任务状态
# --------------------------------------------------------------------------- #
@dataclass
class TaskState:
    """单个任务的加载状态。"""

    task: str
    checkpoint: Optional[Path] = None
    available: bool = False
    reason: Optional[str] = None
    label_map: Optional[Dict[str, Any]] = None
    num_labels: Optional[int] = None
    tokenizer: Any = None
    model: Any = None

    def info(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "available": bool(self.available),
            "checkpoint": str(self.checkpoint) if self.checkpoint else None,
            "numLabels": self.num_labels,
            "labelMap": self.label_map,
        }
        if self.task == "classification":
            payload["cweCount"] = _count_cwes(self.label_map)
        return payload


def _count_cwes(label_map: Optional[Dict[str, Any]]) -> Optional[int]:
    if not label_map:
        return None
    found = set()
    for key, value in label_map.items():
        for token in (key, value):
            normalized = normalize_cwe(token)
            if normalized:
                found.add(normalized)
    return len(found) if found else None


# --------------------------------------------------------------------------- #
# 推理引擎
# --------------------------------------------------------------------------- #
class InferenceEngine:
    """懒加载 + 线程安全的推理引擎（进程内单例，见文件末尾 ``engine``）。"""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._lock = threading.Lock()
        self._loaded = False

        self.torch: Any = None
        self.transformers: Any = None
        self.torch_available = False
        self.transformers_available = False
        self.device: Optional[str] = None
        self._import_error: Optional[str] = None

        self.detection = TaskState(task="detection", checkpoint=settings.detection_checkpoint)
        self.classification = TaskState(
            task="classification", checkpoint=settings.classification_checkpoint
        )

    # -- 运行环境探测 ---------------------------------------------------- #
    def _probe_runtime(self) -> None:
        """探测 torch / transformers 是否可用，并解析 device（只做一次）。"""
        if self._import_error is not None or self.torch_available or self.transformers_available:
            return
        problems: List[str] = []

        try:
            import torch  # noqa: PLC0415 - 懒加载是刻意设计

            self.torch = torch
            self.torch_available = True
        except Exception as exc:  # pragma: no cover - 取决于环境
            problems.append(f"torch 不可用（{type(exc).__name__}: {exc}）")
            logger.warning("torch 导入失败：%s", exc)

        try:
            import transformers  # noqa: PLC0415

            self.transformers = transformers
            self.transformers_available = True
        except Exception as exc:  # pragma: no cover - 取决于环境
            problems.append(f"transformers 不可用（{type(exc).__name__}: {exc}）")
            logger.warning("transformers 导入失败：%s", exc)

        if self.torch_available:
            requested = (self.settings.model_device or "auto").strip().lower()
            if requested in {"", "auto"}:
                try:
                    cuda = bool(self.torch.cuda.is_available())
                except Exception:  # pragma: no cover
                    cuda = False
                self.device = "cuda" if cuda else "cpu"
            else:
                self.device = requested
            if self.device.startswith("cuda") and not self.torch.cuda.is_available():
                logger.warning("MODEL_DEVICE=%s 但 CUDA 不可用，回退 cpu", self.device)
                self.device = "cpu"

        self._import_error = "；".join(problems) if problems else ""

    # -- 懒加载 ---------------------------------------------------------- #
    def ensure_loaded(self) -> None:
        """加载两个任务（并发下只执行一次）。任何异常都转成"不可用 + 原因"，不向上抛。"""
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            self._probe_runtime()
            if self.settings.force_degraded:
                reason = "ML_FORCE_DEGRADED=1：已手动强制降级，跳过所有权重加载"
                for state in (self.detection, self.classification):
                    state.available = False
                    state.reason = reason
                    state.label_map = load_label_map(state.checkpoint) if state.checkpoint else None
                logger.warning(reason)
            else:
                self._load_task(self.detection)
                self._load_task(self.classification)
            self._loaded = True

    def _load_task(self, state: TaskState) -> None:
        """加载单个任务；失败时写 state.reason 并保持 available=False。

        训练产物有两种常见摆放，两种都支持：
          A. 标准 HF 目录：``best/`` 里同时有 ``config.json`` + 权重 + tokenizer；
          B. ScanMan 训练脚本的 ``best/``：**没有 config.json**，权重是
             ``encoder.*``（RobertaModel）+ ``classifier.weight/bias``（单层 Linear，
             CLS pooling，见 config.yaml 的 ``pooling: cls``）。
             —— 训练侧是自定义 ``VulnClassifier`` 包装，不是 HF 的
             ``…ForSequenceClassification``，所以这里从张量形状反推配置后重建。
        """
        checkpoint = state.checkpoint
        if checkpoint is None:
            state.reason = (
                f"未发现 {state.task} checkpoint（可用 {_ENV_FOR[state.task]} 显式指定 best/ 目录）"
            )
            return
        checkpoint = Path(checkpoint)
        if not checkpoint.is_dir():
            state.reason = f"{state.task} checkpoint 目录不存在：{checkpoint}"
            return

        state.label_map = unwrap_label_map(load_label_map(checkpoint))
        if not self.torch_available or not self.transformers_available:
            state.reason = (
                f"torch/transformers 不可用（{self._import_error or '未知原因'}），"
                f"已定位到 {state.task} checkpoint: {checkpoint}"
            )
            return

        tokenizer_dir, weights_dir = _resolve_load_dirs(checkpoint)
        if weights_dir is None:
            state.reason = (
                f"{state.task} checkpoint 缺少权重文件"
                f"（pytorch_model.bin / model.safetensors）：{checkpoint}"
            )
            return
        if tokenizer_dir is None:
            state.reason = (
                f"{state.task} checkpoint 缺少分词器文件（tokenizer.json / vocab.txt）：{checkpoint}"
            )
            return

        run_config = _read_run_config(checkpoint)
        try:
            tokenizer = self.transformers.AutoTokenizer.from_pretrained(
                str(tokenizer_dir), local_files_only=True
            )
            model, num_labels, layout = _load_model(
                torch_module=self.torch,
                transformers=self.transformers,
                weights_dir=weights_dir,
                checkpoint=checkpoint,
                base_model_name=run_config.get("model_name"),
                pooling=run_config.get("pooling", "cls"),
                dropout=run_config.get("dropout", 0.1),
                fallback_num_labels=_num_labels_from_map(state.label_map),
            )
            model.eval()
            if self.device and self.device.startswith("cuda"):
                model.to(self.device)
        except Exception as exc:
            state.reason = f"{state.task} checkpoint 加载失败：{type(exc).__name__}: {exc}"
            logger.warning(state.reason, exc_info=True)
            return

        state.tokenizer = tokenizer
        state.model = model
        state.available = True
        state.reason = None
        state.num_labels = _num_labels(model, state.label_map) or num_labels
        logger.info(
            "%s 模型加载成功：%s（device=%s, num_labels=%s, layout=%s）",
            state.task,
            checkpoint,
            self.device,
            state.num_labels,
            layout,
        )

    # -- 健康 / 信息 ------------------------------------------------------ #
    def probe(self) -> None:
        """供 /health 使用：确保运行环境已探测、模型已尝试加载。"""
        self.ensure_loaded()

    @property
    def fully_available(self) -> bool:
        return self.detection.available and self.classification.available

    @property
    def any_available(self) -> bool:
        return self.detection.available or self.classification.available

    def degraded_reason(self) -> Optional[str]:
        parts = []
        for state in (self.detection, self.classification):
            if not state.available and state.reason:
                parts.append(f"[{state.task}] {state.reason}")
        if not parts:
            return None
        return (
            f"降级模式：{'；'.join(parts)}。"
            f"以下结果由内置启发式规则（{DEGRADED_ENGINE_TAG}）模拟，**不是** ScanMan 模型输出，仅用于链路联调/演示。"
        )

    def model_name(self) -> str:
        if self.any_available:
            return self.settings.model_name
        return "heuristic-mock"

    def health(self) -> Dict[str, Any]:
        self.ensure_loaded()
        return {
            "status": "ok",
            "modelServed": bool(self.fully_available),
            "degraded": (not self.fully_available),
            "degradedReason": self.degraded_reason(),
            "modelName": self.model_name(),
            "detectionCheckpoint": str(self.detection.checkpoint) if self.detection.checkpoint else None,
            "classificationCheckpoint": str(self.classification.checkpoint)
            if self.classification.checkpoint
            else None,
            "device": self.device,
            "torchAvailable": bool(self.torch_available),
            "transformersAvailable": bool(self.transformers_available),
            "version": self.settings.version,
        }

    def model_info(self) -> Dict[str, Any]:
        self.ensure_loaded()
        return {
            "tasks": {
                "detection": self.detection.info(),
                "classification": self.classification.info(),
            },
            "device": self.device,
            "maxLength": int(self.settings.max_length),
            "detectionThreshold": float(self.settings.detection_threshold),
            "degraded": (not self.fully_available),
            "degradedReason": self.degraded_reason(),
        }

    # -- 分词 ------------------------------------------------------------ #
    def _encode(self, state: TaskState, code: str) -> Dict[str, List[int]]:
        """头尾截断 + 特殊 token 组装，保证 ``len(input_ids) <= max_length``。"""
        tokenizer = state.tokenizer
        max_length = int(self.settings.max_length)
        body = tokenizer(code, add_special_tokens=False, truncation=False, verbose=False)[
            "input_ids"
        ]
        if not isinstance(body, list):  # pragma: no cover - 极端 tokenizer 行为
            body = list(body)
        budget = max(1, max_length - _special_token_count(tokenizer))
        body = head_tail_truncate(body, budget, self.settings.head_ratio)
        input_ids = _wrap_with_special_tokens(tokenizer, body)
        if len(input_ids) > max_length:
            input_ids = input_ids[:max_length]
        return {"input_ids": input_ids, "attention_mask": [1] * len(input_ids)}

    # -- 单任务推理 ------------------------------------------------------ #
    def _run_detection(self, code: str) -> Tuple[float, float]:
        """返回 (vulnerable_probability, safe_probability)，softmax 二分类。"""
        state = self.detection
        encoded = self._encode(state, code)
        torch = self.torch
        inputs = {
            "input_ids": torch.tensor([encoded["input_ids"]], dtype=torch.long),
            "attention_mask": torch.tensor([encoded["attention_mask"]], dtype=torch.long),
        }
        if self.device:
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
        with torch.inference_mode():
            logits = state.model(**inputs).logits
            probs = torch.softmax(logits, dim=-1)[0].tolist()

        label_map = state.label_map or {}
        vulnerable_index = _index_of_label(label_map, ("vulnerable", "1", 1), default=1)
        vulnerable = float(probs[vulnerable_index]) if vulnerable_index < len(probs) else 0.0
        safe_index = _index_of_label(label_map, ("safe", "0", 0), default=0)
        safe = float(probs[safe_index]) if safe_index < len(probs) else 0.0
        if not label_map:
            # 无 label_map：退化到"最后一维 = 漏洞"的惯例
            vulnerable = float(probs[-1])
            safe = float(probs[0]) if len(probs) > 1 else 0.0
        total = vulnerable + safe
        if total > 0:
            vulnerable, safe = vulnerable / total, safe / total
        return round(vulnerable, 6), round(safe, 6)

    def _run_classification(self, code: str, top_k: int) -> List[Tuple[str, float]]:
        """返回归一化后的 [(cwe, probability)]，按概率降序，长度 <= top_k。"""
        state = self.classification
        encoded = self._encode(state, code)
        torch = self.torch
        inputs = {
            "input_ids": torch.tensor([encoded["input_ids"]], dtype=torch.long),
            "attention_mask": torch.tensor([encoded["attention_mask"]], dtype=torch.long),
        }
        if self.device:
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
        with torch.inference_mode():
            logits = state.model(**inputs).logits
            probs = torch.softmax(logits, dim=-1)[0].tolist()

        label_map = state.label_map or {}
        entries: List[Tuple[int, str, float]] = []
        for index, probability in enumerate(probs):
            raw = _label_name_for_index(label_map, index)
            cwe = normalize_cwe(raw)
            entries.append((index, cwe if cwe else (raw or f"LABEL-{index}"), float(probability)))
        entries.sort(key=lambda item: (-item[2], item[0]))
        ranked: List[Tuple[str, float]] = []
        for _index, label, probability in entries[: max(1, top_k)]:
            ranked.append((label, round(probability, 6)))
        return ranked


# --------------------------------------------------------------------------- #
# 辅助
# --------------------------------------------------------------------------- #
_ENV_FOR = {
    "detection": "DETECTION_CHECKPOINT",
    "classification": "CLASSIFICATION_CHECKPOINT",
}

#: run 目录名里出现这些片段 → 认为是 CodeBERT/RoBERTa 系（否则按 BERT 处理）
_ROBERTA_LIKE = ("codebert", "roberta", "graphcodebert", "unixcoder", "graphcode")


# ---- 分词器的特殊 token（transformers 4.x / 5.x 都可用） -------------------- #
def _wrap_with_special_tokens(tokenizer: Any, token_ids: Sequence[int]) -> List[int]:
    """给 token id 序列套上特殊 token（``<s> … </s>``）。

    transformers 5.x **删除了** ``tokenizer.build_inputs_with_special_tokens``，
    所以这里做两级兼容：先试旧 API，再退回手工拼 ``cls/sep``（或 ``bos/eos``）。
    """
    build = getattr(tokenizer, "build_inputs_with_special_tokens", None)
    if callable(build):
        try:
            return [int(item) for item in build(list(token_ids))]
        except Exception:  # pragma: no cover - 仅旧 API 异常时走下面
            logger.debug("build_inputs_with_special_tokens 调用失败，改用手工拼接", exc_info=True)

    prefix = getattr(tokenizer, "cls_token_id", None)
    suffix = getattr(tokenizer, "sep_token_id", None)
    if prefix is None:
        prefix = getattr(tokenizer, "bos_token_id", None)
    if suffix is None:
        suffix = getattr(tokenizer, "eos_token_id", None)
    wrapped = [int(item) for item in token_ids]
    if prefix is not None:
        wrapped = [int(prefix)] + wrapped
    if suffix is not None:
        wrapped = wrapped + [int(suffix)]
    return wrapped


def _special_token_count(tokenizer: Any) -> int:
    """特殊 token 占用的位置数（用于算截断预算）。"""
    return max(0, len(_wrap_with_special_tokens(tokenizer, [])))


# ---- run 目录的 config.yaml ------------------------------------------------ #
def _read_run_config(checkpoint: Path) -> Dict[str, Any]:
    """读取 ``<run>/config.yaml``（best/ 的上一级），拿模型名 / pooling / dropout。"""
    info: Dict[str, Any] = {}
    for candidate in (checkpoint / "config.yaml", checkpoint.parent / "config.yaml"):
        if not candidate.is_file():
            continue
        try:
            import yaml  # noqa: PLC0415 - 可选依赖，失败就跳过
        except Exception:  # pragma: no cover - 没装 pyyaml
            return info
        try:
            with candidate.open("r", encoding="utf-8") as fp:
                data = yaml.safe_load(fp) or {}
        except Exception as exc:  # pragma: no cover
            logger.debug("读取 %s 失败：%s", candidate, exc)
            return info
        model_section = data.get("model") or {}
        info["model_name"] = model_section.get("name") or model_section.get("model_name")
        info["pooling"] = model_section.get("pooling") or "cls"
        info["dropout"] = model_section.get("dropout", 0.1)
        info["task"] = (data.get("task") or {}).get("type")
        info["num_labels"] = (data.get("task") or {}).get("num_labels")
        return info
    return info


def _num_labels_from_map(label_map: Optional[Dict[str, Any]]) -> Optional[int]:
    if not label_map:
        return None
    return len(label_map) if label_map else None


# ---- 权重读取 -------------------------------------------------------------- #
def _load_state_dict(torch_module: Any, weights_dir: Path) -> Dict[str, Any]:
    """读取 ``pytorch_model.bin`` / ``model.safetensors``（含分片）。"""
    merged: Dict[str, Any] = {}
    bin_files = sorted(weights_dir.glob("pytorch_model*.bin"))
    st_files = sorted(weights_dir.glob("model*.safetensors"))
    if bin_files:
        for path in bin_files:
            merged.update(torch_module.load(str(path), map_location="cpu", weights_only=True))
        return merged
    if st_files:
        try:
            from safetensors.torch import load_file  # noqa: PLC0415
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(f"需要 safetensors 才能读取 {st_files[0].name}：{exc}") from exc
        for path in st_files:
            merged.update(load_file(str(path)))
        return merged
    raise FileNotFoundError(f"{weights_dir} 下没有找到任何权重文件（*.bin / *.safetensors）")


def _encoder_prefix(state: Dict[str, Any]) -> Optional[str]:
    """找出 base model 的属性前缀（``roberta`` / ``bert`` / ``encoder`` …）。"""
    for key in state:
        parts = key.split(".")
        if len(parts) >= 3 and parts[0] not in {"classifier"}:
            if parts[1] in {"embeddings", "encoder"}:
                return parts[0]
    return None


def _infer_config(
    transformers: Any,
    state: Dict[str, Any],
    prefix: str,
    base_model_name: Optional[str],
    num_labels: int,
) -> Any:
    """从权重张量形状反推 ``*Config`` —— checkpoint 里没有 config.json 时的唯一办法。"""
    name = (base_model_name or "").lower()
    if any(token in name for token in _ROBERTA_LIKE):
        is_roberta = True
    elif "bert" in name or "electra" in name:
        is_roberta = "roberta" in name
    else:
        # 名字未知（例如本地路径 models/microsoft__codebert-base）→ 默认 RoBERTa 系
        is_roberta = True
    config_cls = transformers.RobertaConfig if is_roberta else transformers.BertConfig

    root = f"{prefix}.embeddings.word_embeddings.weight"
    if root not in state:
        raise ValueError(f"权重里找不到 {root}，无法反推模型结构")
    word_emb = state[root]
    kwargs: Dict[str, Any] = {
        "vocab_size": int(word_emb.shape[0]),
        "hidden_size": int(word_emb.shape[1]),
        "num_labels": int(num_labels),
    }
    position_key = f"{prefix}.embeddings.position_embeddings.weight"
    if position_key in state:
        kwargs["max_position_embeddings"] = int(state[position_key].shape[0])
    token_type_key = f"{prefix}.embeddings.token_type_embeddings.weight"
    if token_type_key in state:
        kwargs["type_vocab_size"] = int(state[token_type_key].shape[0])

    layer_ids = set()
    for key in state:
        parts = key.split(".")
        if len(parts) > 3 and parts[0] == prefix and parts[1] == "encoder" and parts[2] == "layer":
            if parts[3].isdigit():
                layer_ids.add(int(parts[3]))
    if layer_ids:
        kwargs["num_hidden_layers"] = len(layer_ids)
        intermediate = state.get(f"{prefix}.encoder.layer.0.intermediate.dense.weight")
        if intermediate is not None:
            kwargs["intermediate_size"] = int(intermediate.shape[0])
    hidden = int(word_emb.shape[1])
    kwargs["num_attention_heads"] = max(1, hidden // 64)
    return config_cls(**kwargs)


def _build_scanman_wrapper(
    torch_module: Any,
    encoder: Any,
    classifier: Any,
    pooling: str,
    dropout: float,
) -> Any:
    """重建训练侧的 ``VulnClassifier``：``encoder`` + 单层 ``classifier``（CLS pooling）。"""

    class _ScanManClassifier(torch_module.nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.encoder = encoder
            self.classifier = classifier
            self.pooling = pooling or "cls"
            self.dropout = torch_module.nn.Dropout(float(dropout if dropout is not None else 0.1))
            self.config = encoder.config

        def forward(self, input_ids: Any = None, attention_mask: Any = None, **_kwargs: Any) -> Any:
            output = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
            hidden = output.last_hidden_state
            if self.pooling == "mean" and attention_mask is not None:
                mask = attention_mask.unsqueeze(-1).to(hidden.dtype)
                pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-6)
            elif self.pooling == "max" and attention_mask is not None:
                mask = attention_mask.unsqueeze(-1).to(hidden.dtype)
                pooled = (hidden * mask + (1.0 - mask) * -1e4).max(dim=1).values
            else:
                pooled = hidden[:, 0]
            return SimpleNamespace(logits=self.classifier(self.dropout(pooled)))

    return _ScanManClassifier()


def _load_model(
    torch_module: Any,
    transformers: Any,
    weights_dir: Path,
    checkpoint: Path,
    base_model_name: Optional[str],
    pooling: str,
    dropout: float,
    fallback_num_labels: Optional[int],
) -> Tuple[Any, Optional[int], str]:
    """加载模型，返回 ``(model, num_labels, layout 说明)``。

    支持两种 checkpoint 布局，见 :meth:`InferenceEngine._load_task` 的说明。
    """
    # ---- 布局 A：标准 HF 目录（带 config.json） --------------------------- #
    if (weights_dir / "config.json").is_file():
        model = transformers.AutoModelForSequenceClassification.from_pretrained(
            str(weights_dir), local_files_only=True
        )
        return model, _num_labels(model, None), "hf-auto"

    # ---- 布局 B：ScanMan 训练脚本产物（无 config.json） ------------------- #
    state = _load_state_dict(torch_module, weights_dir)
    prefix = _encoder_prefix(state)
    if prefix is None:
        raise ValueError(
            "权重里既没有 config.json，也无法识别 base model 前缀"
            "（期望形如 encoder.embeddings.* / roberta.embeddings.*）"
        )

    num_labels = fallback_num_labels
    head_weight = state.get("classifier.weight")
    if head_weight is not None and len(getattr(head_weight, "shape", ())) == 2:
        num_labels = int(head_weight.shape[0])
    if not num_labels:
        num_labels = 2

    config = _infer_config(transformers, state, prefix, base_model_name, int(num_labels))

    # B1) 自定义包装：encoder.* + classifier.{weight,bias}（单层 Linear）
    if head_weight is not None and prefix == "encoder":
        model_cls = transformers.RobertaModel if _is_roberta_config(config) else transformers.BertModel
        encoder = model_cls(config, add_pooling_layer=True)
        encoder_state = {
            key[len("encoder.") :]: value for key, value in state.items() if key.startswith("encoder.")
        }
        missing, unexpected = encoder.load_state_dict(encoder_state, strict=False)
        if missing or unexpected:
            raise ValueError(
                f"encoder 权重与重建结构不一致（missing={missing[:5]}, unexpected={unexpected[:5]}）"
            )
        head_bias = state.get("classifier.bias")
        if head_bias is None:
            raise ValueError("权重里缺少 classifier.bias，无法重建分类头")
        classifier = torch_module.nn.Linear(int(head_weight.shape[1]), int(head_weight.shape[0]))
        classifier.load_state_dict({"weight": head_weight, "bias": head_bias})
        model = _build_scanman_wrapper(torch_module, encoder, classifier, pooling, dropout)
        return model, int(num_labels), "scanman-wrapper(encoder+Linear, pooling=%s)" % (pooling or "cls")

    # B2) 标准 HF 命名（roberta.* / bert.*），只是缺 config.json
    model_cls = (
        transformers.RobertaForSequenceClassification
        if _is_roberta_config(config)
        else transformers.BertForSequenceClassification
    )
    model = model_cls(config)
    base_attr = getattr(model, "base_model_prefix", prefix)
    remapped = {
        (f"{base_attr}.{key[len(prefix) + 1:]}" if key.startswith(f"{prefix}.") else key): value
        for key, value in state.items()
    }
    missing, unexpected = model.load_state_dict(remapped, strict=False)
    if missing or unexpected:
        raise ValueError(
            f"权重与重建结构不一致（missing={missing[:5]}, unexpected={unexpected[:5]}）"
        )
    return model, int(num_labels), f"hf-config-inferred({base_attr})"


def _is_roberta_config(config: Any) -> bool:
    return "roberta" in str(getattr(config, "model_type", "")).lower()


def _resolve_load_dirs(checkpoint: Path) -> Tuple[Optional[Path], Optional[Path]]:
    """返回 (分词器目录, 权重目录)。

    训练产物有两种摆放方式：
      1. ``best/`` 里同时有 tokenizer 与权重（本项目默认）；
      2. 权重在 ``best/``，tokenizer 在 run 目录或更上层。
    两种都支持；缺哪个就返回 None。
    """
    dirs = [checkpoint]
    for parent in list(checkpoint.parents)[:3]:
        if parent not in dirs:
            dirs.append(parent)

    tokenizer_dir: Optional[Path] = None
    weights_dir: Optional[Path] = None
    for directory in dirs:
        if tokenizer_dir is None and any(
            (directory / name).is_file()
            for name in ("tokenizer.json", "vocab.txt", "vocab.json", "sentencepiece.bpe.model")
        ):
            tokenizer_dir = directory
        if weights_dir is None and any(
            (directory / name).is_file()
            for name in ("pytorch_model.bin", "model.safetensors", "model.bin")
        ):
            weights_dir = directory
        if tokenizer_dir and weights_dir:
            break

    # 分片权重
    if weights_dir is None:
        for directory in dirs:
            try:
                shards = [
                    child
                    for child in directory.iterdir()
                    if child.is_file() and child.suffix in {".bin", ".safetensors"}
                ]
            except OSError:  # pragma: no cover
                shards = []
            if shards:
                weights_dir = directory
                break
    return tokenizer_dir, weights_dir


def _num_labels(model: Any, label_map: Optional[Dict[str, Any]]) -> Optional[int]:
    config = getattr(model, "config", None)
    value = getattr(config, "num_labels", None)
    if isinstance(value, int):
        return value
    if label_map:
        return len(label_map)
    return None


def _index_of_label(label_map: Dict[str, Any], wanted: Sequence[Any], default: int) -> int:
    """在 ``{id: 名称}`` 或 ``{名称: id}`` 两种映射里找到目标标签的下标。"""
    wanted_norm = {str(item).strip().lower() for item in wanted}
    for key, value in label_map.items():
        if str(key).strip().lower() in wanted_norm and str(value).strip().isdigit():
            return int(str(value))
        if str(value).strip().lower() in wanted_norm and str(key).strip().isdigit():
            return int(str(key))
    return default


def _label_name_for_index(label_map: Dict[str, Any], index: int) -> Optional[str]:
    """``{id: 名称}`` 取名称；``{名称: id}`` 反向取名称。"""
    if not label_map:
        return None
    for key, value in label_map.items():
        if str(key).strip() == str(index) and not str(value).strip().isdigit():
            return str(value)
    for key, value in label_map.items():
        if str(value).strip() == str(index):
            return str(key)
    return None


def _prior_top_cwe(scores: Dict[str, float], top_k: int) -> List[Tuple[str, float]]:
    """把 CWE 打分归一化成 Top-K 概率（降级模式用）。"""
    if not scores:
        return []
    ordered = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))[: max(1, top_k)]
    total = sum(value for _cwe, value in ordered)
    if total <= 0:
        return []
    return [(cwe, round(value / total, 6)) for cwe, value in ordered]


# --------------------------------------------------------------------------- #
# 对外结果组装
# --------------------------------------------------------------------------- #
def _empty_cwe_fields() -> Dict[str, Any]:
    return {
        "predictedCwe": None,
        "predictedCweName": None,
        "cweConfidence": None,
        "topCwe": [],
    }


class Predictor:
    """把「引擎状态 + 单次请求参数」组装成契约要求的 JSON。"""

    def __init__(self, engine: InferenceEngine) -> None:
        self.engine = engine

    def predict(
        self,
        code: str,
        mode: str = "auto",
        threshold: Optional[float] = None,
        top_k: Optional[int] = None,
    ) -> Dict[str, Any]:
        started = time.perf_counter()
        self.engine.ensure_loaded()

        mode = (mode or "auto").strip().lower()
        if mode not in {"auto", "detection", "classification"}:
            mode = "auto"
        threshold = float(threshold) if threshold is not None else float(self.engine.settings.detection_threshold)
        threshold = max(0.0, min(1.0, threshold))
        top_k = int(top_k) if top_k is not None else int(self.engine.settings.top_k)
        top_k = max(1, min(50, top_k))

        want_detection = mode in {"auto", "detection"}
        want_classification = mode in {"auto", "classification"}

        result: Dict[str, Any] = {
            "verdict": None,
            "vulnerableProbability": None,
            "safeProbability": None,
            "threshold": threshold,
            "predictedCwe": None,
            "predictedCweName": None,
            "cweConfidence": None,
            "topCwe": [],
        }

        degraded_tasks: List[str] = []

        # ---- 任务 A：检测 ------------------------------------------------ #
        if want_detection:
            if self.engine.detection.available:
                vulnerable, safe = self.engine._run_detection(code)
            else:
                heuristic = heuristic_analyze(code)
                vulnerable, safe = heuristic.vulnerable_probability, heuristic.safe_probability
                degraded_tasks.append("detection")
            result["vulnerableProbability"] = vulnerable
            result["safeProbability"] = safe
            result["verdict"] = "vulnerable" if vulnerable >= threshold else "safe"

        # ---- 任务 B：分类 ------------------------------------------------ #
        if want_classification:
            if self.engine.classification.available:
                ranked = self.engine._run_classification(code, top_k)
            else:
                heuristic = heuristic_analyze(code)
                ranked = _prior_top_cwe(heuristic.cwe_scores, top_k)
                degraded_tasks.append("classification")
            if ranked:
                top_cwe = [
                    {"cwe": cwe, "name": cwe_name(cwe), "probability": probability}
                    for cwe, probability in ranked
                ]
                result["topCwe"] = top_cwe
                best = top_cwe[0]
                result["predictedCwe"] = best["cwe"]
                result["predictedCweName"] = best["name"]
                result["cweConfidence"] = best["probability"]

        elapsed_ms = (time.perf_counter() - started) * 1000.0
        model_served = len(degraded_tasks) == 0
        reason = self._reason_for(degraded_tasks) if degraded_tasks else None

        # 逐任务的来源说明。为什么需要它：
        # mode=auto 时只要有一个任务降级，整体就是 degraded=true、modelName=heuristic-mock，
        # 但实际上另一个任务可能是**真实模型**算出来的（例如本机只有检测权重）。
        # 只看顶层字段会把「真模型判定的漏洞」误当成 mock 结果，所以这里把每个任务
        # 分别标明来源：调用方可以放心地展示 detection 的结论，只对 classification 显示降级提示。
        tasks: Dict[str, Any] = {}
        if want_detection:
            det_ok = self.engine.detection.available
            tasks["detection"] = {
                "modelServed": det_ok,
                "degraded": not det_ok,
                "modelName": self.engine.settings.model_name if det_ok else DEGRADED_ENGINE_TAG,
                "reason": None if det_ok else (self.engine.detection.reason or "不可用"),
            }
        if want_classification:
            cls_ok = self.engine.classification.available
            tasks["classification"] = {
                "modelServed": cls_ok,
                "degraded": not cls_ok,
                "modelName": self.engine.settings.model_name if cls_ok else DEGRADED_ENGINE_TAG,
                "reason": None if cls_ok else (self.engine.classification.reason or "不可用"),
            }

        return {
            "modelServed": model_served,
            "degraded": not model_served,
            "degradedReason": reason,
            "modelName": self.engine.settings.model_name if model_served else DEGRADED_ENGINE_TAG,
            "tasks": tasks,
            "latencyMs": int(round(elapsed_ms)),
            **result,
        }

    def _reason_for(self, degraded_tasks: Sequence[str]) -> str:
        details = []
        for name in degraded_tasks:
            state = self.engine.detection if name == "detection" else self.engine.classification
            details.append(f"[{name}] {state.reason or '不可用'}")
        return (
            f"降级模式：{'；'.join(details)}。"
            f"本次响应中这些任务由内置启发式规则（{DEGRADED_ENGINE_TAG}）模拟，"
            f"**不是** ScanMan 模型输出，仅用于链路联调/演示。"
        )


# --------------------------------------------------------------------------- #
# 进程内单例
# --------------------------------------------------------------------------- #
engine = InferenceEngine(global_settings)
predictor = Predictor(engine)


def get_engine() -> InferenceEngine:
    return engine


def get_predictor() -> Predictor:
    return predictor


__all__ = [
    "DEGRADED_ENGINE_TAG",
    "HeuristicHit",
    "HeuristicVerdict",
    "InferenceEngine",
    "Predictor",
    "TaskState",
    "cwe_name",
    "cwe_name_zh",
    "engine",
    "get_engine",
    "get_predictor",
    "head_tail_truncate",
    "heuristic_analyze",
    "normalize_cwe",
    "predictor",
]
