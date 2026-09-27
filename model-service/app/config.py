"""配置模块 —— 全部通过环境变量覆盖，带合理默认值。

设计原则（硬性要求）：
    服务在 **torch / transformers / checkpoint 全部缺失** 的情况下也必须能启动、
    能对外提供 HTTP 服务，此时自动进入 degraded（降级）模式，并在每个响应里
    明确标注。因此本模块 **只做路径探测**，绝不 import torch / transformers，
    也绝不在 import 期加载任何权重。
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("model_service.config")

VERSION = "1.0.0"

# --------------------------------------------------------------------------- #
# 目录锚点
# --------------------------------------------------------------------------- #
# config.py 位于 <model-service>/app/config.py
APP_DIR = Path(__file__).resolve().parent
SERVICE_DIR = APP_DIR.parent          # <model-service>
# 仓库根目录（model-service 的上一级）。允许用 REPO_ROOT 覆盖。
_DEFAULT_REPO_ROOT = SERVICE_DIR.parent


def _env_str(name: str, default: Optional[str] = None) -> Optional[str]:
    raw = os.environ.get(name)
    if raw is None:
        return default
    raw = raw.strip()
    return raw if raw else default


def _env_int(name: str, default: int) -> int:
    raw = _env_str(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning("环境变量 %s=%r 不是整数，使用默认值 %s", name, raw, default)
        return default


def _env_float(name: str, default: float) -> float:
    raw = _env_str(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        logger.warning("环境变量 %s=%r 不是浮点数，使用默认值 %s", name, raw, default)
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env_str(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on", "是"}


# --------------------------------------------------------------------------- #
# label_map.json 解析 & 任务判定
# --------------------------------------------------------------------------- #
def load_label_map(best_dir: Path) -> Optional[Dict[str, Any]]:
    """读取 best/label_map.json，失败返回 None（不抛异常）。"""
    path = best_dir / "label_map.json"
    if not path.is_file():
        return None
    for encoding in ("utf-8", "utf-8-sig", "gbk"):
        try:
            with path.open("r", encoding=encoding) as fp:
                data = json.load(fp)
            if isinstance(data, dict):
                return data
            return None
        except UnicodeDecodeError:
            continue
        except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - 损坏文件
            logger.warning("读取 %s 失败：%s", path, exc)
            return None
    return None


def unwrap_label_map(label_map: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """把训练产物的 label_map 拍平成 ``{id: 名称}`` / ``{名称: id}``。

    训练脚本写出的 label_map.json 有两种结构::

        {"safe": 0, "vulnerable": 1}                     # 扁平（较早版本）
        {"task": "detection", "num_labels": 2,
         "id2name": {"0": "safe", "1": "vulnerable"}}    # 嵌套（当前版本）

    本函数统一取出内层的 ``id2name``，让上层代码只面对一种结构。
    """
    if not isinstance(label_map, dict):
        return label_map
    for key in ("id2name", "id_to_name", "id2label", "labels", "cwe_map"):
        inner = label_map.get(key)
        if isinstance(inner, dict) and inner:
            return inner
    return label_map


def _label_task_hint(label_map: Optional[Dict[str, Any]]) -> Optional[str]:
    """从 label_map 里显式的 ``task`` 字段读任务类型（训练产物会写）。"""
    if not isinstance(label_map, dict):
        return None
    task = label_map.get("task")
    if isinstance(task, str):
        lowered = task.strip().lower()
        if lowered in {"detection", "classification"}:
            return lowered
    return None


def _label_map_is_binary_detection(label_map: Optional[Dict[str, Any]]) -> bool:
    """整数标签的二分类映射（{safe:0, vulnerable:1} 或 {0:'safe',1:'vulnerable'}）→ 检测任务。

    注意：训练产物里 label_map 有 ``{id: 名称}`` 与 ``{名称: id}`` 两种写法，还可能被
    ``id2name`` 包一层（见 :func:`unwrap_label_map`）。分类任务的映射值是 ``CWE-xxx``
    字符串，检测任务的值只有 safe/vulnerable 两种字面量。
    """
    label_map = unwrap_label_map(label_map)
    if not label_map:
        return False
    keys = [str(k) for k in label_map.keys()]
    values = [str(v) for v in label_map.values()]
    token_set = {t.strip().lower() for t in keys + values}
    if not token_set:
        return False
    if token_set.issubset({"safe", "vulnerable", "0", "1", "non-vulnerable", "nonvulnerable"}):
        return True
    # 出现 CWE- 则是分类
    if any(t.startswith("cwe-") for t in token_set):
        return False
    return False


def _label_map_cwe_count(label_map: Optional[Dict[str, Any]]) -> int:
    label_map = unwrap_label_map(label_map)
    if not label_map:
        return 0
    names = set()
    for key, value in label_map.items():
        for token in (str(key).strip(), str(value).strip()):
            if token.upper().startswith("CWE-"):
                names.add(token.upper())
    return len(names)


def _has_weights(best_dir: Path) -> bool:
    """best/ 下是否存在可加载的权重文件。"""
    for name in (
        "model.safetensors",
        "pytorch_model.bin",
        "model.bin",
        "tf_model.h5",
    ):
        if (best_dir / name).is_file():
            return True
    # 分片权重：pytorch_model-00001-of-00002.bin / model-00001-of-00002.safetensors
    try:
        for child in best_dir.iterdir():
            if child.is_file() and child.suffix in {".bin", ".safetensors"}:
                return True
    except OSError:  # pragma: no cover
        return False
    return False


# --------------------------------------------------------------------------- #
# 自动发现
# --------------------------------------------------------------------------- #
@dataclass
class CheckpointCandidate:
    """一个候选 checkpoint（best/ 目录）。"""

    path: Path
    task: Optional[str]          # "detection" | "classification" | None(未知)
    label_map: Optional[Dict[str, Any]]
    has_weights: bool

    @property
    def run_name(self) -> str:
        # <run>/best -> <run>
        return self.path.parent.name

    def __str__(self) -> str:  # pragma: no cover - 仅调试用
        return f"{self.path} (task={self.task}, weights={self.has_weights})"


def _classify_candidate(best_dir: Path) -> CheckpointCandidate:
    """看 label_map.json + 运行目录名来判定这是检测还是分类 checkpoint。"""
    label_map = load_label_map(best_dir)
    run_name = best_dir.parent.name.lower()
    name_hint: Optional[str] = None
    if "detection" in run_name or "detect" in run_name or "vuln_detect" in run_name:
        name_hint = "detection"
    elif "classification" in run_name or "classify" in run_name or "cls" in run_name:
        name_hint = "classification"

    task: Optional[str]
    explicit = _label_task_hint(label_map)
    if explicit:
        task = explicit
    elif _label_map_is_binary_detection(label_map):
        task = "detection"
    elif _label_map_cwe_count(label_map) > 0:
        task = "classification"
    else:
        task = name_hint
    return CheckpointCandidate(
        path=best_dir,
        task=task,
        label_map=label_map,
        has_weights=_has_weights(best_dir),
    )


def _iter_auto_search_best_dirs() -> List[Path]:
    """按 spec 规定的顺序列出候选 best/ 目录（去重、稳定顺序）。

    顺序：
        (a0) 环境变量 SCANMAN_ROOT 指向的 ScanMan 训练工程根目录
             （真实训练产物往往在另一个目录，如 D:\\workbuddy_workspace\\vuln_bert，
              此时用 SCANMAN_ROOT 指过去即可，无需拷贝权重）
        (b) 相对 model-service 的固定相对路径
            ../ScanMan/outputs/*/best, ../../outputs/*/best,
            ./outputs/*/best,          ../outputs/*/best
        (c) 从仓库根 glob： **/outputs/*_detection_*/best
                           **/outputs/*_classification_*/best
    """
    seen: List[Path] = []

    def _add(path: Path) -> None:
        try:
            resolved = path.resolve()
        except OSError:  # pragma: no cover
            return
        if resolved in seen:
            return
        seen.append(resolved)

    # (a0) 显式指定 ScanMan 训练工程根目录（可多个，用 os.pathsep 分隔）
    scanman_root = _env_str("SCANMAN_ROOT")
    if scanman_root:
        for raw in scanman_root.split(os.pathsep):
            raw = raw.strip()
            if not raw:
                continue
            root = Path(raw).expanduser()
            if not root.is_absolute():
                root = (SERVICE_DIR / root).resolve()
            if not root.is_dir():
                logger.warning("SCANMAN_ROOT 指向的目录不存在：%s", root)
                continue
            logger.info("SCANMAN_ROOT=%s，在其中搜索 outputs/*/best", root)
            for hit in _safe_glob(root / "outputs/*/best"):
                _add(hit)
            for hit in _safe_glob(root / "**/best"):
                _add(hit)

    # (b) 固定相对路径
    for rel in (
        "../ScanMan/outputs/*/best",
        "../../outputs/*/best",
        "./outputs/*/best",
        "../outputs/*/best",
    ):
        for hit in _safe_glob(SERVICE_DIR / rel):
            _add(hit)

    # (c) 从仓库根 glob 两类 run 目录
    repo_roots = [SERVICE_DIR, _DEFAULT_REPO_ROOT]
    for root in repo_roots:
        for pattern in ("**/outputs/*_detection_*/best", "**/outputs/*_classification_*/best"):
            for hit in _safe_glob(root / pattern):
                _add(hit)
    return seen


def _safe_glob(pattern: Path) -> List[Path]:
    """glob 但吞掉权限/路径异常，且只返回目录。"""
    base = pattern
    parts = []
    while True:
        if any(ch in base.name for ch in "*?["):
            parts.insert(0, base.name)
            base = base.parent
            continue
        break
    try:
        results = [p for p in base.glob("/".join(parts)) if p.is_dir()]
    except (OSError, ValueError) as exc:  # pragma: no cover
        logger.debug("glob %s 失败：%s", pattern, exc)
        return []
    return sorted(results)


def auto_discover_checkpoint(task: str, explicit: Optional[str] = None) -> Optional[Path]:
    """按 (a) 环境变量 → (b) 固定相对路径 → (c) 仓库根 glob 的顺序找 checkpoint。

    参数
    ----
    task:       "detection" 或 "classification"
    explicit:  环境变量的值（可为文件或目录）

    返回：指向 ``best/`` 目录的 Path，或 None。
    """
    # (a) 环境变量显式指定
    if explicit:
        candidate = Path(explicit).expanduser()
        if not candidate.is_absolute():
            candidate = (SERVICE_DIR / candidate).resolve()
        if candidate.is_file():
            # 允许直接指向 best/pytorch_model.bin 或 config.yaml
            if candidate.parent.name == "best":
                candidate = candidate.parent
            elif candidate.name in {"pytorch_model.bin", "model.safetensors"}:
                candidate = candidate.parent
            else:
                candidate = candidate.parent
        if candidate.is_dir():
            logger.info("使用环境变量指定的 %s checkpoint：%s", task, candidate)
            return candidate
        logger.warning("环境变量指定的 %s checkpoint 不存在：%s", task, explicit)

    found = _iter_auto_search_best_dirs()
    # 第一轮：任务判定匹配 且 有权重
    for best_dir in found:
        cand = _classify_candidate(best_dir)
        if cand.task == task and cand.has_weights:
            logger.info("自动发现 %s checkpoint（有权重）：%s", task, best_dir)
            return cand.path
    # 第二轮：任务判定匹配但缺权重（仍返回，让 model.py 给出更精确的降级原因）
    for best_dir in found:
        cand = _classify_candidate(best_dir)
        if cand.task == task:
            logger.warning("发现 %s checkpoint 但缺少权重文件：%s", task, best_dir)
            return cand.path
    logger.warning("未发现 %s checkpoint，将进入降级模式", task)
    return None


# --------------------------------------------------------------------------- #
# 设置
# --------------------------------------------------------------------------- #
@dataclass
class Settings:
    """服务全部设置。所有字段都可由环境变量覆盖。"""

    host: str = "127.0.0.1"
    port: int = 8000

    detection_checkpoint: Optional[Path] = None
    classification_checkpoint: Optional[Path] = None

    model_device: str = "auto"            # auto | cpu | cuda | cuda:0 ...
    max_length: int = 512
    detection_threshold: float = 0.5
    top_k: int = 5
    head_ratio: float = 0.6               # 头 60% / 尾 40%
    tail_ratio: float = 0.4

    model_name: str = "codebert-base"
    version: str = VERSION

    # ML_FORCE_DEGRADED=1 时强制跳过一切权重加载，只用启发式 mock。
    # 用途：CI / 单元测试 / 演示机器上没有真实 checkpoint 时保证行为确定。
    force_degraded: bool = False

    # 运行期由 model.py 填充的运行时状态（不属于环境变量）
    extra: Dict[str, Any] = field(default_factory=dict)

    # -- 便捷属性 ---------------------------------------------------------- #
    @property
    def boundaries(self) -> Dict[str, Optional[str]]:
        return {
            "detection": str(self.detection_checkpoint) if self.detection_checkpoint else None,
            "classification": str(self.classification_checkpoint)
            if self.classification_checkpoint
            else None,
        }


def _derive_model_name(det: Optional[Path], cls: Optional[Path], fallback: str) -> str:
    """从 run 目录名推断模型名（如 cvefixes_detection_codebert-base → codebert-base）。"""
    for path in (det, cls):
        if not path:
            continue
        run = path.parent.name.lower()
        if "codebert" in run:
            return "codebert-base"
        if "graphcodebert" in run:
            return "graphcodebert-base"
        if "unixcoder" in run:
            return "unixcoder-base"
    return fallback


def load_settings() -> Settings:
    """从环境变量构造 Settings（每次调用都重新读环境变量，便于测试）。"""
    det_env = _env_str("DETECTION_CHECKPOINT")
    cls_env = _env_str("CLASSIFICATION_CHECKPOINT")

    detection = auto_discover_checkpoint("detection", det_env)
    classification = auto_discover_checkpoint("classification", cls_env)

    settings = Settings(
        host=_env_str("ML_HOST", "127.0.0.1") or "127.0.0.1",
        port=_env_int("ML_PORT", 8000),
        detection_checkpoint=detection,
        classification_checkpoint=classification,
        model_device=_env_str("MODEL_DEVICE", "auto") or "auto",
        max_length=_env_int("MAX_LENGTH", 512),
        detection_threshold=_env_float("DETECTION_THRESHOLD", 0.5),
        top_k=_env_int("TOP_K", 5),
        head_ratio=0.6,
        tail_ratio=0.4,
        model_name=_derive_model_name(detection, classification, "codebert-base"),
        version=VERSION,
        force_degraded=_env_bool("ML_FORCE_DEGRADED", False),
    )
    if settings.max_length < 8:
        logger.warning("MAX_LENGTH=%s 过小，已提升到 8", settings.max_length)
        settings.max_length = 8
    if settings.top_k < 1:
        settings.top_k = 1
    return settings


# 模块级单例：main.py / model.py 直接 import 使用。
settings = load_settings()


__all__ = [
    "VERSION",
    "Settings",
    "CheckpointCandidate",
    "SERVICE_DIR",
    "APP_DIR",
    "settings",
    "load_settings",
    "load_label_map",
    "unwrap_label_map",
    "auto_discover_checkpoint",
]
