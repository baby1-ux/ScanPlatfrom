"""ScanMan 模型服务接口测试。

设计约束
--------
* **不依赖 torch / transformers**，也 **不需要任何 checkpoint**：全部在 degraded 降级模式下断言。
  （``tests/conftest.py`` 默认设置 ``ML_FORCE_DEGRADED=1``。）
* 只用普通 ``assert``，不用 pytest 专有 API —— 这样即使机器上装不了 pytest
  （离线环境），也能用 ``python tests/run_tests.py`` 跑同一套断言。
* 运行方式：``python -m pytest tests -q``
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient

SERVICE_DIR = Path(__file__).resolve().parents[1]
if str(SERVICE_DIR) not in sys.path:  # 直接 `python tests/test_service.py` 时也能跑
    sys.path.insert(0, str(SERVICE_DIR))

os.environ.setdefault("ML_FORCE_DEGRADED", "1")

from app.config import settings  # noqa: E402
from app.main import MAX_BATCH_ITEMS, app  # noqa: E402
from app.model import cwe_name, head_tail_truncate, heuristic_analyze, normalize_cwe  # noqa: E402

client = TestClient(app)

# 契约要求的字段顺序（Node 后端按 key 取值，这里顺带锁死顺序，防止重构打乱）
HEALTH_KEYS = [
    "status",
    "modelServed",
    "degraded",
    "degradedReason",
    "modelName",
    "detectionCheckpoint",
    "classificationCheckpoint",
    "device",
    "torchAvailable",
    "transformersAvailable",
    "version",
]
MODEL_INFO_KEYS = [
    "tasks",
    "device",
    "maxLength",
    "detectionThreshold",
    "degraded",
    "degradedReason",
]
TASK_KEYS = ["available", "checkpoint", "numLabels", "labelMap"]
PREDICT_KEYS = [
    "modelServed",
    "degraded",
    "degradedReason",
    "modelName",
    # 逐任务来源说明（新增字段，只增不改；用于区分「真模型的任务」与「降级 mock 的任务」）
    "tasks",
    "latencyMs",
    "verdict",
    "vulnerableProbability",
    "safeProbability",
    "threshold",
    "predictedCwe",
    "predictedCweName",
    "cweConfidence",
    "topCwe",
]
TOP_CWE_KEYS = ["cwe", "name", "probability"]
# 逐任务来源块的结构
TASK_PROVENANCE_KEYS = ["modelServed", "degraded", "modelName", "reason"]

VULN_SAMPLE = 'void f(char *s){ char buf[10]; strcpy(buf, s); }'
SAFE_SAMPLE = "int add(int a, int b) { return a + b; }"


# --------------------------------------------------------------------------- #
# /health
# --------------------------------------------------------------------------- #
def test_health_shape_and_types():
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert list(body.keys()) == HEALTH_KEYS
    assert body["status"] == "ok"
    assert isinstance(body["modelServed"], bool)
    assert isinstance(body["degraded"], bool)
    assert isinstance(body["torchAvailable"], bool)
    assert isinstance(body["transformersAvailable"], bool)
    assert body["version"] == "1.0.0"
    # degradedReason 在降级时必须是可读字符串，不能是空串
    if body["degraded"]:
        assert isinstance(body["degradedReason"], str) and body["degradedReason"].strip()
    else:
        assert body["degradedReason"] is None


def test_health_is_degraded_without_checkpoints():
    """没有 checkpoint / 没有 torch 时，服务必须照常响应并且明确说自己是降级的。"""
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["degraded"] is True
    assert body["modelServed"] is False
    assert "降级" in body["degradedReason"]


# --------------------------------------------------------------------------- #
# /model/info
# --------------------------------------------------------------------------- #
def test_model_info_shape():
    resp = client.get("/model/info")
    assert resp.status_code == 200
    body = resp.json()
    assert list(body.keys()) == MODEL_INFO_KEYS
    assert set(body["tasks"].keys()) == {"detection", "classification"}
    for task in ("detection", "classification"):
        info = body["tasks"][task]
        expected = TASK_KEYS + (["cweCount"] if task == "classification" else [])
        assert list(info.keys()) == expected
        assert isinstance(info["available"], bool)
    assert isinstance(body["maxLength"], int) and body["maxLength"] > 0
    assert isinstance(body["detectionThreshold"], float)
    assert isinstance(body["degraded"], bool)


# --------------------------------------------------------------------------- #
# /predict
# --------------------------------------------------------------------------- #
def test_predict_degraded_returns_exact_contract():
    resp = client.post("/predict", json={"code": VULN_SAMPLE, "mode": "auto"})
    assert resp.status_code == 200
    body = resp.json()
    assert list(body.keys()) == PREDICT_KEYS

    assert body["modelServed"] is False
    assert body["degraded"] is True
    assert isinstance(body["degradedReason"], str) and body["degradedReason"]
    # 降级时顶层 modelName 是启发式 mock 标签
    assert body["modelName"].lower().startswith("heuristic-mock")
    # 逐任务来源：auto 模式下两个任务都降级
    assert set(body["tasks"].keys()) == {"detection", "classification"}
    for task_name, info in body["tasks"].items():
        assert list(info.keys()) == TASK_PROVENANCE_KEYS, task_name
        assert info["modelServed"] is False
        assert info["degraded"] is True
        assert info["reason"], f"{task_name} 降级时必须给出原因"
    assert isinstance(body["latencyMs"], int) and body["latencyMs"] >= 0
    assert body["verdict"] in ("vulnerable", "safe")
    assert isinstance(body["vulnerableProbability"], float)
    assert isinstance(body["safeProbability"], float)
    assert 0.0 <= body["vulnerableProbability"] <= 1.0
    assert 0.0 <= body["safeProbability"] <= 1.0
    assert abs(body["vulnerableProbability"] + body["safeProbability"] - 1.0) < 1e-6
    assert body["threshold"] == settings.detection_threshold
    assert isinstance(body["predictedCwe"], str)
    assert body["predictedCwe"].startswith("CWE-")
    for entry in body["topCwe"]:
        assert list(entry.keys()) == TOP_CWE_KEYS
        assert 0.0 <= entry["probability"] <= 1.0


def test_predict_detection_only_nulls_cwe_fields():
    resp = client.post("/predict", json={"code": VULN_SAMPLE, "mode": "detection"})
    assert resp.status_code == 200
    body = resp.json()
    assert list(body.keys()) == PREDICT_KEYS
    assert body["verdict"] in ("vulnerable", "safe")
    assert body["predictedCwe"] is None
    assert body["predictedCweName"] is None
    assert body["cweConfidence"] is None
    assert body["topCwe"] == []


def test_predict_classification_only_nulls_verdict_fields():
    resp = client.post("/predict", json={"code": VULN_SAMPLE, "mode": "classification"})
    assert resp.status_code == 200
    body = resp.json()
    assert list(body.keys()) == PREDICT_KEYS
    assert body["verdict"] is None
    assert body["vulnerableProbability"] is None
    assert body["safeProbability"] is None
    # classification 模式必须给出 CWE
    assert isinstance(body["predictedCwe"], str)
    assert body["predictedCweName"] is not None
    assert len(body["topCwe"]) >= 1


def test_predict_threshold_override_changes_verdict():
    low = client.post("/predict", json={"code": VULN_SAMPLE, "threshold": 0.01}).json()
    high = client.post("/predict", json={"code": VULN_SAMPLE, "threshold": 0.9999}).json()
    assert low["threshold"] == 0.01
    assert high["threshold"] == 0.9999
    assert low["verdict"] == "vulnerable"      # 阈值极低 → 判漏洞
    assert high["verdict"] == "safe"           # 阈值极高 → 判安全


def test_predict_top_k_limits_result_size():
    body = client.post("/predict", json={"code": VULN_SAMPLE, "mode": "classification", "topK": 3}).json()
    assert len(body["topCwe"]) <= 3
    assert len(body["topCwe"]) >= 1


def test_predict_empty_code_returns_422_chinese_detail():
    for payload in ({"code": ""}, {"code": "   \n\t "}, {}):
        resp = client.post("/predict", json=payload)
        assert resp.status_code == 422, payload
        assert resp.json() == {"detail": "code 不能为空"}


def test_predict_ignores_unknown_mode_by_falling_back_to_auto():
    resp = client.post("/predict", json={"code": VULN_SAMPLE, "mode": "nonsense"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] is not None
    assert body["predictedCwe"] is not None


def test_predict_accepts_file_path_and_language():
    resp = client.post(
        "/predict",
        json={"code": VULN_SAMPLE, "filePath": "src/a.c", "language": "C"},
    )
    assert resp.status_code == 200
    assert list(resp.json().keys()) == PREDICT_KEYS


# --------------------------------------------------------------------------- #
# /predict/batch
# --------------------------------------------------------------------------- #
def test_batch_cap_returns_422():
    too_many = [{"code": SAFE_SAMPLE} for _ in range(MAX_BATCH_ITEMS + 1)]
    resp = client.post("/predict/batch", json={"items": too_many})
    assert resp.status_code == 422
    assert "items" in resp.json()["detail"]


def test_batch_at_cap_is_allowed():
    items = [{"code": SAFE_SAMPLE} for _ in range(MAX_BATCH_ITEMS)]
    resp = client.post("/predict/batch", json={"items": items})
    assert resp.status_code == 200
    assert len(resp.json()["results"]) == MAX_BATCH_ITEMS


def test_batch_results_match_single_predict_shape():
    resp = client.post(
        "/predict/batch",
        json={
            "items": [
                {"code": VULN_SAMPLE},
                {"code": SAFE_SAMPLE, "mode": "classification"},
            ],
            "threshold": 0.5,
        },
    )
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert len(results) == 2
    for item in results:
        assert list(item.keys()) == PREDICT_KEYS
    assert results[1]["verdict"] is None  # classification 模式


def test_batch_empty_item_code_returns_422():
    resp = client.post("/predict/batch", json={"items": [{"code": ""}]})
    assert resp.status_code == 422
    assert "code" in resp.json()["detail"]


def test_batch_empty_list_returns_empty_results():
    resp = client.post("/predict/batch", json={"items": []})
    assert resp.status_code == 200
    assert resp.json() == {"results": []}


# --------------------------------------------------------------------------- #
# 头尾截断（head+tail 6:4）
# --------------------------------------------------------------------------- #
def test_head_tail_short_input_unchanged():
    ids = list(range(10))
    assert head_tail_truncate(ids, 512) == ids
    assert head_tail_truncate(ids, 10) == ids


def _is_subsequence(part, whole) -> bool:
    """part 是否为 whole 的子序列（保持相对顺序）——用来验证截断没有打乱/篡改 token。"""
    it = iter(whole)
    return all(any(candidate == item for candidate in it) for item in part)


def test_head_tail_never_exceeds_max_length():
    for max_length in (1, 2, 3, 8, 64, 512):
        for size in (0, 1, 7, 100, 1000):
            ids = list(range(size))
            out = head_tail_truncate(ids, max_length)
            assert len(out) <= max_length, (max_length, size)
            assert all(isinstance(i, int) for i in out)
            # 结果必须是原序列的有序子序列（没有切断/改值）
            assert _is_subsequence(out, ids), (max_length, size)
            if size > max_length:
                assert len(out) == max_length
                head_len = int(max_length * 0.6)
                if head_len > 0:
                    assert out[0] == ids[0]        # 头部保留
                if head_len < max_length:
                    assert out[-1] == ids[-1]      # 尾部保留


def test_head_tail_is_exactly_60_40():
    ids = list(range(1000))
    out = head_tail_truncate(ids, 100, 0.6)
    assert len(out) == 100
    assert out[:60] == list(range(60))          # 头部 60%
    assert out[60:] == list(range(960, 1000))   # 尾部 40%


def test_head_tail_keeps_head_and_tail_of_512_budget():
    ids = list(range(2000))
    out = head_tail_truncate(ids, 512, 0.6)
    assert len(out) == 512
    assert out[0] == 0 and out[-1] == 1999      # 首尾都在
    assert out[306] == 306 and out[307] == 2000 - 512 + 307


def test_head_tail_does_not_mutate_input():
    ids = list(range(100))
    snapshot = list(ids)
    head_tail_truncate(ids, 10)
    assert ids == snapshot


def test_head_tail_handles_degenerate_ratio():
    ids = list(range(100))
    assert head_tail_truncate(ids, 10, 0.0) == list(range(90, 100))
    assert head_tail_truncate(ids, 10, 1.0) == list(range(10))


# --------------------------------------------------------------------------- #
# 降级启发式（确定性）
# --------------------------------------------------------------------------- #
def test_heuristic_flags_strcpy_into_small_buffer():
    verdict = heuristic_analyze(VULN_SAMPLE)
    assert verdict.vulnerable_probability >= 0.5
    assert verdict.top_cwe in {"CWE-787", "CWE-119"}
    assert any("strcpy" in hit.evidence for hit in verdict.hits)


def test_heuristic_flags_sql_injection():
    code = 'query = "SELECT * FROM users WHERE name = \'" + name + "\'";'
    verdict = heuristic_analyze(code)
    assert verdict.vulnerable_probability >= 0.5
    assert verdict.cwe_scores.get("CWE-89", 0.0) > 0.5


def test_heuristic_flags_os_command_injection():
    verdict = heuristic_analyze('os.system("ping " + host)')
    assert verdict.vulnerable_probability >= 0.5
    assert verdict.cwe_scores.get("CWE-78", 0.0) > 0.5


def test_heuristic_flags_hardcoded_password():
    verdict = heuristic_analyze('password = "SuperSecret123"')
    assert verdict.vulnerable_probability >= 0.5
    assert verdict.cwe_scores.get("CWE-798", 0.0) > 0.5


def test_heuristic_does_not_flag_trivial_safe_function():
    verdict = heuristic_analyze(SAFE_SAMPLE)
    assert verdict.vulnerable_probability < 0.5
    assert verdict.hits == []


def test_heuristic_is_deterministic():
    first = heuristic_analyze(VULN_SAMPLE)
    second = heuristic_analyze(VULN_SAMPLE)
    assert first.vulnerable_probability == second.vulnerable_probability
    assert first.top_cwe == second.top_cwe
    assert [(h.rule_id, h.cwe) for h in first.hits] == [(h.rule_id, h.cwe) for h in second.hits]


def test_predict_verdict_matches_heuristic_on_safe_sample():
    body = client.post("/predict", json={"code": SAFE_SAMPLE, "mode": "detection"}).json()
    assert body["verdict"] == "safe"
    assert body["vulnerableProbability"] < 0.5


# --------------------------------------------------------------------------- #
# CWE 名称表 / label_map 归一化
# --------------------------------------------------------------------------- #
def test_cwe_name_table_common_entries():
    assert cwe_name("CWE-79") is not None
    assert cwe_name("CWE-89") == "SQL Injection"
    assert cwe_name("CWE-125") == "Out-of-bounds Read"
    assert cwe_name("CWE-787") == "Out-of-bounds Write"
    assert cwe_name("cwe-89") == "SQL Injection"      # 大小写不敏感
    assert cwe_name("CWE-9999") is None               # 未知 id → None


def test_normalize_cwe_variants():
    assert normalize_cwe("CWE-787") == "CWE-787"
    assert normalize_cwe("cwe787") == "CWE-787"
    assert normalize_cwe("79") == "CWE-79"
    assert normalize_cwe(787) == "CWE-787"
    assert normalize_cwe("OTHER") is None
    assert normalize_cwe(None) is None


# --------------------------------------------------------------------------- #
# 配置
# --------------------------------------------------------------------------- #
def test_settings_have_sane_defaults():
    assert 0.0 <= settings.detection_threshold <= 1.0
    assert settings.max_length > 0
    assert settings.top_k >= 1
    assert settings.head_ratio == 0.6
