"""FastAPI 入口 —— ScanMan 模型推理服务（漏洞检测 / 漏洞分类）。

对外契约（Node 后端依赖，字段名不可改）：

    GET  /health
    GET  /model/info
    POST /predict
    POST /predict/batch

硬性要求：torch / transformers / checkpoint 任意缺失时服务依然能启动并响应，
此时进入 degraded 降级模式（启发式 mock），并在响应中显式标注。
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, List, Literal, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from .config import settings
from .model import get_engine, get_predictor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
logger = logging.getLogger("model_service.main")

MAX_BATCH_ITEMS = 100

Mode = Literal["auto", "detection", "classification"]
_VALID_MODES = {"auto", "detection", "classification"}


def _startup() -> None:
    """启动时做一次探测/加载；**绝不**因模型缺失而失败。"""
    engine = get_engine()
    try:
        engine.ensure_loaded()
    except Exception as exc:  # pragma: no cover - 双保险，任何异常都不该让服务起不来
        logger.warning("启动期模型加载出现异常（已忽略，保持降级）：%s", exc, exc_info=True)
    try:
        health = engine.health()
    except Exception as exc:  # pragma: no cover
        logger.warning("启动期健康检查异常：%s", exc)
        return
    if health["degraded"]:
        logger.warning("服务已启动，但处于【降级模式】。原因：%s", health["degradedReason"])
    else:
        logger.info(
            "服务已启动，模型就绪。device=%s detection=%s classification=%s",
            health["device"],
            health["detectionCheckpoint"],
            health["classificationCheckpoint"],
        )


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    _startup()
    yield


app = FastAPI(
    title="ScanMan Model Service",
    description=(
        "代码漏洞检测（safe/vulnerable）+ 漏洞分类（CWE Top-K）推理服务。"
        "模型不可用时自动降级为启发式 mock，并在响应中标注 degraded。"
    ),
    version=settings.version,
    lifespan=lifespan,
)

# 仅服务端到服务端 / 本地前端调用，放开全部来源
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class PredictRequest(BaseModel):
    """``POST /predict`` 的请求体。"""

    code: str = Field(default="", description="待检测源码")
    mode: Mode = Field(default="auto", description="auto | detection | classification")
    threshold: Optional[float] = Field(default=None, description="漏洞判定阈值，默认取服务配置")
    topK: Optional[int] = Field(default=None, description="Top-K CWE，默认取服务配置")
    filePath: Optional[str] = Field(default=None, description="源码文件路径（仅回显/日志用）")
    language: Optional[str] = Field(default=None, description="源码语言（仅回显/日志用）")

    @field_validator("mode", mode="before")
    @classmethod
    def _normalize_mode(cls, value: Any) -> Any:
        """容错：``null`` 或无法识别的 mode 一律回落 ``auto``，绝不因此报 422。"""
        if value is None:
            return "auto"
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in _VALID_MODES:
                return lowered
        return "auto"


class BatchItem(BaseModel):
    """``POST /predict/batch`` 里的单条。"""

    code: str = Field(default="", description="待检测源码")
    mode: Optional[Mode] = Field(default=None, description="缺省视为 auto")
    filePath: Optional[str] = None
    language: Optional[str] = None

    @field_validator("mode", mode="before")
    @classmethod
    def _normalize_mode(cls, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in _VALID_MODES:
                return lowered
        return None


class BatchRequest(BaseModel):
    """``POST /predict/batch`` 的请求体。"""

    items: List[BatchItem] = Field(default_factory=list)
    threshold: Optional[float] = None


# --------------------------------------------------------------------------- #
# 接口
# --------------------------------------------------------------------------- #
@app.get("/health")
def health() -> Dict[str, Any]:
    engine = get_engine()
    engine.ensure_loaded()
    return engine.health()


@app.get("/model/info")
def model_info() -> Dict[str, Any]:
    engine = get_engine()
    engine.ensure_loaded()
    return engine.model_info()


@app.post("/predict")
def predict(payload: PredictRequest) -> Dict[str, Any]:
    code = payload.code or ""
    if not code.strip():
        raise HTTPException(status_code=422, detail="code 不能为空")
    return get_predictor().predict(
        code=code,
        mode=payload.mode or "auto",
        threshold=payload.threshold,
        top_k=payload.topK,
    )


@app.post("/predict/batch")
def predict_batch(payload: BatchRequest) -> Dict[str, Any]:
    items = payload.items or []
    if len(items) > MAX_BATCH_ITEMS:
        raise HTTPException(
            status_code=422,
            detail=f"items 数量不能超过 {MAX_BATCH_ITEMS}（当前 {len(items)}）",
        )
    predictor = get_predictor()
    results: List[Dict[str, Any]] = []
    for index, item in enumerate(items):
        code = item.code or ""
        if not code.strip():
            raise HTTPException(status_code=422, detail=f"items[{index}].code 不能为空")
        results.append(
            predictor.predict(
                code=code,
                mode=item.mode or "auto",
                threshold=payload.threshold,
                top_k=None,
            )
        )
    return {"results": results}


__all__ = ["app", "MAX_BATCH_ITEMS"]
