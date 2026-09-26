"""pytest 全局前置：保证 `python -m pytest tests -q` 在任何机器上结果一致。

两件事：
1. 把 ``model-service/`` 加进 ``sys.path``，这样无论 pytest 的 rootdir 怎么算，
   ``import app.xxx`` 都能成功（不依赖 CWD）。
2. 默认强制 ``ML_FORCE_DEGRADED=1``，让测试结果与「本机有没有 torch / checkpoint」无关。
   想跑真实模型测试时：``ML_TEST_ALLOW_MODEL=1 python -m pytest tests -q``。
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

SERVICE_DIR = Path(__file__).resolve().parents[1]
if str(SERVICE_DIR) not in sys.path:
    sys.path.insert(0, str(SERVICE_DIR))

if os.environ.get("ML_TEST_ALLOW_MODEL") != "1":
    os.environ["ML_FORCE_DEGRADED"] = "1"
