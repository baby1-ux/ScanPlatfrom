"""离线兜底测试运行器（**不是** pytest 的替代品）。

为什么存在
----------
``tests/test_service.py`` 是标准 pytest 测试文件，正常用法是::

    python -m pytest tests -q

但有些交付机器完全离线、装不上 pytest（本机就是这样：PyPI 的 HTTPS 客户端被网络策略
挡住）。为了仍然能真实验证同一套断言，这个脚本用最朴素的反射把 ``test_*`` 函数跑一遍。

它 **只** 运行 ``tests/test_service.py`` 里的普通函数（无 fixture、无参数），
因此测试文件里刻意不使用任何 pytest 专有 API。

用法::

    python tests/run_tests.py
"""

from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
SERVICE_DIR = TESTS_DIR.parent
for path in (str(SERVICE_DIR), str(TESTS_DIR)):
    if path not in sys.path:
        sys.path.insert(0, path)

os.environ.setdefault("ML_FORCE_DEGRADED", "1")


def main() -> int:
    try:
        import test_service  # type: ignore[import-not-found]
    except Exception:
        traceback.print_exc()
        return 2

    names = sorted(name for name in dir(test_service) if name.startswith("test_"))
    passed, failed = 0, []
    for name in names:
        func = getattr(test_service, name)
        if not callable(func):
            continue
        try:
            func()
        except Exception as exc:  # noqa: BLE001
            failed.append((name, exc))
            print(f"FAIL {name}: {type(exc).__name__}: {exc}")
            traceback.print_exc()
        else:
            passed += 1
            print(f"PASS {name}")

    print("-" * 60)
    print(f"offline runner: {passed} passed, {len(failed)} failed, {passed + len(failed)} total")
    if failed:
        print("failed:", ", ".join(name for name, _ in failed))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
