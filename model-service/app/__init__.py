"""ScanMan 模型推理服务（FastAPI）。

模块划分：
    config.py  环境变量配置 + checkpoint 自动发现
    model.py   推理核心（懒加载 / 头尾截断 / 降级启发式）
    main.py    HTTP 契约
"""

from .config import VERSION

__all__ = ["VERSION"]
__version__ = VERSION
