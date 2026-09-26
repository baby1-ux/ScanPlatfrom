#!/usr/bin/env bash
# =============================================================================
# ScanMan 模型服务启动脚本（Linux / macOS / Git Bash）
#
#   ./run.sh                  # 用默认配置启动
#   ./run.sh --reload         # 开发模式（代码热重载）
#   SKIP_INSTALL=1 ./run.sh   # 跳过 pip install
#
# 行为：
#   1. 选一个可用的 Python 3.9~3.12
#   2. 没有 .venv 就创建，并安装 requirements.txt
#      —— requirements.txt 里的 [ml] 块（torch/transformers）是**可选**的，
#         装不上或没装都不影响服务启动，服务会自动进入 degraded 降级模式。
#   3. uvicorn app.main:app --host $ML_HOST --port $ML_PORT
# =============================================================================
set -u

SERVICE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SERVICE_DIR" || exit 1

step()  { printf '\033[36m==> %s\033[0m\n' "$1"; }
warn()  { printf '\033[33m[!] %s\033[0m\n' "$1"; }

# ---- 1. 读取 .env ----------------------------------------------------------
if [ -f "$SERVICE_DIR/.env" ]; then
  step "读取 $SERVICE_DIR/.env"
  while IFS= read -r line; do
    line="${line%%$'\r'}"
    case "$line" in ''|'#'*) continue ;; esac
    key="${line%%=*}"
    value="${line#*=}"
    value="${value%\"}"; value="${value#\"}"
    value="${value%\'}"; value="${value#\'}"
    if [ -n "$key" ] && [ -n "$value" ]; then
      export "$key=$value"
    fi
  done < "$SERVICE_DIR/.env"
fi

# ---- 2. 找 Python ----------------------------------------------------------
PYTHON=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c 'import sys; sys.exit(0 if (3,9) <= sys.version_info[:2] <= (3,12) else 1)' 2>/dev/null; then
      PYTHON="$candidate"
      break
    fi
  fi
done
if [ -z "$PYTHON" ]; then
  echo "未找到 Python 3.9~3.12，请先安装。" >&2
  exit 1
fi

VENV_PY="$SERVICE_DIR/.venv/bin/python"
if [ ! -x "$VENV_PY" ]; then
  step "创建虚拟环境 .venv（使用 $PYTHON）"
  "$PYTHON" -m venv "$SERVICE_DIR/.venv" || { echo "venv 创建失败" >&2; exit 1; }
fi

# ---- 3. 安装依赖（先 core；[ml] 失败不影响启动） ---------------------------
if [ "${SKIP_INSTALL:-0}" != "1" ]; then
  step "安装 core 依赖"
  "$VENV_PY" -m pip install --upgrade pip >/dev/null 2>&1 || true
  "$VENV_PY" -m pip install fastapi 'uvicorn[standard]' pydantic numpy \
    || warn "core 依赖安装失败（离线？）—— 先检查环境里是否已经装好。"
  # 只要 core 能 import，服务就能起来；装不上也不阻塞（离线机器常见）
  if ! "$VENV_PY" -c 'import fastapi, uvicorn' >/dev/null 2>&1; then
    echo "fastapi / uvicorn 不可用，无法启动服务。请联网后重跑，或手动安装 core 依赖。" >&2
    exit 1
  fi

  step "尝试安装 [ml] 依赖（torch / transformers / safetensors，可选）"
  "$VENV_PY" -m pip install 'transformers>=4.45' safetensors \
    || warn "ML 依赖安装失败 —— 服务仍会启动，但会运行在 degraded 降级模式。"
  "$VENV_PY" -m pip install torch \
    || warn "torch 安装失败 —— 服务仍会启动，但会运行在 degraded 降级模式。"
fi

# ---- 4. 启动 --------------------------------------------------------------
ML_HOST="${ML_HOST:-127.0.0.1}"
ML_PORT="${ML_PORT:-8000}"
RELOAD_FLAG=""
if [ "${1:-}" = "--reload" ]; then RELOAD_FLAG="--reload"; fi

step "启动 uvicorn：http://${ML_HOST}:${ML_PORT}  （Ctrl+C 停止）"
exec "$VENV_PY" -m uvicorn app.main:app --host "$ML_HOST" --port "$ML_PORT" $RELOAD_FLAG
