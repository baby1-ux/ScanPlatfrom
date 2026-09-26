# =============================================================================
# ScanMan 模型服务启动脚本（Windows PowerShell）
#
#   .\run.ps1                 # 用默认配置启动
#   .\run.ps1 -Reload         # 开发模式（代码热重载）
#   .\run.ps1 -SkipInstall    # 跳过 pip install（依赖已装好时更快）
#
# 行为：
#   1. 选一个可用的 Python（py -3 / python / python3）
#   2. 没有 .venv 就创建，并安装 requirements.txt
#      —— 注意：requirements.txt 里的 [ml] 块（torch/transformers）是**可选**的，
#         装不上或没装都不影响服务启动，服务会自动进入 degraded 降级模式。
#   3. uvicorn app.main:app --host $env:ML_HOST --port $env:ML_PORT
# =============================================================================

[CmdletBinding()]
param(
    [switch]$Reload,
    [switch]$SkipInstall
)

$ErrorActionPreference = 'Stop'
$ServiceDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ServiceDir

function Write-Step([string]$Text) { Write-Host "==> $Text" -ForegroundColor Cyan }
function Write-Warn2([string]$Text) { Write-Host "[!] $Text" -ForegroundColor Yellow }

# ---- 1. 读取 .env（仅用于 ML_HOST / ML_PORT 等，简单的 KEY=VALUE） ----------
$envFile = Join-Path $ServiceDir '.env'
if (Test-Path $envFile) {
    Write-Step "读取 $envFile"
    # 必须用 .NET 读：它会自动识别 BOM，且无 BOM 时按 UTF-8 解码。
    # 不能用 Get-Content —— Windows PowerShell 5.1 默认按系统 ANSI(GBK) 解码，
    # 一旦 checkpoint 路径含中文（如 ...\漏洞管理平台\model\...）就会被读成乱码，
    # 结果是「环境变量指定的 detection checkpoint 不存在」而误进降级模式。
    foreach ($raw in [System.IO.File]::ReadAllLines($envFile)) {
        $line = $raw.Trim()
        if ($line -eq '' -or $line.StartsWith('#')) { continue }
        $idx = $line.IndexOf('=')
        if ($idx -lt 1) { continue }
        $key = $line.Substring(0, $idx).Trim()
        $value = $line.Substring($idx + 1).Trim().Trim('"').Trim("'")
        if ($value -ne '' -and -not (Test-Path "env:$key")) {
            Set-Item -Path "env:$key" -Value $value
        }
    }
}

# ---- 2. 找 Python ----------------------------------------------------------
$script:PythonTried = @()

function Resolve-Python {
    foreach ($candidate in @('py -3', 'python', 'python3')) {
        # 注意：不能写成 $parts[1..($parts.Length - 1)]。当候选只有一个词（如 python）时
        # PowerShell 的 1..0 是倒序范围，会把 exe 本身又当成参数传进去，命令必然失败。
        $parts = @($candidate -split '\s+' | Where-Object { $_ -ne '' })
        $exe = Get-Command $parts[0] -ErrorAction SilentlyContinue
        if (-not $exe) { continue }
        $rest = @()
        if ($parts.Count -gt 1) { $rest = @($parts[1..($parts.Count - 1)]) }
        try {
            $version = & $parts[0] @rest --version 2>&1
        } catch { continue }
        $script:PythonTried += "$candidate => $version"
        if ($LASTEXITCODE -eq 0 -and "$version" -match 'Python 3\.(9|1[0-2])') {
            return $candidate
        }
    }
    return $null
}

$pythonCmd = Resolve-Python
if (-not $pythonCmd) {
    $detail = ''
    if ($script:PythonTried.Count -gt 0) {
        $detail = "`n  已尝试：`n    " + ($script:PythonTried -join "`n    ")
    }
    Write-Error "未找到 Python 3.9~3.12。请先安装 Python 3.9~3.12 并加入 PATH。$detail"
}

$venvPython = Join-Path $ServiceDir '.venv\Scripts\python.exe'
if (-not (Test-Path $venvPython)) {
    Write-Step "创建虚拟环境 .venv（使用 $pythonCmd）"
    $parts = @($pythonCmd -split '\s+' | Where-Object { $_ -ne '' })
    $rest = @()
    if ($parts.Count -gt 1) { $rest = @($parts[1..($parts.Count - 1)]) }
    & $parts[0] @rest -m venv (Join-Path $ServiceDir '.venv')
    if (-not (Test-Path $venvPython)) {
        Write-Error '虚拟环境创建失败。'
    }
}

# ---- 3. 安装依赖（永远先装 core；[ml] 装不上也不影响启动） -----------------
if (-not $SkipInstall) {
    Write-Step '安装 core 依赖'
    & $venvPython -m pip install --upgrade pip | Out-Null
    & $venvPython -m pip install fastapi "uvicorn[standard]" pydantic numpy
    if ($LASTEXITCODE -ne 0) {
        Write-Warn2 'core 依赖安装失败（离线？）—— 先检查环境里是否已经装好。'
    }

    # 只要 core 能 import，服务就能起来；装不上也不阻塞（离线机器常见）
    & $venvPython -c 'import fastapi, uvicorn' 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Error 'fastapi / uvicorn 不可用，无法启动服务。请联网后重跑，或手动安装 core 依赖。'
    }

    Write-Step '尝试安装 [ml] 依赖（torch / transformers / safetensors，可选）'
    & $venvPython -m pip install "transformers>=4.45" safetensors
    if ($LASTEXITCODE -ne 0) {
        Write-Warn2 'ML 依赖安装失败 —— 服务仍会启动，但会运行在 degraded 降级模式。'
    }
    & $venvPython -m pip install torch
    if ($LASTEXITCODE -ne 0) {
        Write-Warn2 'torch 安装失败 —— 服务仍会启动，但会运行在 degraded 降级模式。'
        Write-Warn2 '  有 GPU：pip install torch --index-url https://download.pytorch.org/whl/cu121'
        Write-Warn2 '  纯 CPU：pip install torch --index-url https://download.pytorch.org/whl/cpu'
    }
}

# ---- 4. 启动 --------------------------------------------------------------
$hostAddr = if ($env:ML_HOST) { $env:ML_HOST } else { '127.0.0.1' }
$portNum = if ($env:ML_PORT) { $env:ML_PORT } else { '8000' }

Write-Step "启动 uvicorn：http://${hostAddr}:${portNum}  （Ctrl+C 停止）"
$uvicornArgs = @('-m', 'uvicorn', 'app.main:app', '--host', $hostAddr, '--port', $portNum)
if ($Reload) { $uvicornArgs += '--reload' }
& $venvPython @uvicornArgs
