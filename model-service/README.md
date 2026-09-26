# ScanMan 模型推理服务（model-service）

把训练好的 **ScanMan（CodeBERT 微调）** 模型包成一个 HTTP 服务，供平台的 Node 后端 /
前端调用。两个任务：

| 任务 | 类型 | 输入 | 输出 |
|------|------|------|------|
| **任务 A 漏洞检测** | 二分类 | 一段源码 | `safe` / `vulnerable` + 置信度 |
| **任务 B 漏洞分类** | 多分类 | 一段漏洞源码 | CWE 类型（CWE-79 / CWE-89 / CWE-125 …）+ Top-5 |

> ⚠️ **最重要的一条设计**：`torch` / `transformers` / checkpoint **任意一个缺失**，本服务
> 依然能正常启动并响应所有接口，只是自动进入 **degraded 降级模式**（内置启发式 mock），
> 并且会在**每一个响应里**用 `degraded` / `degradedReason` 明确告诉你
> 「这不是模型输出」。服务**绝不会**因为找不到模型而起不来。

---

## 一、它在整个平台里的位置

```
┌──────────────────┐   扫描/上传    ┌────────────────────┐
│ ScanMan 扫描工具  │ ────────────▶ │  平台后端（Node）   │
│ (CodeBERT 微调)   │                │  /api/vulns …      │
└──────────────────┘                └─────────┬──────────┘
                                              │ HTTP（本服务）
                                              ▼
                                    ┌─────────────────────┐
                                    │ model-service       │
                                    │ FastAPI :8000       │
                                    │ /predict /health …  │
                                    └─────────────────────┘
                                              ▲
                                              │ 模型检测页直接调
                                    ┌─────────────────────┐
                                    │ 平台前端（React）    │
                                    └─────────────────────┘
```

两条典型链路：

1. **扫描入库**：ScanMan 扫描出漏洞 → 上传到平台 → Node 后端把代码片段 POST 给
   `/predict`，把 `verdict` / `predictedCwe` / 置信度一起写进漏洞记录。
2. **人工复检**：前端「模型检测」页把用户粘贴的代码 POST 给 `/predict`，实时展示
   检测结论 + Top-K CWE 概率。

本服务**无状态**、不连数据库、只做推理，可以随便重启。

---

## 二、目录结构

```
model-service/
├── app/
│   ├── __init__.py
│   ├── config.py          # 环境变量配置 + checkpoint 自动发现（不 import torch）
│   ├── model.py           # 推理核心：懒加载 / 头尾截断 / 降级启发式
│   └── main.py            # FastAPI 入口 + HTTP 契约
├── tests/
│   ├── conftest.py        # 让 pytest 在任何机器上结果一致（默认强制降级）
│   ├── test_service.py    # 32 个用例，不需要 torch、不需要 checkpoint
│   └── run_tests.py       # 离线兜底运行器（装不上 pytest 时用）
├── .tools/
│   ├── fetch_wheels.py    # 离线机器上手工抓 wheel 的小工具
│   └── verify_live.ps1    # 一键冒烟：起服务 → curl → 杀进程
├── requirements.txt       # [core] 必装 / [dev] 测试 / [ml] 可选
├── run.ps1 / run.sh       # 启动脚本（建 venv → 装依赖 → uvicorn）
├── .env.example           # 环境变量示例
├── pytest.ini
└── README.md
```

---

## 三、快速开始

### 3.1 一键启动（推荐）

```powershell
# Windows
cd D:\ai_demo\demo\漏洞管理平台\model-service
.\run.ps1
```

```bash
# Linux / macOS / Git Bash
cd model-service
chmod +x run.sh && ./run.sh
```

脚本会：建 `.venv` → 装 `requirements.txt`（core 必需，`[ml]` 装不上也继续）→
`uvicorn app.main:app --host $ML_HOST --port $ML_PORT`。

常用参数：

| 命令 | 作用 |
|------|------|
| `.\run.ps1 -Reload` | 开发模式（热重载） |
| `.\run.ps1 -SkipInstall` | 依赖已装好，跳过 pip（离线机器用这个） |
| `SKIP_INSTALL=1 ./run.sh` | 同上（Linux/macOS） |

### 3.2 手动启动

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows
# source .venv/bin/activate       # Linux/macOS
pip install -r requirements.txt   # 只想跑通链路：pip install fastapi "uvicorn[standard]" pydantic numpy
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

起来之后：

- Swagger 文档：<http://127.0.0.1:8000/docs>
- 健康检查：<http://127.0.0.1:8000/health>

### 3.3 配置

所有配置都是环境变量，复制 `.env.example` 为 `.env` 即可（启动脚本会自动读取）。

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `ML_HOST` | `127.0.0.1` | 监听地址 |
| `ML_PORT` | `8000` | 监听端口 |
| `SCANMAN_ROOT` | 无 | **ScanMan 训练工程根目录**（含 `outputs/`），在此目录下自动找 `outputs/*/best` 与 `**/best`。多个目录用 `;`（Windows）/ `:` 分隔 |
| `DETECTION_CHECKPOINT` | 自动发现 | 检测 checkpoint 的 `best/` 目录（优先级最高） |
| `CLASSIFICATION_CHECKPOINT` | 自动发现 | 分类 checkpoint 的 `best/` 目录（优先级最高） |
| `MODEL_DEVICE` | `auto` | `auto`（有 CUDA 就用）/ `cpu` / `cuda` / `cuda:0` |
| `MAX_LENGTH` | `512` | 最大 token 数（头尾截断预算） |
| `DETECTION_THRESHOLD` | `0.5` | `vulnerableProbability >= 阈值` ⇒ `vulnerable` |
| `TOP_K` | `5` | 分类返回的 Top-K 个数 |
| `ML_FORCE_DEGRADED` | `0` | 设为 `1` 强制降级（演示 / 联调 / 测试用） |

> **权重不在本仓库时怎么接**：ScanMan 的训练产物通常放在另一个工程目录
> （例如 `D:\workbuddy_workspace\vuln_bert\outputs\`）。此时**不需要拷贝权重**，
> 只要把训练工程根目录告诉本服务即可：
>
> ```ini
> SCANMAN_ROOT=D:\workbuddy_workspace\vuln_bert
> ```
>
> 若检测与分类不在同一个工程下，用分号分隔多个根目录：
> `SCANMAN_ROOT=D:\projA;E:\projB`。

---

## 四、怎么指向真实 checkpoint

### 4.1 两种方式

**方式一（推荐，最明确）**：在 `.env` 里写绝对路径

```ini
DETECTION_CHECKPOINT=D:\ai_demo\demo\demo1_git\ScanMan\outputs\cvefixes_detection_codebert-base\best
CLASSIFICATION_CHECKPOINT=D:\...\outputs\<你的分类run>\best
```

指向 `best/` 目录，也可以直接指到 `pytorch_model.bin`（会自动上溯到 `best/`）。

**方式二：自动发现**。不设环境变量时，按下面的顺序找：

1. `SCANMAN_ROOT` 指向目录下的 `outputs/*/best` 与 `**/best`
2. 相对 `model-service/` 的固定相对路径：
   `../ScanMan/outputs/*/best`、`../../outputs/*/best`、`./outputs/*/best`、`../outputs/*/best`
3. 从仓库根 glob：`**/outputs/*_detection_*/best`、`**/outputs/*_classification_*/best`

找到多个候选时，**优先选有权重文件的**（`pytorch_model.bin` / `model.safetensors`）。

检测 / 分类怎么区分？按 `label_map.json` 的内容和 run 目录名：

- `label_map.json` 里出现 `task: "detection"`，或映射只有 `safe`/`vulnerable` 两种标签 →
  **检测**；
- 映射里出现 `CWE-xxx` → **分类**；
- 都没有时看 run 目录名里有没有 `detection` / `classification`。

### 4.2 训练产物的两种摆放，本服务都支持

| 布局 | `best/` 里有什么 | 加载方式 |
|------|------------------|----------|
| **A. 标准 HF 目录** | `config.json` + 权重 + tokenizer | `AutoModelForSequenceClassification.from_pretrained` |
| **B. ScanMan 训练脚本产物** | 权重 + tokenizer，**没有 config.json** | 从权重张量形状反推 `RobertaConfig`，重建 `encoder + Linear`（CLS pooling）后逐张量加载 |

布局 B 是当前训练脚本实际产出的形式：`best/pytorch_model.bin` 里的 key 是
`encoder.*`（199 个张量，即 `RobertaModel`）+ `classifier.weight/bias`（单层 Linear），
对应 `config.yaml` 里的 `pooling: cls`、`head_ratio: 0.6`。服务会读
`<run>/config.yaml` 拿到 `model.name` / `pooling` / `dropout` 来重建，并校验
`missing_keys` / `unexpected_keys` 必须为空，否则按加载失败处理、降级并说明原因。

### 4.3 好消息 / 坏消息

- `best/` 里**没有 `config.json`**、`label_map.json` 是嵌套结构
  （`{"task":..., "id2name":{"0":"safe","1":"vulnerable"}}`）—— 这两种情况本服务都已处理。
- 如果 `best/` 里**只有 `label_map.json`** 而没有权重（本机好几个 run 目录都是这样），
  服务会明确告诉你「缺少权重文件」并降级，而不是崩掉。

---

## 五、degraded 降级模式

### 5.1 什么时候会降级

任意一条成立即降级：

1. `torch` 或 `transformers` 装不上 / import 失败；
2. 找不到对应任务的 `best/` 目录；
3. `best/` 里没有权重文件；
4. 权重能读但结构和重建的模型对不上 / tokenizer 缺失；
5. 手动设了 `ML_FORCE_DEGRADED=1`。

### 5.2 降级时做什么

用内置的**确定性启发式规则**（`HEURISTIC-MOCK/v1`）给结果。规则全部是高信号正则，
例如：

| 命中特征 | 映射 CWE |
|----------|----------|
| `strcpy` / `strcat` / `sprintf` 写入定长缓冲区 | CWE-787 越界写入 |
| `gets` / `scanf("%s")` | CWE-119 缓冲区溢出 |
| SQL 语句用 `+` / `.format()` / f-string 拼接 | CWE-89 SQL 注入 |
| `eval(` / `exec(` / `new Function(` | CWE-94 代码注入 |
| `.innerHTML=` / `document.write(` / PHP 未转义回显 | CWE-79 XSS |
| `system(` / `popen` / `shell=True` / `Runtime.exec` | CWE-78 命令注入 |
| `pickle.loads` / `yaml.load` / `unserialize` / `readObject` | CWE-502 反序列化 |
| `password = "..."` / `api_key = "..."` | CWE-798 硬编码凭证 |
| 外部输入直接拼路径 | CWE-22 路径遍历 |
| `malloc` 后未判空即解引用 | CWE-476 空指针 |
| `free(x)` 之后又用 `x` | CWE-416 释放后使用 |
| 数组下标来自 `atoi`/`request` 且全文没有边界判断 | CWE-125 越界读取 |

打分是确定性的（同样的输入永远给同样的输出），概率用
`0.02 + 0.96 × (1 − e^(−3.2 × 命中权重和))` 映射，所以**看起来像概率但本质是 mock**。

> 它是"让链路能跑通"的临时替身，**不是**模型。不要用它出任何结论。

### 5.3 怎么一眼看出现在是降级

**看 `/health`：**

```json
{
  "status": "ok",
  "modelServed": false,        // ← false 就是没在用真模型
  "degraded": true,            // ← true 就是降级
  "degradedReason": "降级模式：[detection] ML_FORCE_DEGRADED=1：…",   // ← 人话原因
  "modelName": "heuristic-mock",   // ← 降级时固定是这个名字
  "torchAvailable": true,
  "transformersAvailable": true
}
```

**看 `/predict`：** 每个响应都有 `modelServed` / `degraded` / `degradedReason`
三个字段，`degradedReason` 会说明**是哪个任务**降级了、**为什么**。

**部分可用**也是允许的状态（很常见）：

- 只有检测 checkpoint → `/health` 里 `detectionCheckpoint` 有值、
  `classificationCheckpoint: null`，`degraded: true`；
- 此时 `POST /predict {"mode":"detection"}` 返回 `modelServed: true, degraded: false`
  （这个任务真的是模型算的）；
- 而 `{"mode":"auto"}` 因为还要求分类，所以返回 `modelServed: false, degraded: true`。

> 判定规则很简单：**本次请求需要的任务全都由真模型完成 → `modelServed:true`；
> 只要有一个任务用了启发式 → `degraded:true`。**

---

## 六、HTTP 契约

所有接口都返回 JSON。字段名**已冻结**，Node 后端按此解析。

### 6.1 `GET /health`

```json
{
  "status": "ok",
  "modelServed": true,
  "degraded": false,
  "degradedReason": null,
  "modelName": "codebert-base",
  "detectionCheckpoint": "D:\\...\\cvefixes_detection_codebert-base\\best",
  "classificationCheckpoint": null,
  "device": "cpu",
  "torchAvailable": true,
  "transformersAvailable": true,
  "version": "1.0.0"
}
```

### 6.2 `GET /model/info`

```json
{
  "tasks": {
    "detection": {
      "available": true,
      "checkpoint": "D:\\...\\cvefixes_detection_codebert-base\\best",
      "numLabels": 2,
      "labelMap": { "0": "safe", "1": "vulnerable" }
    },
    "classification": {
      "available": false,
      "checkpoint": null,
      "numLabels": null,
      "labelMap": null,
      "cweCount": null
    }
  },
  "device": "cpu",
  "maxLength": 512,
  "detectionThreshold": 0.5,
  "degraded": true,
  "degradedReason": "降级模式：[classification] 未发现 classification checkpoint…"
}
```

> `labelMap` 已经**拍平**成 `{id: 名称}`（训练产物里的 `id2name` 嵌套会被拆开）。
> 分类任务的 `labelMap` 是 `{ "0": "CWE-79", … }`，额外多一个 `cweCount`。

### 6.3 `POST /predict`

请求体：

```json
{
  "code": "void f(char *s){ char buf[10]; strcpy(buf, s); }",
  "mode": "auto",
  "threshold": 0.5,
  "topK": 5,
  "filePath": "src/a.c",
  "language": "C"
}
```

- `code` 必填；**空字符串或全空白 → HTTP 422 `{"detail":"code 不能为空"}`**
- `mode`：`auto`（默认，两个任务都跑）/ `detection`（只检测）/ `classification`（只分类）。
  给了 `null` 或无法识别的值一律按 `auto` 处理，不会 422。
- `threshold` / `topK`：不传就用服务配置。

响应（**字段顺序即下表顺序**）：

```json
{
  "modelServed": true,
  "degraded": false,
  "degradedReason": null,
  "modelName": "codebert-base",
  "tasks": {
    "detection": { "modelServed": true, "degraded": false, "modelName": "codebert-base", "reason": null },
    "classification": { "modelServed": true, "degraded": false, "modelName": "codebert-base", "reason": null }
  },
  "latencyMs": 86,
  "verdict": "vulnerable",
  "vulnerableProbability": 0.859113,
  "safeProbability": 0.140887,
  "threshold": 0.5,
  "predictedCwe": "CWE-787",
  "predictedCweName": "Out-of-bounds Write",
  "cweConfidence": 0.612,
  "topCwe": [{ "cwe": "CWE-787", "name": "Out-of-bounds Write", "probability": 0.612 }]
}
```

#### 关于 `tasks`（逐任务来源）—— 为什么必须有它

顶层的 `modelServed` / `degraded` / `modelName` 是**「本次请求涉及的**所有**任务」的合成结果**：

> `mode=auto` 时，只要**任意一个**任务降级，整体就是 `degraded: true`、
> `modelName: "heuristic-mock"`。但另一个任务**可能仍然是真实模型算出来的**。

本机的真实情况正好踩中这一点：只有检测权重、没有分类权重，于是

```
mode=auto  →  modelServed:false, degraded:true, modelName:"heuristic-mock"
              verdict:"vulnerable"   ← 但这个是 ScanMan 模型算的（vulnerableProbability 0.873）
              predictedCwe:"CWE-787" ← 这个是启发式 mock 编的
```

只看顶层字段，会把**真模型判定的漏洞**误当成 mock 结果丢掉。所以每个任务单独标注来源：

| `tasks.<task>` 字段 | 含义 |
|---|---|
| `modelServed` | 该任务本次是否由真实模型完成 |
| `degraded` | 该任务是否降级 |
| `modelName` | 该任务的结果来自哪个模型（降级时是 `HEURISTIC-MOCK/v1`） |
| `reason` | 该任务降级的原因（未降级为 `null`） |

**调用方应该这样用**：展示 `verdict` 时看 `tasks.detection.modelServed`；
展示 CWE 时看 `tasks.classification.modelServed`。别用顶层 `modelServed` 一刀切。

> 本平台前端的「模型检测」页就是这么做的：对真实模型产出的部分正常展示，
> 只对降级的部分显示「启发式 mock」提示。
> （`tasks` 是**新增字段**，符合契约"只增字段、不删不改语义"的策略；老客户端忽略即可。）

各字段随 `mode` 的取值：

| 字段 | `auto` | `detection` | `classification` |
|------|--------|-------------|------------------|
| `verdict` / `vulnerableProbability` / `safeProbability` | 有值 | 有值 | **`null`** |
| `predictedCwe` / `predictedCweName` / `cweConfidence` | 有值 | **`null`** | 有值 |
| `topCwe` | 有值 | **`[]`** | 有值 |

其他说明：

- `latencyMs` 是**真实测量**的整数（毫秒，含分词 + 前向 + 后处理）。
- `threshold` 是本次实际生效的阈值。
- `topCwe[].probability` 在 Top-K 内部归一化（和为 1）。
- `predictedCweName` 来自内置 CWE 名称表；表里没有的 id → `null`（`predictedCwe` 仍是
  `CWE-xxx` 字符串）。
- `modelName` 在被服务为纯 mock 时是 `"heuristic-mock"`。

**curl 示例：**

```bash
curl -s http://127.0.0.1:8000/health

curl -s -X POST http://127.0.0.1:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"code":"void f(char *s){ char buf[10]; strcpy(buf, s); }","mode":"auto"}'

# 只做检测（CWE 字段全为 null）
curl -s -X POST http://127.0.0.1:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"code":"os.system(\"ping \" + host)","mode":"detection","threshold":0.7}'

# 只做分类
curl -s -X POST http://127.0.0.1:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"code":"query = \"SELECT * FROM u WHERE n = \x27\" + n + \"\x27\";","mode":"classification","topK":3}'
```

> Windows 上引号很麻烦，建议把 body 写进文件再 `curl -d @body.json`。

### 6.4 `POST /predict/batch`

```json
{
  "items": [
    { "code": "...", "mode": "detection", "filePath": "a.c", "language": "C" },
    { "code": "...", "mode": null, "filePath": null, "language": null }
  ],
  "threshold": 0.5
}
```

响应：

```json
{ "results": [ { /* 与 /predict 完全同结构 */ }, { /* ... */ } ] }
```

- `items` **最多 100 条**，超过 → HTTP 422
  `{"detail":"items 数量不能超过 100（当前 101）"}`
- `items` 为空数组 → `{"results": []}`（200，不是错误）
- 某条 `code` 为空 → HTTP 422 `{"detail":"items[3].code 不能为空"}`
- 批量的每一条都用请求里的 `threshold`，`topK` 用服务配置。

### 6.5 CORS

已开 `allow_origins=["*"]`、`allow_methods=["*"]`、`allow_headers=["*"]`
（只被服务端和本地前端调用，不涉及 Cookie，所以不启用 credentials）。

---

## 七、给 Node 后端的接入提示

1. **永远先看 `degraded`**。`degraded: true` 时结果来自启发式 mock，页面上应该打一个
   「降级模式 · 结果仅供参考」的提示，别当成模型结论展示。
2. **`mode` 用法**：入库时通常 `detection`（快速筛），需要 CWE 时用 `auto`。
3. **`auto` 模式下如果有一个任务降级，整个响应就是 `degraded: true`**，但
   `vulnerableProbability` 可能仍是真模型算的 —— 想精确区分就分开调两次
   （`detection` + `classification`），这样每个响应的 `modelServed` 都是准确的。
4. **超时**：CPU 上单条 512-token 首次推理约 0.2~1s（首次还要 +几秒加载权重）。
   建议 Node 侧超时 ≥ 30s，并在服务启动后再打流量。
5. **不要并发打爆**：批量接口是**串行**推理的，100 条在 CPU 上可能要十几秒。
   要并行就拆成多个请求。
6. `POST /predict` 的 422 有两个来源：契约校验（`detail` 是字符串，中文提示）和
   Pydantic 类型错误（`detail` 是数组）。建议前端只对 `code` 做前置校验。

---

## 八、测试

```bash
cd model-service
python -m pytest tests -q
```

**32 个用例，全部不需要 torch / transformers / checkpoint** —— `tests/conftest.py`
默认设置 `ML_FORCE_DEGRADED=1`，所以结果与机器上有没有模型无关。覆盖：

- `/health`、`/model/info` 的字段集合与顺序（锁死契约，防止重构打乱）
- `/predict` 在 `auto` / `detection` / `classification` 三种 mode 下的取空规则
- 空 code → 422 且 `detail` 是中文；batch 超过 100 条 → 422；batch 空数组 → 200
- **头尾截断**单元测试：不超过 `max_length`、不切断 token、结果是有序子序列、
  不修改入参、6:4 比例精确、退化比例（0 / 1）边界
- **降级启发式**：`strcpy` 进小缓冲区 → 判漏洞；`int add(int a,int b){return a+b;}`
  → 不判漏洞；SQL 注入 / 命令注入 / 硬编码口令各自命中对应 CWE；同一输入输出完全可复现
- CWE 名称表与 `normalize_cwe` 的各种写法

想用真模型跑同一套测试：

```bash
ML_TEST_ALLOW_MODEL=1 DETECTION_CHECKPOINT=<你的 best 目录> python -m pytest tests -q
```

> 装不上 pytest 的离线机器可以跑 `python tests/run_tests.py`，它用同样的断言
> （测试文件刻意只用普通 `assert`，不依赖 pytest 专有 API）。

---

## 九、冒烟验证

```powershell
# 降级模式（强制）
.\.tools\verify_live.ps1 -Mode degraded -Port 8000

# 真模型模式（指向检测 checkpoint）
.\.tools\verify_live.ps1 -Mode real -Port 8000 `
    -DetectionCheckpoint 'D:\...\outputs\cvefixes_detection_codebert-base\best'
```

脚本会启动 uvicorn → curl `/health`、`/model/info`、`/predict`、`/predict/batch`
→ 打印原始 JSON → 杀掉进程。

---

## 十、排错

| 现象 | 原因 / 处理 |
|------|-------------|
| `/health` 一直 `degraded: true`，`degradedReason` 说「未发现 … checkpoint」 | 没找到 `best/`。用 `DETECTION_CHECKPOINT` / `CLASSIFICATION_CHECKPOINT` 明确指过去 |
| `degradedReason` 说「缺少权重文件」 | 那个 run 目录只存了 `label_map.json`（多半是冒烟测试产物）。换一个有 `pytorch_model.bin` 的 run |
| `degradedReason` 说「torch/transformers 不可用」 | 装 ML 依赖：`pip install torch transformers safetensors`。CPU 版更快：`pip install torch --index-url https://download.pytorch.org/whl/cpu` |
| 启动日志 `checkpoint 加载失败：ValueError: Unrecognized model … Should have a model_type key` | 这版已修复（从张量形状反推配置）。若仍出现，说明权重 key 布局既不是 HF 标准也不是 `encoder.*`+`classifier.*`，请把 key 前缀发给模型同学 |
| `degradedReason` 说「权重与重建结构不一致」 | 同上；日志里有 `missing` / `unexpected` 的前 5 个 key，对照训练侧 `src/models.py::VulnClassifier` |
| 推理结果明显不对（安全代码判成漏洞） | 先确认不是降级（`modelServed: true`）。若真是模型，多半是**输入太短**：CodeBERT 在 CVEfixes 这种"函数级"数据上训练，对 `int add(int a,int b){return a+b;}` 这类 2 行片段属于分布外，输出不可信 |
| 端口被占用 | `ML_PORT=8010 .\run.ps1` |
| `run.ps1` 报「未找到 Python 3.9~3.12」 | 装 Python 3.9~3.12 并加入 PATH；或手动建 venv 后 `.\run.ps1 -SkipInstall` |
| pip 装不上依赖 / 网络受限 | `.\run.ps1 -SkipInstall`（环境已就绪时）；完全离线又缺 pytest，可用 `.tools\fetch_wheels.py` 从可达的 PyPI 镜像手工抓 wheel，再 `pip install --no-index --find-links <目录> pytest` |
| `CUDA out of memory` / 想强制 CPU | `MODEL_DEVICE=cpu` |

---

## 十一、关键实现说明

1. **懒加载 + 线程安全**：`InferenceEngine` 在**首次使用**时才 import torch 并加载权重，
   用 `threading.Lock` 保证并发请求下只加载一次（双重检查）。加载失败不会向上抛，
   而是记成「该任务不可用 + 原因」，让服务继续跑。
2. **头尾截断（head+tail 6:4）**：与训练侧 `src/utils.py::truncate_code` 一致 ——
   在 token 级保留前 60% + 后 40%。漏洞代码的关键信息（参数校验、循环边界、`free()`）
   常出现在函数首尾，比只截尾保留更多信息。实现见 `head_tail_truncate()`，
   保证**不切断 token、长度不超过 `max_length`**。
3. **transformers 4.x / 5.x 双兼容**：5.x 删掉了
   `tokenizer.build_inputs_with_special_tokens`，`_wrap_with_special_tokens()` 会先试旧
   API，再退回手工拼 `cls/sep`（`<s> … </s>`）。
4. **检测任务的概率方向**：按 `label_map` 找 `vulnerable` 的下标（`{safe:0, vulnerable:1}`
   或 `{0:'safe',1:'vulnerable'}` 两种写法都支持），再 softmax 取该下标。
5. **CWE 名称表**：内置 25+ 个常见 CWE 的英文短名（`{cwe, name}` 里的 `name`）和中文名
   （`cwe_name_zh()`，内部使用）。表里没有的 id → `name: null`。
