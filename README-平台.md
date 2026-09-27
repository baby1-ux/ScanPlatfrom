# 漏洞管理平台（Vulnerability Management Platform）

> 接收 **ScanMan** 扫描工具上报的**漏洞信息**与**正负样本**，入库后提供登录、数据看板、漏洞查询与处置界面。
> 技术栈：**Node.js + React + Ant Design + SQLite/MySQL + Python（ScanMan 模型推理）**

---

## 1. 一句话说清流程

```
开发者 push 代码
      │
      ▼
┌──────────────┐   CI 拉取执行    ┌──────────────────────────┐
│ GitHub/GitLab │ ─────────────▶ │ ScanMan 扫描工具 (CI)      │
└──────────────┘                 │ · BERT 漏洞检测 / CWE 分类  │
                                 └───────────┬──────────────┘
                                             │ HTTP + X-API-Key，4 步上报
                                             │ 1) POST /ingest/scans                       创建批次
                                             │ 2) POST /ingest/scans/{no}/vulnerabilities  上报漏洞
                                             │ 3) POST /ingest/scans/{no}/samples          上报正负样本
                                             │ 4) POST /ingest/scans/{no}/complete         结束批次
                                             ▼
                                 ┌──────────────────────────┐
                                 │  平台后端 (Express)        │ 校验 Key → 参数校验 → 指纹去重 → 入库
                                 └───────────┬──────────────┘
                                             ▼
                                 ┌──────────────────────────┐
                                 │ SQLite（默认）/ MySQL 8.0  │ projects / scan_tasks /
                                 └───────────┬──────────────┘ vulnerabilities / samples / …
                                             ▼
                                 ┌──────────────────────────┐
                                 │  React + AntD 前端         │ 登录 → 看板 → 漏洞列表/详情 → 处置
                                 └──────────────────────────┘
```

配套的 **ScanMan 模型推理服务**（`model-service/`）独立运行：前端「模型检测」页通过平台后端代理调用它，
可对单段代码做漏洞判定与 CWE 分类，并一键归档为扫描批次与样本。

---

## 2. 快速开始

### 2.1 前置

| 项 | 版本 |
|---|---|
| Node.js | ≥ 20.11（用到内置 `node:sqlite`，**无需 MySQL 实例、无需 C++ 编译工具链**） |
| pnpm | ≥ 9 |
| Python | 3.9~3.12（仅模型推理服务需要） |

### 2.2 启动

```bash
# 1) 安装依赖（monorepo：apps/server + apps/web + packages/shared）
pnpm install

# 2) 配置环境变量
copy .env.example .env        # Windows；Linux/macOS 用 cp

# 3) 建库 + 灌演示数据（8 个项目 / 100+ 批次 / 140 漏洞 / 7500+ 样本）
pnpm -C apps/server db:reset

# 4) 同时启动前后端
pnpm dev
```

访问 **http://127.0.0.1:5173** ，用 `admin / Admin@12345` 登录。

> 演示账号：`admin`（管理员）、`auditor`（安全审计员）、`viewer`（只读）—— 密码均为 `Admin@12345`。

### 2.3 启动模型服务（可选，推荐）

```bash
cd model-service
./run.ps1            # Windows；Linux/macOS 用 ./run.sh
```

模型服务起来后，前端顶部标签会从「模型服务 离线」变为「在线」，
「模型检测」页的结果即来自真实的 ScanMan 模型；离线时会明确标记为**降级启发式判定**。
详见 [`model-service/README.md`](model-service/README.md)。

> **重要：权重通常不在本仓库内。** 已训练好的 ScanMan 检测权重在本机位于
> `D:\ai_demo\demo\demo1_git\ScanMan\outputs\cvefixes_detection_codebert-base\best`（475 MB）。
> 启动前把训练工程根目录告诉模型服务即可，**不需要拷贝权重**：
>
> ```powershell
> $env:SCANMAN_ROOT = 'D:\ai_demo\demo\demo1_git\ScanMan'
> ./run.ps1
> ```
>
> 或直接指定 `DETECTION_CHECKPOINT='...\cvefixes_detection_codebert-base\best'`。
>
> **分类任务例外**：该工程下所有 `*_classification_*` / `merged_top27_*` 的 `best/`
> 里**只有 `label_map.json`、没有权重文件**，因此 CWE 分类只能走降级；
> 这时 `/health` 会显示 `detection.available: true` 而整体 `degraded: true` ——
> 这是正确行为，页面上也会提示。

### 2.4 验证链路

```bash
# 单元/集成测试：59 个用例，覆盖鉴权、幂等、指纹去重、状态流转、统计口径、角色权限、
# 错误码与边界（不需要先起服务，使用独立的临时 SQLite 库）
pnpm test

# 端到端冒烟测试：覆盖上报 4 步 + 幂等 + 错误码 + 看板数字一致性（54 项检查，需先启动后端）
pnpm smoke
```

---

## 3. 实际落地了什么

| 里程碑 | 文档要求 | 当前状态 |
|---|---|---|
| M1 骨架 + Mock | monorepo 骨架 | ✅ 已落地，且**不再需要 Mock** —— 后端已可直接跑 |
| M2 后端上报链路 | ingest 全部接口 + Key 鉴权 + 幂等去重 | ✅ 全部实现并通过冒烟测试 |
| M3 后端查询与统计 | 漏洞/项目/扫描/样本查询 + 统计 | ✅ 全部 P0 接口实现 |
| M4 前端 | 登录 → 布局 → 看板 → 漏洞列表/详情 → 其余页面 | ✅ 9 个页面全部实现 |
| M5 联调验收 | 真实扫描工具端到端 | ⏳ 后端已就绪，等扫描侧接入 |
| M6 增强 | 导出、Webhook、告警、审计 | CSV 导出已做；Webhook/告警/审计为 P2 |

### 3.1 目录结构

```
漏洞管理平台/
├── apps/
│   ├── server/                     # Node.js 后端（Express 4 + TypeScript + zod）
│   │   ├── src/
│   │   │   ├── app.ts              # Express 装配（helmet/cors/trace/限流/错误处理）
│   │   │   ├── index.ts            # 启动入口
│   │   │   ├── config/             # 环境变量与常量
│   │   │   ├── core/               # errors / http / auth / validate / rateLimit
│   │   │   ├── db/                 # 适配层 + DDL + 种子数据
│   │   │   │   ├── index.ts        # Db 接口 + SQLite 实现（换 MySQL 只改这里）
│   │   │   │   ├── schema.ts       # 建表 DDL（由文档 MySQL DDL 逐字段翻译）
│   │   │   │   ├── seed.ts         # 演示数据（走真实 ingest 服务生成）
│   │   │   │   └── seedData.ts     # 规则库 / 项目库
│   │   │   ├── services/           # fingerprint（指纹与片段规范化）
│   │   │   ├── modules/            # auth | ingest | vulnerability | project | scan
│   │   │   │                       # sample | stats | apiKey | user | ml
│   │   │   └── scripts/            # db:reset / db:seed
│   │   └── dist/                   # tsc 产物
│   └── web/                        # React 18 + Vite 5 + AntD 5 前端
│       └── src/
│           ├── api/                # axios 封装（拦截器 / 统一解包 / 401 跳登录）
│           ├── store/auth.ts       # zustand：用户与权限
│           ├── layouts/BasicLayout.tsx
│           ├── components/common.tsx   # 等级/状态标签、时间与文件位置格式化
│           └── pages/              # login | dashboard | vulnerability | project
│                                   # scan | sample | model | setting
├── packages/shared/                # 前后端共享类型与枚举（单一事实来源）
├── model-service/                  # ScanMan 模型推理服务（FastAPI）
├── scripts/smoke-ingest.mjs        # 端到端冒烟测试
├── apps/server/tests/              # 集成测试（node:test，59 个用例）
├── docs/                           # 需求文档 / API 契约 / OpenAPI
├── data/vuln_platform.db           # SQLite 数据库文件（自动生成）
├── .env.example
└── README-平台.md                   # 本文档
```

### 3.2 页面清单

| 路由 | 页面 | 要点 |
|---|---|---|
| `/login` | 登录页 | 居中卡片、回车提交、记住我、失败不区分账号是否存在 |
| `/dashboard` | **数据看板** | 4 张统计卡 + 趋势面积图 + 等级环图 + 状态柱图 + Top 规则/项目 + 最近批次表；支持项目与时间范围筛选 |
| `/vulnerabilities` | 漏洞列表 | 12 个筛选条件、分页、排序、批量改状态、导出 CSV、筛选条件同步到 URL |
| `/vulnerabilities/:id` | 漏洞详情 | 代码高亮（带行号）、描述与修复建议、处置时间线、关联样本、状态/指派/备注抽屉 |
| `/projects` | 项目管理 | 列表 + 统计、新建/编辑项目（扫描上报也会自动建） |
| `/projects/:id` | 项目详情 | 等级分布环图、项目信息、最近 5 次扫描 |
| `/scans` | 扫描记录 | 批次列表、文件覆盖率进度条、耗时、状态徽标 |
| `/scans/:scanNo` | 批次详情 | 等级分布、Top 规则、进度与时间线 |
| `/samples` | 样本库 | 正/负/全部切换、片段预览抽屉（含哈希） |
| `/model` | **模型检测** | 调 ScanMan 模型做检测/分类，展示概率与 Top-5 CWE；可归档为扫描批次 + 样本 |
| `/settings` | 系统设置 | 用户管理、API Key 管理（明文仅显示一次）、角色权限矩阵、系统信息 |

---

## 4. 关键实现说明

### 4.1 数据库：先用 SQLite，切 MySQL 只换一层

需求方指定 MySQL 8.0，`docs/01` 第 10.2 节有完整 MySQL DDL；但本地没有数据库实例时无法跑通全链路，因此：

- `apps/server/src/db/schema.ts` 是把该 DDL **逐字段翻译**过来的 SQLite 版本
  （`ENUM` → `TEXT + CHECK`、`TINYINT` → `INTEGER`、`DECIMAL` → `REAL`）。
- `apps/server/src/db/index.ts` 定义了与驱动无关的 `Db` 接口（`exec/run/get/all/tx`）。
  接 MySQL 时只需实现一个 `MysqlDb` 并在 `createDb()` 里按 `DB_CLIENT` 分支，
  **业务模块一行都不用改**。
- 时间统一以 ISO 8601 UTC 字符串存储，字符串字典序 == 时间序，可直接用于范围查询与排序。
- SQLite 驱动用 Node 20.11+ 内置的 `node:sqlite`：**零原生依赖、零编译**。

### 4.2 幂等与去重（三条幂等键）

| 对象 | 幂等键 | 重复上报的行为 |
|---|---|---|
| 扫描批次 | `scanNo` | 返回原记录，`duplicated: true`，不报错、不新增 |
| 漏洞 | `fingerprint = sha256(projectId\|ruleId\|filePath\|snippetHash)` | 更新 `last_found_at` / `scan_id` / 命中次数，**保留人工处置过的状态** |
| 样本 | `(scanId, filePath, snippetHash)` | 跳过，`duplicated` 计数 +1 |

**复现（resurfaced）语义**：指纹已存在但原状态是终态（`fixed`/`ignored`/`false_positive`）时，
自动置回 `open` 并写入一条 `resurfaced` 事件 —— 既不静默刷掉"已修复"，也不埋掉真实回归。

`externalVulnId` 的关联是**批次内**解析的，所以必须**先上报漏洞再上报样本**（契约 Step 2 → Step 3）。

已 `complete` 的批次继续上报漏洞会返回 `40004`，这是契约明确要求的行为。

### 4.3 鉴权

| 调用方 | 方式 | 说明 |
|---|---|---|
| 扫描工具（机器） | `X-API-Key` | 只存 `sha256`；可吊销、可设过期、可限仓库白名单；仅能访问 `/ingest/**` |
| 平台前端（浏览器） | `Authorization: Bearer <JWT>` | 有效期 8h，登录后存 localStorage |

权限用 `ROLE_PERMISSIONS`（在 `packages/shared`）统一定义，**前后端共用同一份**，避免权限漂移。

### 4.4 模型检测（ScanMan 接入）

```
前端「模型检测」页
      │ POST /api/v1/ml/detect 或 /ml/analyze
      ▼
平台后端（ml 模块） ── HTTP ──▶ model-service (FastAPI + CodeBERT)
      │                          · 检测：safe / vulnerable + 概率
      │                          · 分类：CWE 预测 + Top-5
      ▼
/analyze 会写库：判定为漏洞 → 建漏洞记录 + 正样本；判定为安全 → 只沉淀负样本
```

- 平台后端是**唯一**的模型调用方，前端不直连模型（便于内网部署、统一鉴权与限流）。
- 模型服务不可用时按 `ML_FALLBACK` 处理：`fallback` 走启发式降级
  （响应 `degraded: true`，并在写入的漏洞描述里注明），`strict` 直接返回 503。
- 降级结果**绝不会**被伪装成模型输出。
- **逐任务来源**：模型服务于 `/predict` 返回 `tasks.detection` / `tasks.classification`，
  分别标明该任务是否由真实模型完成。原因是 `mode=auto` 下只要一个任务降级，
  整体就是 `degraded: true`；本机正好只有检测权重，于是「检测是真模型、分类是 mock」。
  前端据此对真模型的部分正常展示，只对降级的部分打「启发式 mock」标签 ——
  否则会把真模型判定的漏洞误当成 mock 丢掉。

### 4.5 演示数据是用真实 ingest 服务生成的

`seed.ts` 不手写 INSERT 拼数据，而是对每个扫描批次依次调用
`createScan → ingestVulnerabilities → ingestSamples → completeScan`，
**与扫描工具真实上报走同一条代码路径**。

好处：演示库里的指纹、去重、命中次数、状态流转、复现语义与生产完全一致，看板数字才可信；
这也顺带成了 ingest 服务的一次大规模自测（100+ 批次、140 漏洞、7500+ 样本）。

### 4.6 与契约文档的差异（只增不改）

| 位置 | 差异 | 原因 |
|---|---|---|
| `GET /api-keys` 的 `maskedKey` | 基于 `key_prefix` + hash 尾 4 位生成，如 `vuln_sk_9f3a****2e4c` | 平台只存 sha256，无法还原明文；掩码仍可区分不同 Key |
| `POST /ingest/scans/{scanNo}/complete` 重复调用 | 幂等返回当前统计，不报错 | 扫描侧重试安全 |
| 新增 `GET /ingest/limits` | 返回报文上限，供扫描侧自检 | 契约"只增字段"允许 |
| 新增 `GET /ml/**`、`GET /assignees` | 模型检测与指派下拉数据源 | 新增能力，不影响既有语义 |
| 新增 `POST /api-keys/{id}/restore` | 恢复被吊销的 Key | 管理便利性 |

---

## 5. 常用命令

```bash
pnpm dev                          # 同时起前后端（server:3000 / web:5173）
pnpm dev:server                   # 只起后端
pnpm dev:web                      # 只起前端
pnpm build                        # 全量构建（shared → server → web）
pnpm typecheck                    # 全量类型检查
pnpm test                         # 集成测试（自建临时库，59 用例）
pnpm -C apps/server db:reset      # 清库 + 重新灌演示数据
pnpm -C apps/server db:seed       # 仅灌演示数据（表为空时才写）
pnpm smoke                        # 端到端冒烟测试（需后端已启动）
pnpm -C apps/server build && pnpm -C apps/server start   # 生产模式启动后端
```

放大演示数据规模（便于压测列表分页与看板）：

```powershell
$env:SEED_SCALE = 3
pnpm -C apps/server db:reset
```

### 手动验证上报链路（curl）

```bash
KEY=vuln_sk_demo00000000000000000000000001
API=http://127.0.0.1:3000/api/v1
SCAN=gh-org-demo-$(date +%Y%m%d)-abc1234

# 自检
curl -H "X-API-Key: $KEY" $API/ingest/ping

# 1) 创建批次
curl -X POST $API/ingest/scans -H "Content-Type: application/json" -H "X-API-Key: $KEY" \
  -d "{\"scanNo\":\"$SCAN\",\"scan\":{\"repoType\":\"github\",\"repoUrl\":\"https://github.com/org/demo\",\"projectName\":\"demo\",\"branch\":\"main\"}}"

# 2) 上报漏洞
curl -X POST $API/ingest/scans/$SCAN/vulnerabilities \
  -H "Content-Type: application/json" -H "X-API-Key: $KEY" \
  -d '{"vulnerabilities":[{"externalVulnId":"VULN-0001","ruleId":"sql-injection-java","ruleName":"SQL注入","title":"用户输入未过滤直接拼接进 SQL","severity":"high","cwe":"CWE-89","language":"java","filePath":"src/UserDao.java","lineStart":42,"lineEnd":45,"codeSnippet":"String sql = \"SELECT * FROM users WHERE name = \x27\" + name + \"\x27\";","suggestion":"使用 PreparedStatement"}]}'

# 3) 上报正负样本（必须先做完第 2 步）
curl -X POST $API/ingest/scans/$SCAN/samples \
  -H "Content-Type: application/json" -H "X-API-Key: $KEY" \
  -d '{"samples":[{"label":"positive","filePath":"src/UserDao.java","externalVulnId":"VULN-0001","snippet":"String sql = ..."},{"label":"negative","filePath":"src/UserService.java","snippet":"public class UserService {}"}]}'

# 4) 结束批次
curl -X POST $API/ingest/scans/$SCAN/complete \
  -H "Content-Type: application/json" -H "X-API-Key: $KEY" \
  -d '{"status":"success","scannedFiles":1275}'
```

---

## 6. 文档索引

| 文档 | 说明 |
|---|---|
| [`docs/01-需求与开发文档.md`](docs/01-需求与开发文档.md) | 需求、架构、技术选型、数据库设计、页面设计、开发计划 |
| [`docs/02-API接口文档.md`](docs/02-API接口文档.md) | **★ API 契约**：上报协议、查询接口、错误码、集成示例 |
| [`docs/openapi.yaml`](docs/openapi.yaml) | OpenAPI 3.0 机器可读契约 |
| [`model-service/README.md`](model-service/README.md) | ScanMan 模型推理服务的接口与部署 |
| [`README.md`](README.md) | ScanMan BERT 微调全流程（模型侧，与本平台配套） |
| [`README1.md`](README1.md) | 本平台最初的需求备忘与契约冻结流程 |

---

## 7. 部署到生产前必做

- [ ] 修改 `JWT_SECRET`（生产环境沿用默认值会**直接启动失败**，这是有意的保护）
- [ ] 修改默认管理员密码 `admin / Admin@12345`
- [ ] 吊销演示用 API Key `vuln_sk_demo...`，为每个 CI 环境单独创建
- [ ] 按需切换 MySQL：实现 `Db` 接口的 MySQL 适配器并设 `DB_CLIENT=mysql`
- [ ] 用 Nginx 托管 `apps/web/dist` 静态资源并反代 `/api`
- [ ] 确认 `CORS_ORIGIN` 只包含正式域名
- [ ] 配置数据库每日备份（保留 30 天）与日志采集

---

## 8. 已知限制

1. **数据库默认为 SQLite**：适合单机与联调；生产多实例需切 MySQL（适配层已预留）。
2. **限流为单进程内存实现**：多实例部署需换 Redis（逻辑已隔离在 `apps/server/src/core/rateLimit.ts`）。
3. **`running` 批次的定时回收未实现**：契约提到"每小时把超 2 小时仍 running 的批次标记为 partial"，
   当前只在演示数据里造了这种状态，定时任务待补（P1）。
4. **Webhook / 告警 / 审计日志**为 P2，未实现（`audit_logs` 表已建好）。
5. **样本分月归档未实现**：样本表历史数据量增长后需补归档策略（P1）。
