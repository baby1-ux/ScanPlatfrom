# 漏洞管理平台（Vulnerability Management Platform）

简易的漏洞管理平台：接收扫描工具上报的**漏洞信息**与**正负样本**，入库 MySQL，提供登录、看板、漏洞查询与处置界面。

**技术栈**：Node.js + React + Ant Design + MySQL

---

## 文档索引

| 文档 | 说明 |
|---|---|
| [`docs/01-需求与开发文档.md`](docs/01-需求与开发文档.md) | 需求总结、架构、技术选型、数据库设计、页面设计、开发计划 |
| [`docs/02-API接口文档.md`](docs/02-API接口文档.md) | **★ API 契约**（优先评审冻结），含上报协议、查询接口、错误码、集成示例 |
| [`docs/openapi.yaml`](docs/openapi.yaml) | OpenAPI 3.0 机器可读契约，可直接起 Mock Server |

---

## 一句话说清流程

```
代码提交 → 扫描工具扫描 → 上报漏洞+正负样本到平台 API → 入库 MySQL → 登录平台查看
```

## 核心约定

- **扫描工具**用 `X-API-Key` 调 `/api/v1/ingest/**` 上报，调用链 4 步：
  1. `POST /ingest/scans` — 创建批次（`scanNo` 幂等）
  2. `POST /ingest/scans/{scanNo}/vulnerabilities` — 上报漏洞
  3. `POST /ingest/scans/{scanNo}/samples` — 上报正负样本
  4. `POST /ingest/scans/{scanNo}/complete` — 结束批次
- **平台前端**用 JWT 调查询/处置接口。
- 统一响应：`{ code, message, data, traceId }`，`code = 0` 为成功。
- 契约兼容策略：**只增字段，不删不改语义**。

## 起 Mock Server（前期联调，无需数据库）

```bash
npx @stoplight/prism-cli mock docs/openapi.yaml --port 4010
# 然后访问 http://localhost:4010/api/v1/ingest/ping
```

## 目录规划

```
漏洞管理平台/
├── docs/                  # 文档（当前唯一已有内容）
├── apps/server/           # Node.js 后端（待开发）
├── apps/web/              # React + AntD 前端（待开发）
├── packages/shared/       # 前后端共享类型（待开发）
├── docker-compose.yml     # 待开发
└── README.md
```

## 当前状态

- [x] 需求梳理
- [x] 数据库设计
- [x] API 契约文档 + OpenAPI
- [ ] **扫描侧评审并冻结 API v1.0** ← 卡在这里，需要双方确认
- [ ] Mock Server
- [ ] 后端开发
- [ ] 前端开发
- [ ] 联调验收

## 下一步

1. 把 `docs/02-API接口文档.md` 发给扫描侧（国庆团队）。
2. 请对方填写**附录 A：字段能力确认表**，回答**附录 B 的 7 个问题**。
3. 开会 30 分钟逐条过字段，冻结 v1.0。
4. 平台侧起 Mock Server，双方并行开发。
