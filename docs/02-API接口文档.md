# 漏洞管理平台 — API 接口文档

> 版本：**v1.0（待双方评审冻结）**
> Base URL：`http://<host>:3000/api/v1`（生产经 Nginx 后为 `https://<domain>/api/v1`）
> 关联文档：[`01-需求与开发文档.md`](./01-需求与开发文档.md)、[`openapi.yaml`](./openapi.yaml)

---

## 目录

1. [通用约定](#1-通用约定)
2. [数据字典（枚举与对象）](#2-数据字典)
3. [认证接口（平台前端用）](#3-认证接口)
4. [API Key 管理（管理员用）](#4-api-key-管理)
5. [扫描结果上报接口（扫描工具用）★核心](#5-扫描结果上报接口)
6. [漏洞查询与处置接口](#6-漏洞查询与处置接口)
7. [项目 / 扫描批次 / 样本接口](#7-项目--扫描批次--样本接口)
8. [统计接口](#8-统计接口)
9. [Webhook 接口（可选 P1）](#9-webhook-接口可选)
10. [错误码全表](#10-错误码全表)
11. [联调约定与 Mock](#11-联调约定与-mock)

---

## 1. 通用约定

### 1.1 协议与编码

| 项 | 约定 |
|---|---|
| 协议 | HTTP/1.1，生产强制 HTTPS |
| 编码 | UTF-8 |
| 请求体 | `application/json; charset=utf-8` |
| 响应体 | `application/json; charset=utf-8` |
| 压缩 | 上报接口支持 `Content-Encoding: gzip` |
| 时间格式 | ISO 8601 UTC，形如 `2025-01-01T10:00:00Z`；只到日期用 `2025-01-01` |
| 字段命名 | 小驼峰 `camelCase` |
| 版本 | 路径带版本号 `/api/v1`；破坏性变更升 `/api/v2` |
| 兼容策略 | **只增字段，不删不改语义**；新增字段客户端必须能忽略 |
| TraceId | 请求可带 `X-Trace-Id`，服务端响应头回传，便于排查 |

### 1.2 统一响应格式

**成功：**

```json
{
  "code": 0,
  "message": "success",
  "data": { },
  "traceId": "a1b2c3d4e5f6"
}
```

**失败：**

```json
{
  "code": 40001,
  "message": "参数校验失败",
  "data": {
    "errors": [
      { "field": "vulnerabilities[0].severity", "message": "必须是 critical/high/medium/low/info 之一" }
    ]
  },
  "traceId": "a1b2c3d4e5f6"
}
```

> `code = 0` 表示业务成功；非 0 见[第 10 章](#10-错误码全表)。
> HTTP 状态码同时具有语义（400/401/403/404/429/500），**扫描侧建议先判 HTTP 状态码，再判 `code`**。

### 1.3 鉴权方式

平台有两类调用方，鉴权方式不同：

| 调用方 | 方式 | 请求头 | 有效期 |
|---|---|---|---|
| 扫描工具（机器） | API Key | `X-API-Key: vuln_sk_xxxxxxxxxxxxxxxx` | 长期（可设过期时间，可吊销） |
| 平台前端（浏览器） | JWT | `Authorization: Bearer <accessToken>` | 8 小时 |

**哪些接口用哪种：**

- `/ingest/**` → 只接受 API Key
- `/auth/login` → 无需鉴权
- 其余所有接口 → 只接受 JWT

**鉴权失败响应：**

```json
{ "code": 40101, "message": "API Key 无效或已被吊销", "data": null }
```

### 1.4 分页约定

请求参数：

| 参数 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `page` | int | 1 | 页码，从 1 开始 |
| `pageSize` | int | 20 | 每页条数，最大 200 |
| `sortBy` | string | `lastFoundAt` | 排序字段 |
| `sortOrder` | string | `desc` | `asc` / `desc` |

响应结构：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "list": [],
    "pagination": { "page": 1, "pageSize": 20, "total": 137, "totalPages": 7 }
  }
}
```

### 1.5 幂等与重试

| 接口 | 幂等键 | 行为 |
|---|---|---|
| `POST /ingest/scans` | `scanNo` | 已存在则返回原记录，`duplicated: true`，不报错 |
| `POST /ingest/scans/{scanNo}/vulnerabilities` | `fingerprint` | 已存在则更新 `lastFoundAt`，不新增 |
| `POST /ingest/scans/{scanNo}/samples` | `(scanId, filePath, snippetHash)` | 已存在则跳过 |

**扫描侧重试策略建议**：网络超时/5xx 时，间隔 1s / 3s / 9s 重试 3 次；4xx 不重试（除 429 按 `Retry-After` 退避）。

### 1.6 限流

| 范围 | 限制 | 超限响应 |
|---|---|---|
| 上报接口（按 API Key） | 50 次/秒 | HTTP 429，`code: 42900`，带 `Retry-After` 头 |
| 登录接口（按 IP） | 10 次/分钟 | HTTP 429，`code: 42902` |
| 其他接口（按用户） | 200 次/秒 | HTTP 429，`code: 42900` |

### 1.7 请求体大小限制

| 项 | 限制 |
|---|---|
| 单次请求体（gzip 前） | 5 MB |
| 单批数组元素数 | 500（漏洞 / 样本同理） |
| 单条 `codeSnippet` / `snippet` | 64 KB（超出请截断，平台不做报错，只记录警告） |

超限响应：HTTP 413 → `{ "code": 41300, "message": "请求体过大，请使用分片上报接口" }`

---

## 2. 数据字典

### 2.1 枚举值

**severity（漏洞等级）**

| 值 | 含义 |
|---|---|
| `critical` | 严重 |
| `high` | 高危 |
| `medium` | 中危 |
| `low` | 低危 |
| `info` | 提示 |

**vulnStatus（漏洞状态）**

| 值 | 含义 | 是否终态 |
|---|---|---|
| `open` | 待处理（默认） | 否 |
| `confirmed` | 已确认 | 否 |
| `fixing` | 修复中 | 否 |
| `fixed` | 已修复 | 是 |
| `ignored` | 已忽略（接受风险） | 是 |
| `false_positive` | 误报 | 是 |

**repoType（仓库类型）**：`github` / `gitlab` / `gitee` / `bitbucket` / `other`

**triggerType（触发方式）**：`push` / `merge_request` / `manual` / `schedule` / `webhook`

**scanStatus（扫描批次状态）**：`running` / `success` / `failed` / `partial`

**sampleLabel（样本标签）**：`positive`（有漏洞，正样本）/ `negative`（无漏洞，负样本）

### 2.2 漏洞去重指纹算法（双方必须一致）

```
snippetHash = sha256( 规范化后的代码片段 )
fingerprint = sha256( projectId + "|" + ruleId + "|" + filePath + "|" + snippetHash )

规范化规则：
  1. 去除首尾空白
  2. 统一换行符为 \n
  3. 将连续空白字符折叠为单个空格
  4. 全部转小写
```

> **注意**：`projectId` 由平台在注册项目时分配，扫描侧只需上报 `repoUrl` + `repoType`，平台自行映射。
> 指纹由**平台计算**，扫描侧不需要计算 `fingerprint`；但**扫描侧必须保证 `ruleId` 稳定**（同一规则的 ID 不能在不同版本间变化），否则同一漏洞会被判为两条。

### 2.3 核心对象

**ScanObject（仓库/提交信息）**

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `repoType` | string | 是 | 见 `repoType` 枚举 |
| `repoUrl` | string | 是 | 仓库地址，平台以其唯一标识项目 |
| `repoFullName` | string | 否 | `org/repo`，如 `alibaba/demo` |
| `projectName` | string | 否 | 项目展示名，首次上报时用于创建项目；后续上报忽略 |
| `branch` | string | 否 | 分支名 |
| `commitId` | string | 否 | 提交 SHA（建议传，便于溯源） |
| `commitMessage` | string | 否 | 提交信息（建议截断 ≤ 512 字符） |
| `commitAuthor` | string | 否 | 提交人 |
| `commitTime` | string | 否 | ISO 8601 UTC |

**VulnerabilityItem（漏洞项）**

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `externalVulnId` | string | 否 | 扫描工具内的漏洞 ID，便于双向对账 |
| `ruleId` | string | **是** | 规则 ID，参与指纹计算，**必须稳定** |
| `ruleName` | string | 否 | 规则名，如 `SQL注入` |
| `title` | string | **是** | 漏洞标题（≤ 512 字符） |
| `severity` | string | **是** | 见 `severity` 枚举 |
| `category` | string | 否 | 分类，如 `injection` / `xss` / `deserialization` |
| `cwe` | string | 否 | 如 `CWE-89` |
| `cve` | string | 否 | 如 `CVE-2024-1234` |
| `language` | string | 否 | 如 `javascript` / `java` / `python` |
| `filePath` | string | **是** | **仓库相对路径**，统一用 `/` 分隔，不带前导 `/` |
| `lineStart` | int | 否 | 起始行号（从 1 开始） |
| `lineEnd` | int | 否 | 结束行号 |
| `codeSnippet` | string | 否 | 命中的代码片段（≤ 64KB） |
| `description` | string | 否 | 漏洞描述 |
| `suggestion` | string | 否 | 修复建议 |
| `confidence` | number | 否 | 置信度，0~1，保留 3 位小数 |

**SampleItem（样本项）**

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `externalSampleId` | string | 否 | 扫描工具内的样本 ID |
| `label` | string | **是** | `positive`（有漏洞）/ `negative`（无漏洞） |
| `filePath` | string | **是** | 仓库相对路径 |
| `language` | string | 否 | 语言 |
| `lineStart` | int | 否 | 起始行 |
| `lineEnd` | int | 否 | 结束行 |
| `snippet` | string | 否 | 代码片段（≤ 64KB） |
| `snippetHash` | string | 否 | 片段 sha256；不传由平台计算。**强烈建议扫描侧计算并提供**，可显著加快去重 |
| `fileHash` | string | 否 | 整文件 sha256 |
| `externalVulnId` | string | 否 | 正样本关联的漏洞（对应 `VulnerabilityItem.externalVulnId`）；负样本留空 |

---

## 3. 认证接口

平台前端使用。**鉴权：无（login）/ JWT（其余）**

### 3.1 登录

`POST /api/v1/auth/login`

**请求体**

```json
{
  "username": "admin",
  "password": "Admin@12345"
}
```

**响应 200**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9....",
    "tokenType": "Bearer",
    "expiresIn": 28800,
    "user": {
      "id": 1,
      "username": "admin",
      "displayName": "系统管理员",
      "email": "admin@example.com",
      "role": "admin",
      "lastLoginAt": "2025-01-01T09:00:00Z"
    }
  }
}
```

**失败**

| HTTP | code | 场景 |
|---|---|---|
| 401 | 40100 | 用户名或密码错误（**不区分提示，防账号枚举**） |
| 403 | 40301 | 账号已被禁用 |
| 429 | 42902 | 登录尝试过于频繁 |

### 3.2 获取当前用户

`GET /api/v1/auth/me` — 鉴权：JWT

**响应 200**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": 1,
    "username": "admin",
    "displayName": "系统管理员",
    "email": "admin@example.com",
    "role": "admin",
    "permissions": ["vuln:read", "vuln:write", "user:manage", "apikey:manage", "export"]
  }
}
```

### 3.3 登出

`POST /api/v1/auth/logout` — 鉴权：JWT

```json
{ "code": 0, "message": "success", "data": null }
```

> 前端清理本地 token 即可；若启用 redis 黑名单，服务端同时失效该 token。

### 3.4 修改密码

`POST /api/v1/auth/change-password` — 鉴权：JWT

**请求体**

```json
{ "oldPassword": "Admin@12345", "newPassword": "NewPwd@67890" }
```

**规则**：新密码 ≥ 8 位，且至少包含大写、小写、数字、特殊字符中的 3 类。

**失败**：`40002` 旧密码不正确；`40003` 新密码强度不足。

---

## 4. API Key 管理

平台管理员使用。**鉴权：JWT，且角色必须是 `admin`**

### 4.1 创建 API Key

`POST /api/v1/api-keys`

**请求体**

```json
{
  "name": "github-actions-prod",
  "scopes": ["ingest"],
  "repoScope": ["https://github.com/org/repo-a"],
  "expiresAt": null
}
```

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `name` | string | 是 | 用途备注 |
| `scopes` | string[] | 否 | 默认 `["ingest"]` |
| `repoScope` | string[] | 否 | 允许上报的仓库白名单；`null`/空 = 不限 |
| `expiresAt` | string | 否 | ISO 8601；`null` = 永不过期 |

**响应 201**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": 3,
    "name": "github-actions-prod",
    "apiKey": "vuln_sk_9f3a1c7e4b2d8f6a5e0c3b7d1a9f2e4c",
    "keyPrefix": "vuln_sk_",
    "scopes": ["ingest"],
    "repoScope": ["https://github.com/org/repo-a"],
    "expiresAt": null,
    "createdAt": "2025-01-01T10:00:00Z"
  }
}
```

> ⚠️ **`apiKey` 明文只在创建时返回一次**，平台仅存 `sha256(apiKey)`，之后无法找回。前端必须弹窗提示并提供一键复制。

### 4.2 查询 API Key 列表

`GET /api/v1/api-keys?page=1&pageSize=20&status=1`

**响应 200**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "list": [
      {
        "id": 3,
        "name": "github-actions-prod",
        "keyPrefix": "vuln_sk_",
        "maskedKey": "vuln_sk_9f3a****2e4c",
        "scopes": ["ingest"],
        "repoScope": ["https://github.com/org/repo-a"],
        "status": 1,
        "expiresAt": null,
        "lastUsedAt": "2025-01-01T12:30:00Z",
        "createdAt": "2025-01-01T10:00:00Z"
      }
    ],
    "pagination": { "page": 1, "pageSize": 20, "total": 1, "totalPages": 1 }
  }
}
```

### 4.3 吊销 API Key

`DELETE /api/v1/api-keys/{id}`

```json
{ "code": 0, "message": "success", "data": { "id": 3, "status": 0 } }
```

> 吊销后立即生效，扫描侧再次调用返回 `40101`。

### 4.4 验证 API Key 有效性（扫描侧自检用）

`GET /api/v1/ingest/ping` — **鉴权：API Key**

**响应 200**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "valid": true,
    "keyName": "github-actions-prod",
    "scopes": ["ingest"],
    "serverTime": "2025-01-01T10:00:00Z",
    "apiVersion": "v1"
  }
}
```

> 建议扫描工具在正式上报前先调用一次，快速定位 Key 配置问题。

---

## 5. 扫描结果上报接口

> ★ **本章是双方联调的核心契约，优先评审冻结。**

**鉴权：全部使用 `X-API-Key`**

提供两种上报模式：

| 模式 | 适用场景 | 接口数 |
|---|---|---|
| **A. 分片上报（推荐）** | 生产环境，样本量大 | 4 个接口，顺序调用 |
| **B. 一次性全量上报** | 小仓库、本地调试 | 1 个接口 |

---

### 5.1 模式 A：分片上报

#### Step 1 — 创建扫描批次

`POST /api/v1/ingest/scans`

**请求体**

```json
{
  "scanNo": "gh-org-demo-20250101-abc1234",
  "scanner": {
    "name": "vuln-scanner",
    "version": "1.2.0"
  },
  "triggerType": "push",
  "scan": {
    "repoType": "github",
    "repoUrl": "https://github.com/org/demo",
    "repoFullName": "org/demo",
    "projectName": "demo",
    "branch": "main",
    "commitId": "abc1234567890abcdef1234567890abcdef12345",
    "commitMessage": "fix: 修复登录逻辑",
    "commitAuthor": "zhangsan",
    "commitTime": "2025-01-01T09:55:00Z"
  },
  "startedAt": "2025-01-01T09:58:00Z",
  "totalFiles": 1280
}
```

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `scanNo` | string | **是** | 扫描批次号，**全局唯一**，幂等键。建议规则：`{repoType}-{repoFullName}-{yyyymmdd}-{commitId前7位}` |
| `scanner` | object | 否 | `{ name, version }` |
| `triggerType` | string | 否 | 默认 `push` |
| `scan` | object | **是** | 见 [ScanObject](#23-核心对象) |
| `startedAt` | string | 否 | 扫描开始时间 |
| `totalFiles` | int | 否 | 本次待扫描文件总数 |

**响应 201（首次创建）**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "scanId": 1024,
    "scanNo": "gh-org-demo-20250101-abc1234",
    "projectId": 17,
    "projectCreated": true,
    "status": "running",
    "duplicated": false,
    "createdAt": "2025-01-01T10:00:00Z"
  }
}
```

**响应 200（重复上报，幂等）**

```json
{
  "code": 0,
  "message": "扫描批次已存在，返回原记录",
  "data": {
    "scanId": 1024,
    "scanNo": "gh-org-demo-20250101-abc1234",
    "projectId": 17,
    "projectCreated": false,
    "status": "running",
    "duplicated": true,
    "createdAt": "2025-01-01T10:00:00Z"
  }
}
```

> **项目自动创建**：平台以 `(repoType, repoUrl)` 唯一匹配项目，不存在则自动创建。`projectCreated=true` 表示本次新建。

---

#### Step 2 — 批量上报漏洞

`POST /api/v1/ingest/scans/{scanNo}/vulnerabilities`

**请求体**

```json
{
  "vulnerabilities": [
    {
      "externalVulnId": "VULN-0001",
      "ruleId": "sql-injection-java",
      "ruleName": "SQL注入",
      "title": "用户输入未过滤直接拼接进 SQL 语句",
      "severity": "high",
      "category": "injection",
      "cwe": "CWE-89",
      "cve": null,
      "language": "java",
      "filePath": "src/main/java/com/demo/UserDao.java",
      "lineStart": 42,
      "lineEnd": 45,
      "codeSnippet": "String sql = \"SELECT * FROM users WHERE name = '\" + name + \"'\";",
      "description": "name 参数来源于 HTTP 请求且未做校验，攻击者可构造恶意输入执行任意 SQL。",
      "suggestion": "使用 PreparedStatement 参数化查询。",
      "confidence": 0.95
    }
  ]
}
```

- 数组元素 **1 ≤ N ≤ 500**
- `severity` / `ruleId` / `title` / `filePath` 为必填，缺失返回 `40001`

**响应 200**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "received": 1,
    "created": 1,
    "updated": 0,
    "skipped": 0,
    "details": [
      {
        "externalVulnId": "VULN-0001",
        "vulnId": 88301,
        "vulnNo": "VUL-20250101-0001",
        "fingerprint": "3f2a...9c1b",
        "result": "created"
      }
    ]
  }
}
```

| `result` 值 | 含义 |
|---|---|
| `created` | 新漏洞，已入库 |
| `updated` | 指纹已存在（同一漏洞再次命中），已更新 `lastFoundAt` / `scanId`，**保留原状态与指派人** |
| `resurfaced` | 指纹已存在但原状态为 `fixed`/`ignored`，本轮重新出现 → 自动置回 `open` 并记录事件 |
| `skipped` | 校验不通过（如缺少 `ruleId`），已跳过，详见 `skippedItems` |

**响应含跳过项时：**

```json
{
  "code": 0,
  "message": "部分数据被跳过",
  "data": {
    "received": 3,
    "created": 2,
    "updated": 0,
    "skipped": 1,
    "skippedItems": [
      { "index": 2, "externalVulnId": "VULN-0003", "reason": "缺少必填字段 ruleId" }
    ]
  }
}
```

> `skipped` 不会导致整个请求失败（部分成功语义）。若**全部**被跳过，返回 HTTP 400 + `code: 40001`。

---

#### Step 3 — 批量上报正负样本

`POST /api/v1/ingest/scans/{scanNo}/samples`

**请求体**

```json
{
  "samples": [
    {
      "externalSampleId": "S-0001",
      "label": "positive",
      "filePath": "src/main/java/com/demo/UserDao.java",
      "language": "java",
      "lineStart": 42,
      "lineEnd": 45,
      "snippet": "String sql = \"SELECT * FROM users WHERE name = '\" + name + \"'\";",
      "snippetHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "fileHash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "externalVulnId": "VULN-0001"
    },
    {
      "externalSampleId": "S-0002",
      "label": "negative",
      "filePath": "src/main/java/com/demo/UserService.java",
      "language": "java",
      "lineStart": 1,
      "lineEnd": 60,
      "snippet": "public class UserService { ... }",
      "fileHash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    }
  ]
}
```

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `samples[].label` | string | **是** | `positive` = 有漏洞（正样本）；`negative` = 无漏洞（负样本） |
| `samples[].filePath` | string | **是** | 仓库相对路径 |
| `samples[].snippet` | string | 否 | 代码片段；超 64KB 平台自动截断并记录警告 |
| `samples[].snippetHash` | string | 否 | 片段 sha256（64 位小写十六进制）；不传平台自行计算 |
| `samples[].externalVulnId` | string | 否 | 仅正样本需要，关联 Step 2 上报的漏洞 |

> **重要**：`externalVulnId` 的关联是**批次内**解析的 —— 平台在本批次已入库的漏洞中查找匹配的 `externalVulnId`。因此**必须先调 Step 2 再调 Step 3**。

**响应 200**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "received": 2,
    "created": 2,
    "duplicated": 0,
    "truncated": 0,
    "positiveCount": 1,
    "negativeCount": 1
  }
}
```

---

#### Step 4 — 结束扫描批次

`POST /api/v1/ingest/scans/{scanNo}/complete`

**请求体**

```json
{
  "status": "success",
  "finishedAt": "2025-01-01T10:02:30Z",
  "totalFiles": 1280,
  "scannedFiles": 1275,
  "errorMessage": null
}
```

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `status` | string | **是** | `success` / `failed` / `partial` |
| `finishedAt` | string | 否 | 结束时间，默认当前时间 |
| `totalFiles` | int | 否 | 待扫描文件总数 |
| `scannedFiles` | int | 否 | 实际扫描文件数（可用于算覆盖率） |
| `errorMessage` | string | 否 | `status=failed` 时的失败原因 |

**响应 200**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "scanId": 1024,
    "scanNo": "gh-org-demo-20250101-abc1234",
    "status": "success",
    "vulnCount": 12,
    "sampleCount": 1280,
    "positiveCount": 12,
    "negativeCount": 1268,
    "durationMs": 270000
  }
}
```

> **调用或不调用都可**。若扫描工具中途崩溃没调这个接口，平台会用**定时任务**（每小时）把超过 2 小时仍为 `running` 的批次标记为 `partial`，因此不会永久挂起。**但强烈建议调用**，否则批次状态与统计数字不准确。

---

### 5.2 模式 B：一次性全量上报

`POST /api/v1/ingest/report`

适合小仓库或本地调试：一次请求把 Step 1~4 的内容全部带上，服务端在一个事务里完成。

**请求体**

```json
{
  "scanNo": "gh-org-demo-20250101-abc1234",
  "scanner": { "name": "vuln-scanner", "version": "1.2.0" },
  "triggerType": "push",
  "scan": {
    "repoType": "github",
    "repoUrl": "https://github.com/org/demo",
    "repoFullName": "org/demo",
    "projectName": "demo",
    "branch": "main",
    "commitId": "abc1234567890abcdef1234567890abcdef12345",
    "commitMessage": "fix: 修复登录逻辑",
    "commitAuthor": "zhangsan",
    "commitTime": "2025-01-01T09:55:00Z"
  },
  "startedAt": "2025-01-01T09:58:00Z",
  "finishedAt": "2025-01-01T10:02:30Z",
  "status": "success",
  "totalFiles": 1280,
  "scannedFiles": 1275,
  "vulnerabilities": [
    {
      "externalVulnId": "VULN-0001",
      "ruleId": "sql-injection-java",
      "title": "SQL注入",
      "severity": "high",
      "filePath": "src/main/java/com/demo/UserDao.java",
      "lineStart": 42,
      "lineEnd": 45,
      "codeSnippet": "String sql = \"...\" + name;",
      "suggestion": "使用 PreparedStatement"
    }
  ],
  "samples": [
    {
      "label": "positive",
      "filePath": "src/main/java/com/demo/UserDao.java",
      "snippet": "String sql = \"...\" + name;",
      "externalVulnId": "VULN-0001"
    },
    {
      "label": "negative",
      "filePath": "src/main/java/com/demo/UserService.java",
      "snippet": "public class UserService { }"
    }
  ]
}
```

> **限制**：`vulnerabilities` 与 `samples` 各 ≤ 500 条。超出请改用模式 A。整个请求 ≤ 5MB。

**响应 201**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "scanId": 1024,
    "scanNo": "gh-org-demo-20250101-abc1234",
    "projectId": 17,
    "projectCreated": true,
    "duplicated": false,
    "result": {
      "vulnReceived": 1,
      "vulnCreated": 1,
      "vulnUpdated": 0,
      "vulnSkipped": 0,
      "sampleReceived": 2,
      "sampleCreated": 2,
      "sampleDuplicated": 0,
      "positiveCount": 1,
      "negativeCount": 1
    }
  }
}
```

---

### 5.3 扫描侧集成示例

**GitHub Actions（Bash + curl）**

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run scanner
        run: |
          ./scanner --output report.json --samples samples.json

      - name: Upload to vuln platform
        env:
          VULN_API: https://vuln.example.com/api/v1
          VULN_KEY: ${{ secrets.VULN_API_KEY }}
          SCAN_NO: "gh-${{ github.repository }}-$(date +%Y%m%d)-${{ github.sha }}"
        run: |
          set -e
          COMMON=(-sS -H "Content-Type: application/json" -H "X-API-Key: $VULN_KEY")

          # Step 1 创建批次
          curl "${COMMON[@]}" -X POST "$VULN_API/ingest/scans" -d @- <<EOF
          {
            "scanNo": "${SCAN_NO}",
            "scanner": { "name": "vuln-scanner", "version": "1.2.0" },
            "triggerType": "push",
            "scan": {
              "repoType": "github",
              "repoUrl": "${{ github.server_url }}/${{ github.repository }}",
              "repoFullName": "${{ github.repository }}",
              "branch": "${{ github.ref_name }}",
              "commitId": "${{ github.sha }}",
              "commitMessage": "${{ github.event.head_commit.message }}",
              "commitAuthor": "${{ github.actor }}"
            }
          }
          EOF

          # Step 2 上报漏洞
          curl "${COMMON[@]}" -X POST "$VULN_API/ingest/scans/${SCAN_NO}/vulnerabilities" \
               --data-binary @vulns.json

          # Step 3 上报正负样本
          curl "${COMMON[@]}" -X POST "$VULN_API/ingest/scans/${SCAN_NO}/samples" \
               --data-binary @samples.json

          # Step 4 结束批次
          curl "${COMMON[@]}" -X POST "$VULN_API/ingest/scans/${SCAN_NO}/complete" \
               -d '{"status":"success","scannedFiles":1275}'
```

> ⚠️ `scanNo` 中若含 `/`（如 `org/demo`）会污染 URL 路径，**必须 URL 编码**或改用 `-` 分隔。建议扫描侧统一用 `-`。

**Node.js（fetch）**

```js
const API = process.env.VULN_API;
const KEY = process.env.VULN_API_KEY;
const scanNo = `gh-org-demo-20250101-abc1234`;

async function post(path, body) {
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-API-Key': KEY },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  if (json.code !== 0) throw new Error(`[${json.code}] ${json.message}`);
  return json.data;
}

async function report(report) {
  await post('/ingest/scans', { scanNo, scanner: report.scanner, scan: report.scan });
  if (report.vulnerabilities.length) {
    await post(`/ingest/scans/${scanNo}/vulnerabilities`, { vulnerabilities: report.vulnerabilities });
  }
  if (report.samples.length) {
    await post(`/ingest/scans/${scanNo}/samples`, { samples: report.samples });
  }
  return post(`/ingest/scans/${scanNo}/complete`, {
    status: 'success',
    scannedFiles: report.scannedFiles,
  });
}
```

---

## 6. 漏洞查询与处置接口

**鉴权：JWT**

### 6.1 漏洞列表

`GET /api/v1/vulnerabilities`

**查询参数**

| 参数 | 类型 | 说明 |
|---|---|---|
| `page` | int | 页码，默认 1 |
| `pageSize` | int | 每页条数，默认 20，最大 200 |
| `projectId` | int / int[] | 项目 ID，可多选（`projectId=1,2,3`） |
| `repoType` | string | 仓库类型 |
| `severity` | string / string[] | 漏洞等级，可多选：`severity=critical,high` |
| `status` | string / string[] | 漏洞状态，可多选 |
| `ruleId` | string | 规则 ID |
| `category` | string | 漏洞分类 |
| `cwe` | string | CWE 编号 |
| `language` | string | 语言 |
| `filePath` | string | 文件路径模糊匹配 |
| `keyword` | string | 关键词，匹配 `title` / `ruleName` / `filePath` 的模糊搜索 |
| `assignee` | int | 指派人 ID |
| `branch` | string | 分支 |
| `startTime` | string | 按 `lastFoundAt` 起始（ISO 8601） |
| `endTime` | string | 按 `lastFoundAt` 结束（ISO 8601） |
| `sortBy` | string | `lastFoundAt`(默认) / `severity` / `firstFoundAt` / `status` / `projectId` |
| `sortOrder` | string | `desc`(默认) / `asc` |

**响应 200**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "list": [
      {
        "id": 88301,
        "vulnNo": "VUL-20250101-0001",
        "title": "用户输入未过滤直接拼接进 SQL 语句",
        "severity": "high",
        "status": "open",
        "category": "injection",
        "cwe": "CWE-89",
        "cve": null,
        "language": "java",
        "ruleId": "sql-injection-java",
        "ruleName": "SQL注入",
        "project": { "id": 17, "name": "demo", "repoType": "github", "repoUrl": "https://github.com/org/demo" },
        "filePath": "src/main/java/com/demo/UserDao.java",
        "lineStart": 42,
        "lineEnd": 45,
        "assignee": null,
        "confidence": 0.95,
        "firstFoundAt": "2025-01-01T10:00:00Z",
        "lastFoundAt": "2025-01-01T10:00:00Z",
        "occurrenceCount": 3,
        "createdAt": "2025-01-01T10:00:00Z"
      }
    ],
    "pagination": { "page": 1, "pageSize": 20, "total": 137, "totalPages": 7 },
    "summary": {
      "critical": 2,
      "high": 35,
      "medium": 60,
      "low": 30,
      "info": 10
    }
  }
}
```

> `summary` 字段返回**当前筛选条件下的**各等级数量，方便前端在表格上方渲染徽标。列表接口**不返回** `codeSnippet` / `description`（体积大），需要时调详情接口。

### 6.2 漏洞详情

`GET /api/v1/vulnerabilities/{id}`

**响应 200**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": 88301,
    "vulnNo": "VUL-20250101-0001",
    "fingerprint": "3f2a...9c1b",
    "title": "用户输入未过滤直接拼接进 SQL 语句",
    "severity": "high",
    "status": "open",
    "category": "injection",
    "cwe": "CWE-89",
    "cve": null,
    "language": "java",
    "ruleId": "sql-injection-java",
    "ruleName": "SQL注入",
    "description": "name 参数来源于 HTTP 请求且未做校验……",
    "suggestion": "使用 PreparedStatement 参数化查询。",
    "confidence": 0.95,
    "remark": null,
    "project": { "id": 17, "name": "demo", "repoType": "github", "repoUrl": "https://github.com/org/demo" },
    "location": {
      "filePath": "src/main/java/com/demo/UserDao.java",
      "lineStart": 42,
      "lineEnd": 45,
      "codeSnippet": "public List<User> find(String name) {\n  String sql = \"SELECT * FROM users WHERE name = '\" + name + \"'\";\n  return jdbc.query(sql);\n}",
      "codeSnippetOffset": 40
    },
    "assignee": { "id": 5, "username": "lisi", "displayName": "李四" },
    "latestScan": {
      "scanId": 1024,
      "scanNo": "gh-org-demo-20250101-abc1234",
      "branch": "main",
      "commitId": "abc1234",
      "commitAuthor": "zhangsan",
      "commitTime": "2025-01-01T09:55:00Z",
      "status": "success"
    },
    "samples": [
      {
        "id": 5001,
        "label": "positive",
        "filePath": "src/main/java/com/demo/UserDao.java",
        "snippet": "String sql = \"...\" + name;"
      }
    ],
    "occurrenceCount": 3,
    "firstFoundAt": "2024-12-20T08:00:00Z",
    "lastFoundAt": "2025-01-01T10:00:00Z",
    "fixedAt": null,
    "events": [
      {
        "id": 9001,
        "action": "created",
        "fromValue": null,
        "toValue": "open",
        "operatorName": "vuln-scanner",
        "comment": "首次由扫描工具上报",
        "createdAt": "2024-12-20T08:00:00Z"
      },
      {
        "id": 9002,
        "action": "status_changed",
        "fromValue": "open",
        "toValue": "fixing",
        "operatorName": "李四",
        "comment": "已提交修复 PR",
        "createdAt": "2024-12-25T14:30:00Z"
      },
      {
        "id": 9003,
        "action": "resurfaced",
        "fromValue": "fixed",
        "toValue": "open",
        "operatorName": "system",
        "comment": "该漏洞在扫描批次 gh-org-demo-20250101-abc1234 中再次出现",
        "createdAt": "2025-01-01T10:00:00Z"
      }
    ]
  }
}
```

**失败**：`40400` 漏洞不存在。

### 6.3 修改漏洞状态

`PATCH /api/v1/vulnerabilities/{id}/status`

**请求体**

```json
{ "status": "fixed", "comment": "已合并修复 PR #231" }
```

**响应 200**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": 88301,
    "status": "fixed",
    "fixedAt": "2025-01-02T09:00:00Z",
    "updatedAt": "2025-01-02T09:00:00Z"
  }
}
```

> 置为 `fixed` 时自动写 `fixedAt`；从 `fixed` 改回其他状态时清空 `fixedAt`。

### 6.4 批量修改状态

`POST /api/v1/vulnerabilities/batch-status`

**请求体**

```json
{ "ids": [88301, 88302, 88303], "status": "ignored", "comment": "存量代码，接受风险" }
```

**响应 200**

```json
{
  "code": 0,
  "message": "success",
  "data": { "requested": 3, "updated": 3, "failed": [] }
}
```

### 6.5 指派漏洞

`PATCH /api/v1/vulnerabilities/{id}/assignee`

```json
{ "assignee": 5, "comment": "请李四跟进" }
```

> `assignee` 传 `null` 表示取消指派。

### 6.6 新增备注

`POST /api/v1/vulnerabilities/{id}/comments`

```json
{ "comment": "与开发确认后判定为真实漏洞，排期修复" }
```

### 6.7 导出漏洞列表

`GET /api/v1/vulnerabilities/export?severity=critical,high&status=open`

- 查询参数同 6.1（不含分页）
- 返回 `text/csv`，`Content-Disposition: attachment; filename="vulnerabilities_20250101.csv"`
- 单次导出上限 50000 条；超出提示缩小筛选范围

**CSV 表头**：`漏洞编号,标题,等级,状态,规则ID,规则名,项目,仓库类型,文件路径,起始行,结束行,语言,CWE,首次发现,最后发现,命中次数,指派人`

---

## 7. 项目 / 扫描批次 / 样本接口

**鉴权：JWT**

### 7.1 项目列表

`GET /api/v1/projects?page=1&pageSize=20&keyword=&repoType=`

**响应 200**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "list": [
      {
        "id": 17,
        "name": "demo",
        "repoType": "github",
        "repoUrl": "https://github.com/org/demo",
        "repoFullName": "org/demo",
        "defaultBranch": "main",
        "owner": "张三",
        "description": "示例项目",
        "status": 1,
        "stats": {
          "scanCount": 42,
          "vulnTotal": 137,
          "vulnOpen": 88,
          "vulnCritical": 2,
          "vulnHigh": 35
        },
        "lastScanAt": "2025-01-01T10:00:00Z",
        "createdAt": "2024-11-01T00:00:00Z"
      }
    ],
    "pagination": { "page": 1, "pageSize": 20, "total": 1, "totalPages": 1 }
  }
}
```

### 7.2 项目详情

`GET /api/v1/projects/{id}` — 结构同上单条，附加 `severityDistribution` 与 `recentScans`（最近 5 次）。

### 7.3 创建 / 更新项目（手动维护补充信息）

`POST /api/v1/projects`

```json
{
  "name": "demo",
  "repoType": "github",
  "repoUrl": "https://github.com/org/demo",
  "repoFullName": "org/demo",
  "defaultBranch": "main",
  "owner": "张三",
  "description": "示例项目"
}
```

`PATCH /api/v1/projects/{id}` — 部分字段更新，请求体同上（字段均可选）。

> 扫描工具上报时会自动创建项目；此接口用于**预先注册**或**补充负责人等信息**。

### 7.4 扫描批次列表

`GET /api/v1/scans?page=1&pageSize=20&projectId=&status=&branch=&startTime=&endTime=`

**响应 200**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "list": [
      {
        "id": 1024,
        "scanNo": "gh-org-demo-20250101-abc1234",
        "project": { "id": 17, "name": "demo", "repoType": "github" },
        "scanner": { "name": "vuln-scanner", "version": "1.2.0" },
        "triggerType": "push",
        "branch": "main",
        "commitId": "abc1234",
        "commitMessage": "fix: 修复登录逻辑",
        "commitAuthor": "zhangsan",
        "commitTime": "2025-01-01T09:55:00Z",
        "status": "success",
        "totalFiles": 1280,
        "scannedFiles": 1275,
        "vulnCount": 12,
        "sampleCount": 1280,
        "positiveCount": 12,
        "negativeCount": 1268,
        "durationMs": 270000,
        "startedAt": "2025-01-01T09:58:00Z",
        "finishedAt": "2025-01-01T10:02:30Z",
        "createdAt": "2025-01-01T10:00:00Z"
      }
    ],
    "pagination": { "page": 1, "pageSize": 20, "total": 42, "totalPages": 3 }
  }
}
```

### 7.5 扫描批次详情

`GET /api/v1/scans/{scanNo}`

响应为 7.4 单条，附加：

```json
{
  "errorMessage": null,
  "vulnSummary": { "critical": 0, "high": 3, "medium": 7, "low": 2, "info": 0 },
  "topRules": [
    { "ruleId": "sql-injection-java", "ruleName": "SQL注入", "count": 3 }
  ]
}
```

### 7.6 样本列表

`GET /api/v1/samples?page=1&pageSize=20&projectId=&label=positive&ruleId=&scanNo=&language=`

| 参数 | 类型 | 说明 |
|---|---|---|
| `label` | string | `positive` / `negative` / 不传=全部 |
| `projectId` | int | 项目筛选 |
| `scanNo` | string | 批次筛选 |
| `ruleId` | string | 规则筛选（正样本） |
| `language` | string | 语言 |
| `keyword` | string | 匹配 `filePath` / `snippet` |

**响应 200**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "list": [
      {
        "id": 5001,
        "label": "positive",
        "projectId": 17,
        "scanNo": "gh-org-demo-20250101-abc1234",
        "filePath": "src/main/java/com/demo/UserDao.java",
        "language": "java",
        "lineStart": 42,
        "lineEnd": 45,
        "snippetPreview": "String sql = \"SELECT * FROM users WHERE name = '\" + name + \"'\";",
        "snippetSize": 128,
        "vulnId": 88301,
        "ruleId": "sql-injection-java",
        "createdAt": "2025-01-01T10:00:00Z"
      }
    ],
    "pagination": { "page": 1, "pageSize": 20, "total": 1280, "totalPages": 64 },
    "summary": { "positive": 12, "negative": 1268 }
  }
}
```

> 列表返回 `snippetPreview`（前 200 字符）。完整片段用 7.7。

### 7.7 样本详情

`GET /api/v1/samples/{id}` — 返回完整 `snippet` 字段。

### 7.8 样本统计

`GET /api/v1/samples/stats?projectId=&startTime=&endTime=`

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "total": 12800,
    "positive": 137,
    "negative": 12663,
    "positiveRatio": 0.0107,
    "byLanguage": [
      { "language": "java", "positive": 80, "negative": 6000 },
      { "language": "javascript", "positive": 57, "negative": 6663 }
    ],
    "byRule": [
      { "ruleId": "sql-injection-java", "ruleName": "SQL注入", "count": 42 }
    ]
  }
}
```

---

## 8. 统计接口

**鉴权：JWT**

### 8.1 总览

`GET /api/v1/stats/overview?projectId=&days=30`

**响应 200**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "vulnTotal": 137,
    "vulnOpen": 88,
    "vulnCritical": 2,
    "vulnHigh": 35,
    "newInPeriod": 23,
    "fixedInPeriod": 15,
    "projectCount": 12,
    "scanCount": 420,
    "sampleCount": 128000,
    "avgFixHours": 36.5
  }
}
```

| 字段 | 说明 |
|---|---|
| `vulnTotal` | 漏洞总数（不含误报与已忽略） |
| `vulnOpen` | 待处理数（`open` + `confirmed` + `fixing`） |
| `newInPeriod` | 近 `days` 天新增 |
| `fixedInPeriod` | 近 `days` 天修复 |
| `avgFixHours` | 平均修复时长（小时），由 `fixedAt - firstFoundAt` 计算 |

### 8.2 趋势

`GET /api/v1/stats/trend?days=30&projectId=`

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "list": [
      { "date": "2024-12-01", "newCount": 5, "fixedCount": 2, "openCount": 90 },
      { "date": "2024-12-02", "newCount": 3, "fixedCount": 4, "openCount": 89 }
    ]
  }
}
```

### 8.3 等级分布

`GET /api/v1/stats/severity?projectId=`

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "list": [
      { "severity": "critical", "count": 2, "openCount": 2, "fixedCount": 0 },
      { "severity": "high", "count": 35, "openCount": 20, "fixedCount": 15 },
      { "severity": "medium", "count": 60, "openCount": 45, "fixedCount": 15 },
      { "severity": "low", "count": 30, "openCount": 18, "fixedCount": 12 },
      { "severity": "info", "count": 10, "openCount": 3, "fixedCount": 7 }
    ]
  }
}
```

### 8.4 Top 规则排行

`GET /api/v1/stats/top-rules?limit=10&projectId=&days=30`

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "list": [
      { "ruleId": "sql-injection-java", "ruleName": "SQL注入", "category": "injection", "count": 42, "criticalCount": 3 },
      { "ruleId": "xss-reflected", "ruleName": "反射型XSS", "category": "xss", "count": 31, "criticalCount": 0 }
    ]
  }
}
```

### 8.5 Top 项目排行

`GET /api/v1/stats/top-projects?limit=10&sortBy=vulnOpen`

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "list": [
      { "projectId": 17, "name": "demo", "repoType": "github", "vulnTotal": 137, "vulnOpen": 88, "criticalCount": 2, "highCount": 35 }
    ]
  }
}
```

---

## 9. Webhook 接口（可选）

> 优先级 P1。用于 GitHub / GitLab 推送时代码仓库**主动通知平台**（触发扫描或记录提交），本期可先不实现。

### 9.1 GitHub Webhook

`POST /api/v1/webhook/github`

- 请求头：`X-Hub-Signature-256`（HMAC-SHA256，用 webhook secret 校验）、`X-GitHub-Event`
- 支持的 event：`push`、`pull_request`

### 9.2 GitLab Webhook

`POST /api/v1/webhook/gitlab`

- 请求头：`X-Gitlab-Token`（明文 token 比对）、`X-Gitlab-Event`
- 支持的 event：`Push Hook`、`Merge Request Hook`

> 两个接口统一返回 `{ "code": 0, "message": "success", "data": { "received": true } }`，异步处理，立即返回 200，避免第三方重试。

---

## 10. 错误码全表

### 10.1 业务错误码

| code | HTTP | 消息 | 说明 / 处理建议 |
|---|---|---|---|
| `0` | 200/201 | success | 成功 |
| `40001` | 400 | 参数校验失败 | 看 `data.errors`，修正后重试；**不要重试原请求** |
| `40002` | 400 | 旧密码不正确 | |
| `40003` | 400 | 新密码强度不足 | |
| `40004` | 400 | 批次状态不允许该操作 | 如对已 complete 的批次续传漏洞 |
| `40100` | 401 | 未登录或 Token 无效/过期 | 前端跳登录页 |
| `40101` | 401 | API Key 无效或已被吊销 | 检查 Key 配置，**不要重试** |
| `40102` | 401 | API Key 已过期 | 联系管理员续期 |
| `40103` | 401 | API Key 无权访问该仓库 | 检查 `repoScope` 白名单 |
| `40300` | 403 | 无权限 | 当前角色不具备该操作权限 |
| `40301` | 403 | 账号已被禁用 | |
| `40400` | 404 | 资源不存在 | 检查 ID / scanNo |
| `40900` | 409 | 资源冲突 | 如 `scanNo` 已存在但关键信息不一致 |
| `41300` | 413 | 请求体过大 | 改用分片上报，单批 ≤ 500 条 |
| `42900` | 429 | 请求过于频繁 | 按 `Retry-After` 头退避重试 |
| `42902` | 429 | 登录尝试过于频繁 | 等待后重试 |
| `50000` | 500 | 服务器内部错误 | 可重试；持续失败联系平台侧并附 `traceId` |
| `50001` | 500 | 数据库错误 | 同上 |
| `50300` | 503 | 服务暂不可用（维护中） | 稍后重试 |

### 10.2 扫描侧重试决策表

| HTTP | code | 是否重试 |
|---|---|---|
| 200 / 201 | 0 | 不需要（成功） |
| 400 | 4xxxx | ❌ 不重试，修数据 |
| 401 | 401xx | ❌ 不重试，修 Key |
| 403 | 403xx | ❌ 不重试 |
| 404 | 40400 | ❌ 不重试 |
| 409 | 40900 | ⚠️ 人工确认后处理 |
| 413 | 41300 | ❌ 不重试，改分片 |
| 429 | 42900 | ✅ 按 `Retry-After` 重试 |
| 500 / 502 / 503 / 504 | 5xxxx | ✅ 指数退避重试 3 次（1s/3s/9s） |
| 网络超时 | — | ✅ 同上（接口幂等，安全重试） |

---

## 11. 联调约定与 Mock

### 11.1 契约冻结流程

1. 平台侧发出本文档 + `openapi.yaml`。
2. 扫描侧逐条确认第 5 章字段：**能提供的打勾，不能提供的说明原因**。
3. 双方对"不能提供"的字段达成降级方案（字段可选 / 平台侧填默认值）。
4. **冻结 v1.0**，此后只增字段不改语义。
5. 起 Mock Server，扫描侧先接 Mock 联调上报逻辑。

### 11.2 起 Mock Server

```bash
# 方式一：Prism（推荐，严格按 openapi.yaml 校验请求）
npx @stoplight/prism-cli mock docs/openapi.yaml --port 4010

# 方式二：json-server（更轻，但需手写 db.json）
npx json-server --watch mock/db.json --port 4010
```

Mock 地址：`http://localhost:4010/api/v1`

### 11.3 联调检查清单

| # | 检查项 | 预期 |
|---|---|---|
| 1 | `GET /ingest/ping` 带 API Key | 返回 `valid: true` |
| 2 | `GET /ingest/ping` 不带 API Key | 返回 401 / `40101` |
| 3 | 创建批次 | 返回 `scanId`、`projectId` |
| 4 | 同一 `scanNo` 再创建 | `duplicated: true`，无新记录 |
| 5 | 上报 3 条漏洞 | `created: 3` |
| 6 | 再上报同样 3 条漏洞 | `updated: 3`，`created: 0`，库中仍 3 条 |
| 7 | 上报负样本 | `negativeCount` 与扫描文件数一致 |
| 8 | 上报未先创建批次 | 返回 404 / `40400` |
| 9 | 单批 501 条 | 返回 400 / `40001` |
| 10 | 结束批次 | 返回 `vulnCount` / `sampleCount` 与实际上报一致 |
| 11 | 前端登录后看板 | 数字与 6.1 / 8.1 接口一致 |
| 12 | 吊销 Key 后再上报 | 返回 401 / `40101` |

### 11.4 环境地址

| 环境 | Base URL | 说明 |
|---|---|---|
| 本地 Mock | `http://localhost:4010/api/v1` | 无需数据库，用于前期联调 |
| 开发 | `http://dev-vuln.internal/api/v1` | 真实数据库，可随意造数据 |
| 测试 | `http://test-vuln.internal/api/v1` | 联调验收 |
| 生产 | `https://vuln.example.com/api/v1` | 上线后使用 |

---

## 附录 A：字段能力确认表（请扫描侧填写）

> 请扫描侧逐行标注：✅ 能提供 / ❌ 不能提供 / ⚠️ 部分提供

| # | 字段 | 归属 | 能力 | 备注 |
|---|---|---|---|---|
| 1 | `scanNo` | 批次 | | 生成规则： |
| 2 | `scan.repoType` | 批次 | | |
| 3 | `scan.repoUrl` | 批次 | | |
| 4 | `scan.repoFullName` | 批次 | | |
| 5 | `scan.branch` | 批次 | | |
| 6 | `scan.commitId` | 批次 | | |
| 7 | `scan.commitMessage` | 批次 | | |
| 8 | `scan.commitAuthor` | 批次 | | |
| 9 | `scan.commitTime` | 批次 | | |
| 10 | `totalFiles` / `scannedFiles` | 批次 | | |
| 11 | `vulnerabilities[].ruleId` | 漏洞 | | **必须稳定**，否则去重失效 |
| 12 | `vulnerabilities[].severity` | 漏洞 | | 等级如何映射到 5 档？ |
| 13 | `vulnerabilities[].title` | 漏洞 | | |
| 14 | `vulnerabilities[].cwe` / `cve` | 漏洞 | | |
| 15 | `vulnerabilities[].filePath` | 漏洞 | | 是否为仓库相对路径？ |
| 16 | `vulnerabilities[].lineStart/lineEnd` | 漏洞 | | |
| 17 | `vulnerabilities[].codeSnippet` | 漏洞 | | 最大长度？ |
| 18 | `vulnerabilities[].suggestion` | 漏洞 | | |
| 19 | `vulnerabilities[].confidence` | 漏洞 | | 取值区间？ |
| 20 | `samples[].label` | 样本 | | 正负样本判定标准？ |
| 21 | `samples[].snippet` | 样本 | | 是整文件还是片段？ |
| 22 | `samples[].snippetHash` | 样本 | | 能否计算 sha256？ |
| 23 | `samples[].fileHash` | 样本 | | |
| 24 | 单次上报样本量级 | 样本 | | 约 ___ 条/仓库 |
| 25 | 上报耗时预估 | 性能 | | 约 ___ 秒 |

## 附录 B：待扫描侧确认的问题

1. `scanNo` 的唯一性与生成规则？同一 commit 重复触发会生成相同还是不同的 `scanNo`？
2. 正样本与负样本的**判定标准**是什么？（有漏洞的行所在文件=正样本？还是整个文件？）
3. 负样本是**全量上报无漏洞文件**，还是**采样上报**？量级多大？
4. `ruleId` 的命名规范与稳定性保证？
5. 扫描工具的漏洞等级体系与平台 5 档（critical/high/medium/low/info）如何映射？
6. 扫描工具是否支持本地缓存 + 失败重试？上报失败会不会丢数据？
7. 是否需要平台提供"扫描任务下发"接口（平台侧主动触发扫描）？

---

**文档状态**：待评审冻结
**变更记录**

| 版本 | 日期 | 变更内容 | 作者 |
|---|---|---|---|
| v0.1 | 2025-01-01 | 初稿，确立上报契约与查询接口 | 平台侧 |
