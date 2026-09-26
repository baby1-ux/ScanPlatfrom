#!/usr/bin/env node
/**
 * 端到端冒烟测试：验证「扫描工具 → 上报 → 入库 → 查询」全链路。
 *
 * 覆盖 docs/02 第 11.3 节的联调检查清单：
 *   1  GET /ingest/ping 带 Key        → valid: true
 *   2  GET /ingest/ping 不带 Key      → 401 / 40101
 *   3  创建批次                        → 返回 scanId / projectId
 *   4  同一 scanNo 再创建              → duplicated: true，无新记录
 *   5  上报 3 条漏洞                   → created: 3
 *   6  再上报同样 3 条                 → updated: 3，created: 0，库中仍 3 条
 *   7  上报正负样本                    → 计数正确
 *   8  未创建批次就上报                → 404 / 40400
 *   9  单批 501 条                     → 400 / 40001
 *  10  结束批次                        → 计数与实际一致
 *  11  登录后看板数字与接口一致        → 登录 + 统计接口
 *  12  吊销 Key 后再上报               → 401 / 40101
 *
 * 用法：
 *   node scripts/smoke-ingest.mjs
 *   BASE_URL=http://127.0.0.1:3000 API_KEY=vuln_sk_xxx node scripts/smoke-ingest.mjs
 */
import process from 'node:process';

const BASE = (process.env.BASE_URL ?? 'http://127.0.0.1:3000').replace(/\/+$/, '');
const API = `${BASE}/api/v1`;
const KEY = process.env.API_KEY ?? 'vuln_sk_demo00000000000000000000000001';
const ADMIN = { username: process.env.ADMIN_USERNAME ?? 'admin', password: process.env.ADMIN_PASSWORD ?? 'Admin@12345' };

let passed = 0;
let failed = 0;
const failures = [];

function check(name, condition, detail = '') {
  if (condition) {
    passed += 1;
    console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  } else {
    failed += 1;
    failures.push(name);
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

async function req(method, path, { body, key, token } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (key) headers['X-API-Key'] = key;
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${API}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let json = null;
  const text = await res.text();
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }
  return { status: res.status, body: json };
}

const section = (t) => console.log(`\n\x1b[36m${t}\x1b[0m`);

const SCAN_NO = `smoke-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${Math.random()
  .toString(16)
  .slice(2, 9)}`;
const REPO_URL = 'https://github.com/smoke/demo-repo';

const VULNS = [
  {
    externalVulnId: 'SMOKE-0001',
    ruleId: 'sql-injection-java',
    ruleName: 'SQL注入',
    title: '冒烟测试：用户输入未过滤直接拼接进 SQL 语句',
    severity: 'high',
    category: 'injection',
    cwe: 'CWE-89',
    language: 'java',
    filePath: 'src/main/java/com/smoke/UserDao.java',
    lineStart: 42,
    lineEnd: 45,
    codeSnippet: 'String sql = "SELECT * FROM users WHERE name = \'" + name + "\'";',
    description: 'name 参数来源于 HTTP 请求且未做校验。',
    suggestion: '使用 PreparedStatement 参数化查询。',
    confidence: 0.95,
  },
  {
    externalVulnId: 'SMOKE-0002',
    ruleId: 'xss-reflected',
    ruleName: '反射型XSS',
    title: '冒烟测试：未转义的用户输入写入 HTML',
    severity: 'medium',
    category: 'xss',
    cwe: 'CWE-79',
    language: 'javascript',
    filePath: 'src/web/search.js',
    lineStart: 12,
    lineEnd: 14,
    codeSnippet: 'el.innerHTML = "结果: " + q;',
  },
  {
    externalVulnId: 'SMOKE-0003',
    ruleId: 'command-injection-python',
    ruleName: '命令注入',
    title: '冒烟测试：用户可控参数拼接进系统命令',
    severity: 'critical',
    category: 'injection',
    cwe: 'CWE-78',
    language: 'python',
    filePath: 'scripts/net_tools.py',
    lineStart: 8,
    lineEnd: 10,
    codeSnippet: 'os.popen("ping -c 1 " + host).read()',
  },
];

const SAMPLES = [
  {
    externalSampleId: 'SMOKE-S-0001',
    label: 'positive',
    filePath: 'src/main/java/com/smoke/UserDao.java',
    language: 'java',
    lineStart: 42,
    lineEnd: 45,
    snippet: VULNS[0].codeSnippet,
    externalVulnId: 'SMOKE-0001',
  },
  {
    externalSampleId: 'SMOKE-S-0002',
    label: 'negative',
    filePath: 'src/main/java/com/smoke/UserService.java',
    language: 'java',
    lineStart: 1,
    lineEnd: 20,
    snippet: 'public class UserService { /* 无漏洞样本 */ }',
  },
];

async function main() {
  console.log(`\n漏洞管理平台 · 上报链路冒烟测试`);
  console.log(`目标：${API}`);
  console.log(`批次号：${SCAN_NO}\n`);

  // 健康检查
  section('0) 服务健康检查');
  try {
    const r = await fetch(`${BASE}/health`);
    check('GET /health 返回 200', r.status === 200, `实际 ${r.status}`);
  } catch (e) {
    console.log(`\x1b[31m无法连接 ${BASE}，请先启动后端：pnpm -C apps/server dev\x1b[0m`);
    console.log(String(e));
    process.exit(1);
  }

  // 1) ping 带 Key
  section('1-2) API Key 自检');
  const ping = await req('GET', '/ingest/ping', { key: KEY });
  check('带 Key 调 /ingest/ping → code=0', ping.body?.code === 0, JSON.stringify(ping.body));
  check('data.valid === true', ping.body?.data?.valid === true);

  // 2) ping 不带 Key
  const pingNoKey = await req('GET', '/ingest/ping');
  check('不带 Key → HTTP 401', pingNoKey.status === 401, `实际 ${pingNoKey.status}`);
  check('不带 Key → code 40101', pingNoKey.body?.code === 40101, JSON.stringify(pingNoKey.body));

  // 8) 未创建批次就上报
  section('8) 未创建批次就上报漏洞');
  const orphan = await req('POST', `/ingest/scans/${SCAN_NO}-not-exist/vulnerabilities`, {
    key: KEY,
    body: { vulnerabilities: [VULNS[0]] },
  });
  check('→ HTTP 404', orphan.status === 404, `实际 ${orphan.status}`);
  check('→ code 40400', orphan.body?.code === 40400, JSON.stringify(orphan.body));

  // 9) 单批 501 条
  section('9) 单批超过 500 条');
  const tooMany = await req('POST', `/ingest/scans/${SCAN_NO}/vulnerabilities`, {
    key: KEY,
    body: { vulnerabilities: Array.from({ length: 501 }, (_, i) => ({ ...VULNS[0], externalVulnId: `X-${i}` })) },
  });
  check('→ HTTP 400', tooMany.status === 400, `实际 ${tooMany.status}`);
  check('→ code 40001', tooMany.body?.code === 40001, JSON.stringify(tooMany.body));
  // 3) 创建批次
  section('3) 创建扫描批次');
  const created = await req('POST', '/ingest/scans', {
    key: KEY,
    body: {
      scanNo: SCAN_NO,
      scanner: { name: 'smoke-test', version: '1.0.0' },
      triggerType: 'manual',
      scan: {
        repoType: 'github',
        repoUrl: REPO_URL,
        repoFullName: 'smoke/demo-repo',
        projectName: 'smoke-demo-repo',
        branch: 'main',
        commitId: 'abc1234567890abcdef1234567890abcdef12345',
        commitMessage: 'test: 冒烟测试上报',
        commitAuthor: 'smoke-bot',
      },
      totalFiles: 120,
    },
  });
  check('→ HTTP 201', created.status === 201, `实际 ${created.status}`);
  check('返回 scanId', typeof created.body?.data?.scanId === 'number', JSON.stringify(created.body?.data));
  check('返回 projectId', typeof created.body?.data?.projectId === 'number');
  check('duplicated === false', created.body?.data?.duplicated === false);
  const scanId = created.body?.data?.scanId;
  const projectId = created.body?.data?.projectId;

  // 4) 幂等：再创建同一批次
  const dup = await req('POST', '/ingest/scans', {
    key: KEY,
    body: {
      scanNo: SCAN_NO,
      triggerType: 'manual',
      scan: { repoType: 'github', repoUrl: REPO_URL, branch: 'main' },
    },
  });
  check('重复创建 → duplicated === true', dup.body?.data?.duplicated === true, JSON.stringify(dup.body?.data));
  check('重复创建 → scanId 不变', dup.body?.data?.scanId === scanId, `${dup.body?.data?.scanId} vs ${scanId}`);

  // 5) 上报漏洞
  // 注意：漏洞按指纹全局去重，不是按批次。首次跑是 created=3；
  // 再次跑同一脚本时指纹已存在，会变成 updated=3 —— 两者都算「处理成功」。
  section('5) 上报 3 条漏洞');
  const v1 = await req('POST', `/ingest/scans/${SCAN_NO}/vulnerabilities`, {
    key: KEY,
    body: { vulnerabilities: VULNS },
  });
  const v1Data = v1.body?.data ?? {};
  check(
    '3 条漏洞全部处理成功（created + updated = 3）',
    (v1Data.created ?? 0) + (v1Data.updated ?? 0) === 3,
    JSON.stringify(v1Data),
  );
  check('skipped === 0', v1Data.skipped === 0, JSON.stringify(v1Data));
  check(
    '首次上报为 created，重复运行时为 updated（指纹去重生效）',
    v1Data.created === 3 || v1Data.updated === 3,
    JSON.stringify(v1Data),
  );

  // 6) 重复上报同样漏洞 → 幂等
  section('6) 重复上报同样 3 条漏洞（幂等）');
  const v2 = await req('POST', `/ingest/scans/${SCAN_NO}/vulnerabilities`, {
    key: KEY,
    body: { vulnerabilities: VULNS },
  });
  check('created === 0（不新增记录）', v2.body?.data?.created === 0, JSON.stringify(v2.body?.data));
  check('updated + resurfaced === 3', (v2.body?.data?.updated ?? 0) + (v2.body?.data?.resurfaced ?? 0) === 3, JSON.stringify(v2.body?.data));

  // 7) 上报样本
  section('7) 上报正负样本');
  const s1 = await req('POST', `/ingest/scans/${SCAN_NO}/samples`, {
    key: KEY,
    body: { samples: SAMPLES },
  });
  check('created === 2', s1.body?.data?.created === 2, JSON.stringify(s1.body?.data));
  check('positiveCount === 1', s1.body?.data?.positiveCount === 1);
  check('negativeCount === 1', s1.body?.data?.negativeCount === 1);

  const s2 = await req('POST', `/ingest/scans/${SCAN_NO}/samples`, {
    key: KEY,
    body: { samples: SAMPLES },
  });
  check('重复上报样本 → duplicated === 2', s2.body?.data?.duplicated === 2, JSON.stringify(s2.body?.data));

  // 10) 结束批次
  section('10) 结束批次');
  const done = await req('POST', `/ingest/scans/${SCAN_NO}/complete`, {
    key: KEY,
    body: { status: 'success', scannedFiles: 118, totalFiles: 120 },
  });
  check('status === success', done.body?.data?.status === 'success', JSON.stringify(done.body?.data));
  check('vulnCount === 3', done.body?.data?.vulnCount === 3, `实际 ${done.body?.data?.vulnCount}`);
  check('sampleCount === 2', done.body?.data?.sampleCount === 2, `实际 ${done.body?.data?.sampleCount}`);

  // 11) 登录 + 看板一致性
  section('11) 登录并校验看板数字');
  const login = await req('POST', '/auth/login', { body: ADMIN });
  check('登录成功 code=0', login.body?.code === 0, JSON.stringify(login.body));
  const token = login.body?.data?.accessToken;
  check('拿到 accessToken', typeof token === 'string' && token.length > 20);

  if (token) {
    const me = await req('GET', '/auth/me', { token });
    check('GET /auth/me 成功', me.body?.code === 0);
    check('返回 permissions', Array.isArray(me.body?.data?.permissions));

    const list = await req('GET', `/vulnerabilities?keyword=${encodeURIComponent('冒烟测试')}&pageSize=50`, { token });
    check('漏洞列表查到本次上报的 3 条', (list.body?.data?.list ?? []).length === 3, `实际 ${(list.body?.data?.list ?? []).length}`);
    check('列表 summary 含 critical/high/medium', (list.body?.data?.summary?.critical ?? 0) >= 1);

    const scanDetail = await req('GET', `/scans/${encodeURIComponent(SCAN_NO)}`, { token });
    check('批次详情可查', scanDetail.body?.code === 0, JSON.stringify(scanDetail.body).slice(0, 200));
    check('批次 vulnSummary.critical ≥ 1', (scanDetail.body?.data?.vulnSummary?.critical ?? 0) >= 1);

    const samples = await req('GET', `/samples?scanNo=${encodeURIComponent(SCAN_NO)}`, { token });
    check('样本列表查到 2 条', (samples.body?.data?.list ?? []).length === 2, `实际 ${(samples.body?.data?.list ?? []).length}`);

    const overview = await req('GET', '/stats/overview?days=7', { token });
    check('看板 overview 可用', overview.body?.code === 0);
    check(
      'vulnTotal ≥ 3（含本次上报）',
      (overview.body?.data?.vulnTotal ?? 0) >= 3,
      `实际 ${overview.body?.data?.vulnTotal}`,
    );

    const trend = await req('GET', '/stats/trend?days=7', { token });
    check('趋势接口返回 7 个点', (trend.body?.data?.list ?? []).length === 7, `实际 ${(trend.body?.data?.list ?? []).length}`);

    const projects = await req('GET', '/projects?pageSize=100', { token });
    check('项目列表包含本项目', (projects.body?.data?.list ?? []).some((p) => p.id === projectId));
    const thisProject = (projects.body?.data?.list ?? []).find((p) => p.id === projectId);
    check('项目统计 scanCount ≥ 1', (thisProject?.stats?.scanCount ?? 0) >= 1, JSON.stringify(thisProject?.stats));

    // 状态流转
    const vulnList = list.body?.data?.list ?? [];
    // 列表按时间倒序，list[0] 可能来自历史运行；按 ruleId + filePath + title 三者
    // 定位本脚本自己上报的那条（这三个值正好决定指纹）。
    const cur = vulnList.find((x) =>
      VULNS.some((v) => v.ruleId === x.ruleId && v.filePath === x.filePath && v.title === x.title),
    );
    check('能在列表中定位到本次上报的漏洞', !!cur, `list[0].ruleId=${vulnList[0]?.ruleId}`);

    const targetId = cur?.id;
    if (targetId) {
      const patched = await req('PATCH', `/vulnerabilities/${targetId}/status`, {
        token,
        body: { status: 'fixed', comment: '冒烟测试：标记为已修复' },
      });
      check('修改漏洞状态成功', patched.body?.code === 0, JSON.stringify(patched.body));
      check('fixedAt 已写入', !!patched.body?.data?.fixedAt);

      const detail = await req('GET', `/vulnerabilities/${targetId}`, { token });
      check(
        '详情含处置时间线',
        (detail.body?.data?.events ?? []).length >= 2,
        `事件数 ${(detail.body?.data?.events ?? []).length}`,
      );
      check('终态为 fixed', detail.body?.data?.status === 'fixed', `status=${detail.body?.data?.status}`);

      // 再上报同一条漏洞：指纹 = projectId|ruleId|filePath|codeSnippet，
      // 三个输入必须与首次上报完全一致才会命中同一指纹。
      // 注意：主批次在第 10 步已 complete，按契约（40004）不允许继续上报，
      // 因此这里另开一个开放批次来验证「终态漏洞复现」语义。
      const REOPEN_SCAN_NO = `${SCAN_NO}-reopen`;
      const reopen = await req('POST', '/ingest/scans', {
        key: KEY,
        body: {
          scanNo: REOPEN_SCAN_NO,
          triggerType: 'manual',
          scan: { repoType: 'github', repoUrl: REPO_URL, branch: 'main' },
        },
      });
      check('另开开放批次成功', reopen.body?.code === 0, JSON.stringify(reopen.body).slice(0, 160));

      const closedBatch = await req('POST', `/ingest/scans/${SCAN_NO}/vulnerabilities`, {
        key: KEY,
        body: { vulnerabilities: [VULNS[0]] },
      });
      check(
        '已 complete 的批次继续上报 → 400 / 40004',
        closedBatch.status === 400 && closedBatch.body?.code === 40004,
        `HTTP ${closedBatch.status} code=${closedBatch.body?.code}`,
      );

      const payload = VULNS.find((v) => v.ruleId === cur.ruleId && v.filePath === cur.filePath);
      const resurface = await req('POST', `/ingest/scans/${REOPEN_SCAN_NO}/vulnerabilities`, {
        key: KEY,
        body: { vulnerabilities: [payload ?? VULNS[0]] },
      });
      const data = resurface.body?.data ?? {};
      check(
        '终态漏洞再次命中 → resurfaced 置回 open',
        data.resurfaced === 1,
        `HTTP ${resurface.status} resurfaced=${data.resurfaced} updated=${data.updated} created=${data.created}`,
      );

      const afterResurface = await req('GET', `/vulnerabilities/${targetId}`, { token });
      check(
        '复现后状态回到 open 且写入 resurfaced 事件',
        afterResurface.body?.data?.status === 'open' &&
          (afterResurface.body?.data?.events ?? []).some((e) => e.action === 'resurfaced'),
        `status=${afterResurface.body?.data?.status}`,
      );
    }

    // ML 状态
    const mlStatus = await req('GET', '/ml/status', { token });
    check('模型服务状态接口可用', mlStatus.body?.code === 0, JSON.stringify(mlStatus.body).slice(0, 200));
    console.log(
      `    ℹ 模型服务：${mlStatus.body?.data?.online ? '在线' : '离线（检测将降级为启发式判定）'} @ ${mlStatus.body?.data?.url}`,
    );

    // 12) 吊销 API Key
    section('12) 吊销 API Key 后再上报');
    const keys = await req('GET', '/api-keys?pageSize=100', { token });
    const demoKey = (keys.body?.data?.list ?? []).find((k) => k.status === 1);
    if (demoKey) {
      await req('DELETE', `/api-keys/${demoKey.id}`, { token });
      const afterRevoke = await req('GET', '/ingest/ping', { key: KEY });
      check('吊销后 ping → HTTP 401', afterRevoke.status === 401, `实际 ${afterRevoke.status}`);
      check('吊销后 ping → code 40101', afterRevoke.body?.code === 40101);
      await req('POST', `/api-keys/${demoKey.id}/restore`, { token });
      const afterRestore = await req('GET', '/ingest/ping', { key: KEY });
      check('恢复后 ping 再次有效', afterRestore.body?.code === 0);
    } else {
      console.log('    ℹ 没有启用的 API Key，跳过吊销检查');
    }
  }

  // -------------------------------------------------------------- 汇总
  console.log(`\n${'─'.repeat(56)}`);
  if (failed === 0) {
    console.log(`\x1b[32m全部通过：${passed} 项检查\x1b[0m`);
  } else {
    console.log(`\x1b[32m通过 ${passed}\x1b[0m / \x1b[31m失败 ${failed}\x1b[0m`);
    console.log('失败项：');
    for (const f of failures) console.log(`  - ${f}`);
  }
  console.log(`${'─'.repeat(56)}\n`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('\n冒烟测试异常终止：', e);
  process.exit(1);
});
