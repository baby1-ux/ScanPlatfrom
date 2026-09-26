/**
 * 集成测试：直接对 Express 应用发请求（不经过网络端口）。
 * 覆盖契约里的关键行为与边界：鉴权、幂等、去重、校验、状态流转、统计口径、权限。
 *
 * 用法：
 *   node --no-warnings=ExperimentalWarning --import tsx/esm --test apps/server/tests/
 *   或 pnpm -C apps/server test
 *
 * 说明：测试使用独立的 SQLite 文件（SQLITE_TEST_PATH），跑完即删，
 * 不会污染开发库。
 */
import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const TEST_DB = path.join(os.tmpdir(), `vuln-test-${process.pid}-${Date.now()}.db`);
process.env.SQLITE_PATH = TEST_DB;
process.env.SEED_DEMO_DATA = 'false';
process.env.JWT_SECRET = 'test-secret-for-integration-test';
process.env.ADMIN_PASSWORD = 'Admin@12345';
process.env.LOG_LEVEL = 'error';
// 测试会反复登录同一账号，这里关闭限流；限流本身在最后的用例里单独验证（用独立 IP 计数）
process.env.RATE_LIMIT_DISABLED = '1';

const { createApp } = await import('../src/app.ts');
const { getDb, initDatabase } = await import('../src/db/index.ts');
const { generateApiKey, apiKeyHash } = await import('../src/services/fingerprint.ts');

const db = getDb();
initDatabase(db, { demoData: false });
const app = createApp();

// ---------------------------------------------------------------- 测试助手
let server;
let baseUrl;

before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve);
  });
  const addr = server.address();
  baseUrl = `http://127.0.0.1:${addr.port}/api/v1`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  db.close();
  for (const suffix of ['', '-wal', '-shm', '-journal']) {
    try {
      fs.unlinkSync(`${TEST_DB}${suffix}`);
    } catch {
      /* 忽略 */
    }
  }
});

async function call(method, path, { body, key, token } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (key) headers['X-API-Key'] = key;
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }
  return { status: res.status, body: json, headers: res.headers };
}

/** 建一个可用的 API Key 并直接返回明文 */
function makeKey(name, opts = {}) {
  const plain = generateApiKey();
  const now = new Date().toISOString();
  db.run(
    `INSERT INTO api_keys(name, key_prefix, key_hash, scopes, repo_scope, expires_at, status, created_at, updated_at)
     VALUES(?, ?, ?, ?, ?, ?, 1, ?, ?)`,
    [
      name,
      plain.slice(0, 12),
      apiKeyHash(plain),
      'ingest',
      opts.repoScope ?? null,
      opts.expiresAt ?? null,
      now,
      now,
    ],
  );
  return plain;
}

async function adminToken() {
  const r = await call('POST', '/auth/login', {
    body: { username: 'admin', password: 'Admin@12345' },
  });
  assert.equal(r.body.code, 0, '管理员登录应成功');
  return r.body.data.accessToken;
}

const REPO = 'https://github.com/test/integration';
let seq = 0;
const nextScanNo = () => `it-${Date.now()}-${++seq}`;

async function createBatch(key, scanNo, extra = {}) {
  return call('POST', '/ingest/scans', {
    key,
    body: {
      scanNo,
      triggerType: 'manual',
      scan: { repoType: 'github', repoUrl: REPO, projectName: 'integration-repo', branch: 'main' },
      ...extra,
    },
  });
}

const VULN = {
  externalVulnId: 'IT-1',
  ruleId: 'it-rule-sqli',
  ruleName: 'SQL注入',
  title: '集成测试：SQL 拼接注入',
  severity: 'high',
  category: 'injection',
  cwe: 'CWE-89',
  language: 'java',
  filePath: 'src/It.java',
  lineStart: 10,
  lineEnd: 12,
  codeSnippet: 'String sql = "SELECT * FROM t WHERE a = \'" + a + "\'";',
  suggestion: '参数化查询',
  confidence: 0.91,
};

// ================================================================ 测试
describe('鉴权', () => {
  it('无 Key 调上报接口返回 40101', async () => {
    const r = await call('GET', '/ingest/ping');
    assert.equal(r.status, 401);
    assert.equal(r.body.code, 40101);
  });

  it('正确 Key 调 ping 返回 valid', async () => {
    const key = makeKey('it-ping');
    const r = await call('GET', '/ingest/ping', { key });
    assert.equal(r.body.code, 0);
    assert.equal(r.body.data.valid, true);
  });

  it('无效 Key 返回 40101', async () => {
    const r = await call('GET', '/ingest/ping', { key: 'vuln_sk_not_a_real_key' });
    assert.equal(r.body.code, 40101);
  });

  it('已过期 Key 返回 40102', async () => {
    const key = makeKey('it-expired', { expiresAt: '2020-01-01T00:00:00Z' });
    const r = await call('GET', '/ingest/ping', { key });
    assert.equal(r.body.code, 40102);
  });

  it('repoScope 白名单外返回 40103', async () => {
    const key = makeKey('it-scoped', { repoScope: 'https://github.com/other/repo' });
    const r = await createBatch(key, nextScanNo());
    assert.equal(r.body.code, 40103);
  });

  it('repoScope 白名单内可上报', async () => {
    const key = makeKey('it-scoped-ok', { repoScope: REPO });
    const r = await createBatch(key, nextScanNo());
    assert.equal(r.body.code, 0);
  });

  it('未登录访问业务接口返回 40100', async () => {
    const r = await call('GET', '/vulnerabilities');
    assert.equal(r.body.code, 40100);
  });
});

describe('上报：批次幂等', () => {
  it('创建批次返回 scanId/projectId，重复创建 duplicated=true 且 scanId 不变', async () => {
    const key = makeKey('it-scan');
    const scanNo = nextScanNo();
    const first = await createBatch(key, scanNo);
    assert.equal(first.status, 201);
    assert.equal(first.body.data.duplicated, false);

    const again = await createBatch(key, scanNo);
    assert.equal(again.status, 200);
    assert.equal(again.body.data.duplicated, true);
    assert.equal(again.body.data.scanId, first.body.data.scanId);

    const rows = db.get('SELECT COUNT(*) AS c FROM scan_tasks WHERE scan_no = ?', [scanNo]);
    assert.equal(rows.c, 1, '同 scanNo 只应有一条批次');
  });

  it('scanNo 含 / 或空格返回 40001', async () => {
    const key = makeKey('it-badno');
    const r = await createBatch(key, 'bad/no with space');
    assert.equal(r.status, 400);
    assert.equal(r.body.code, 40001);
  });

  it('未创建批次就上报漏洞返回 40400', async () => {
    const key = makeKey('it-orphan');
    const r = await call('POST', `/ingest/scans/${nextScanNo()}/vulnerabilities`, {
      key,
      body: { vulnerabilities: [VULN] },
    });
    assert.equal(r.status, 404);
    assert.equal(r.body.code, 40400);
  });
});

describe('上报：漏洞去重与状态保留', () => {
  it('首次上报 created=1，重复上报 updated=1 且不新增记录', async () => {
    const key = makeKey('it-dedup');
    const scanNo = nextScanNo();
    await createBatch(key, scanNo);

    const a = await call('POST', `/ingest/scans/${scanNo}/vulnerabilities`, {
      key,
      body: { vulnerabilities: [VULN] },
    });
    assert.equal(a.body.data.created, 1);

    const b = await call('POST', `/ingest/scans/${scanNo}/vulnerabilities`, {
      key,
      body: { vulnerabilities: [VULN] },
    });
    assert.equal(b.body.data.created, 0);
    assert.equal(b.body.data.updated, 1);

    const cnt = db.get(
      `SELECT COUNT(*) AS c FROM vulnerabilities WHERE rule_id = ? AND file_path = ?`,
      [VULN.ruleId, VULN.filePath],
    );
    assert.equal(cnt.c, 1, '同指纹只应有一条漏洞');
  });

  it('状态为终态(fixed)时再次命中 → resurfaced 并置回 open', async () => {
    const key = makeKey('it-resurface');
    const scanNo = nextScanNo();
    await createBatch(key, scanNo);
    await call('POST', `/ingest/scans/${scanNo}/vulnerabilities`, {
      key,
      body: { vulnerabilities: [VULN] },
    });

    const token = await adminToken();
    const found = await call('GET', `/vulnerabilities?ruleId=${VULN.ruleId}&keyword=${encodeURIComponent('SQL 拼接注入')}`, { token });
    const vulnId = found.body.data.list[0].id;

    const patched = await call('PATCH', `/vulnerabilities/${vulnId}/status`, {
      token,
      body: { status: 'fixed', comment: '集成测试' },
    });
    assert.equal(patched.body.data.status, 'fixed');
    assert.ok(patched.body.data.fixedAt, 'fixed 应写入 fixedAt');

    const scanNo2 = nextScanNo();
    await createBatch(key, scanNo2);
    const again = await call('POST', `/ingest/scans/${scanNo2}/vulnerabilities`, {
      key,
      body: { vulnerabilities: [VULN] },
    });
    assert.equal(again.body.data.resurfaced, 1, '终态漏洞再次命中应计入 resurfaced');

    const detail = await call('GET', `/vulnerabilities/${vulnId}`, { token });
    assert.equal(detail.body.data.status, 'open', '复现后应置回 open');
    assert.ok(
      detail.body.data.events.some((e) => e.action === 'resurfaced'),
      '应写入 resurfaced 事件',
    );
  });

  it('非终态状态不被上报覆盖', async () => {
    const key = makeKey('it-keepstatus');
    const scanNo = nextScanNo();
    await createBatch(key, scanNo);
    await call('POST', `/ingest/scans/${scanNo}/vulnerabilities`, {
      key,
      body: { vulnerabilities: [{ ...VULN, ruleId: 'it-rule-keep', filePath: 'src/Keep.java' }] },
    });

    const token = await adminToken();
    const found = await call('GET', '/vulnerabilities?ruleId=it-rule-keep', { token });
    const vulnId = found.body.data.list[0].id;
    await call('PATCH', `/vulnerabilities/${vulnId}/status`, {
      token,
      body: { status: 'confirmed' },
    });

    const scanNo2 = nextScanNo();
    await createBatch(key, scanNo2);
    await call('POST', `/ingest/scans/${scanNo2}/vulnerabilities`, {
      key,
      body: { vulnerabilities: [{ ...VULN, ruleId: 'it-rule-keep', filePath: 'src/Keep.java' }] },
    });

    const detail = await call('GET', `/vulnerabilities/${vulnId}`, { token });
    assert.equal(detail.body.data.status, 'confirmed', 'confirmed 不应被刷回 open');
    assert.equal(detail.body.data.occurrenceCount, 2, '命中次数应累加');
  });

  it('无效等级返回 40001 并指出字段', async () => {
    const key = makeKey('it-badsev');
    const scanNo = nextScanNo();
    await createBatch(key, scanNo);
    const r = await call('POST', `/ingest/scans/${scanNo}/vulnerabilities`, {
      key,
      body: { vulnerabilities: [{ ...VULN, severity: 'super-critical', ruleId: 'x1' }] },
    });
    assert.equal(r.status, 400);
    assert.equal(r.body.code, 40001);

    // 契约要求：data.errors[] 里给出字段与原因，扫描侧照着改数据即可
    const errText = JSON.stringify(r.body);
    assert.match(errText, /severity/, '应指出出错字段为 severity');
    assert.match(errText, /critical\/high\/medium\/low\/info/, '应给出合法取值提示');
  });

  it('缺少必填 ruleId 返回 40001', async () => {
    const key = makeKey('it-norule');
    const scanNo = nextScanNo();
    await createBatch(key, scanNo);
    const { ruleId, ...noRule } = VULN;
    const r = await call('POST', `/ingest/scans/${scanNo}/vulnerabilities`, {
      key,
      body: { vulnerabilities: [noRule] },
    });
    assert.equal(r.status, 400);
    assert.ok(r.body.data.errors[0].message.includes('ruleId'));
  });

  it('部分成功的语义：1 条合法 + 1 条非法 → code=0 且 skipped=1', async () => {
    const key = makeKey('it-partial');
    const scanNo = nextScanNo();
    await createBatch(key, scanNo);
    const r = await call('POST', `/ingest/scans/${scanNo}/vulnerabilities`, {
      key,
      body: {
        vulnerabilities: [
          { ...VULN, ruleId: 'it-partial-ok', filePath: 'src/Ok.java' },
          { ...VULN, ruleId: 'it-partial-bad', severity: 'nope' },
        ],
      },
    });
    assert.equal(r.body.code, 0);
    assert.equal(r.body.data.created, 1);
    assert.equal(r.body.data.skipped, 1);
    assert.equal(r.body.data.skippedItems.length, 1);
  });

  it('单批超过 500 条返回 40001', async () => {
    const key = makeKey('it-batch');
    const scanNo = nextScanNo();
    await createBatch(key, scanNo);
    const r = await call('POST', `/ingest/scans/${scanNo}/vulnerabilities`, {
      key,
      body: { vulnerabilities: Array.from({ length: 501 }, (_, i) => ({ ...VULN, externalVulnId: `B-${i}` })) },
    });
    assert.equal(r.status, 400);
    assert.equal(r.body.code, 40001);
  });

  it('已 complete 的批次继续上报返回 40004', async () => {
    const key = makeKey('it-closed');
    const scanNo = nextScanNo();
    await createBatch(key, scanNo);
    await call('POST', `/ingest/scans/${scanNo}/complete`, { key, body: { status: 'success' } });
    const r = await call('POST', `/ingest/scans/${scanNo}/vulnerabilities`, {
      key,
      body: { vulnerabilities: [{ ...VULN, ruleId: 'it-closed-rule' }] },
    });
    assert.equal(r.status, 400);
    assert.equal(r.body.code, 40004);
  });
});

describe('上报：样本与批次收尾', () => {
  it('样本按 (scanId,filePath,snippetHash) 幂等，正样本关联到漏洞', async () => {
    const key = makeKey('it-sample');
    const scanNo = nextScanNo();
    await createBatch(key, scanNo);
    await call('POST', `/ingest/scans/${scanNo}/vulnerabilities`, {
      key,
      body: { vulnerabilities: [{ ...VULN, ruleId: 'it-sample-rule', filePath: 'src/S.java' }] },
    });

    const samples = [
      {
        externalSampleId: 'S-1',
        label: 'positive',
        filePath: 'src/S.java',
        language: 'java',
        snippet: 'String sql = "..." + a;',
        externalVulnId: 'IT-1',
      },
      {
        externalSampleId: 'S-2',
        label: 'negative',
        filePath: 'src/Safe.java',
        language: 'java',
        snippet: 'class Safe {}',
      },
    ];

    const first = await call('POST', `/ingest/scans/${scanNo}/samples`, { key, body: { samples } });
    assert.equal(first.body.data.created, 2);
    assert.equal(first.body.data.positiveCount, 1);
    assert.equal(first.body.data.negativeCount, 1);

    const again = await call('POST', `/ingest/scans/${scanNo}/samples`, { key, body: { samples } });
    assert.equal(again.body.data.created, 0);
    assert.equal(again.body.data.duplicated, 2);

    const pos = db.get(
      `SELECT s.vuln_id, s.rule_id FROM samples s WHERE s.file_path = 'src/S.java'`,
    );
    assert.ok(pos.vuln_id, '正样本应关联到批次内已入库的漏洞');
    assert.equal(pos.rule_id, 'it-sample-rule', '样本的 rule_id 应从关联漏洞回填');
  });

  it('无效 label 的样本被跳过而非整体失败', async () => {
    const key = makeKey('it-badlabel');
    const scanNo = nextScanNo();
    await createBatch(key, scanNo);
    const r = await call('POST', `/ingest/scans/${scanNo}/samples`, {
      key,
      body: {
        samples: [
          { label: 'positive', filePath: 'a/ok.java', snippet: 'x' },
          { label: 'maybe', filePath: 'a/bad.java', snippet: 'y' },
        ],
      },
    });
    assert.equal(r.body.code, 0);
    assert.equal(r.body.data.created, 1);
  });

  it('complete 回写统计且重复调用幂等', async () => {
    const key = makeKey('it-complete');
    const scanNo = nextScanNo();
    await createBatch(key, scanNo);
    await call('POST', `/ingest/scans/${scanNo}/vulnerabilities`, {
      key,
      body: { vulnerabilities: [{ ...VULN, ruleId: 'it-complete-rule', filePath: 'src/C.java' }] },
    });
    await call('POST', `/ingest/scans/${scanNo}/samples`, {
      key,
      body: { samples: [{ label: 'negative', filePath: 'src/N.java', snippet: 'z' }] },
    });

    const done = await call('POST', `/ingest/scans/${scanNo}/complete`, {
      key,
      body: { status: 'success', totalFiles: 100, scannedFiles: 98 },
    });
    assert.equal(done.body.data.vulnCount, 1);
    assert.equal(done.body.data.sampleCount, 1);
    assert.equal(done.body.data.status, 'success');

    const doneAgain = await call('POST', `/ingest/scans/${scanNo}/complete`, {
      key,
      body: { status: 'success' },
    });
    assert.equal(doneAgain.body.code, 0, '重复 complete 应幂等成功');
    assert.equal(doneAgain.body.data.vulnCount, 1);
  });

  it('complete 不存在的批次返回 40400', async () => {
    const key = makeKey('it-noscan');
    const r = await call('POST', `/ingest/scans/does-not-exist/complete`, {
      key,
      body: { status: 'success' },
    });
    assert.equal(r.status, 404);
    assert.equal(r.body.code, 40400);
  });
});

describe('模式 B：一次性全量上报', () => {
  it('一个请求完成建批次 + 上报漏洞 + 样本 + 结束批次', async () => {
    const key = makeKey('it-full');
    const scanNo = nextScanNo();
    const r = await call('POST', '/ingest/report', {
      key,
      body: {
        scanNo,
        scanner: { name: 'integration', version: '1.0.0' },
        triggerType: 'push',
        scan: { repoType: 'gitlab', repoUrl: 'https://gitlab.test/full/repo', projectName: 'full-repo' },
        status: 'success',
        totalFiles: 50,
        scannedFiles: 50,
        vulnerabilities: [{ ...VULN, ruleId: 'it-full-rule', filePath: 'src/Full.java' }],
        samples: [
          { label: 'positive', filePath: 'src/Full.java', externalVulnId: 'IT-1', snippet: 'x' },
          { label: 'negative', filePath: 'src/FullSafe.java', snippet: 'y' },
        ],
      },
    });
    assert.equal(r.status, 201);
    assert.equal(r.body.data.result.vulnCreated, 1);
    assert.equal(r.body.data.result.sampleCreated, 2);
    assert.equal(r.body.data.result.positiveCount, 1);
    assert.equal(r.body.data.result.negativeCount, 1);

    const scan = db.get('SELECT status, vuln_count, sample_count FROM scan_tasks WHERE scan_no = ?', [scanNo]);
    assert.equal(scan.status, 'success', 'report 带 status 时应结束批次');
    assert.equal(scan.vuln_count, 1);
    assert.equal(scan.sample_count, 2);
  });
});

describe('查询与处置', () => {
  it('漏洞列表支持多条件筛选并返回 summary', async () => {
    const token = await adminToken();
    const r = await call('GET', '/vulnerabilities?severity=high&status=open&pageSize=5', { token });
    assert.equal(r.body.code, 0);
    assert.ok(Array.isArray(r.body.data.list));
    assert.ok(r.body.data.pagination.total >= 0);
    assert.ok('critical' in r.body.data.summary && 'high' in r.body.data.summary);
    for (const v of r.body.data.list) {
      assert.equal(v.severity, 'high');
      assert.equal(v.status, 'open');
    }
  });

  it('漏洞列表不返回 codeSnippet（体积大）', async () => {
    const token = await adminToken();
    const r = await call('GET', '/vulnerabilities?pageSize=1', { token });
    assert.equal(r.body.data.list[0].codeSnippet, undefined);
    assert.equal(r.body.data.list[0].description, undefined);
  });

  it('漏洞详情返回片段、位置与时间线', async () => {
    const token = await adminToken();
    const list = await call('GET', '/vulnerabilities?pageSize=1', { token });
    const id = list.body.data.list[0].id;
    const r = await call('GET', `/vulnerabilities/${id}`, { token });
    assert.equal(r.body.code, 0);
    assert.ok(r.body.data.location.codeSnippet !== undefined);
    assert.ok(Array.isArray(r.body.data.events));
    assert.ok(Array.isArray(r.body.data.samples));
    assert.ok(r.body.data.fingerprint.length === 64, '指纹应是 sha256 十六进制');
  });

  it('漏洞不存在返回 40400', async () => {
    const token = await adminToken();
    const r = await call('GET', '/vulnerabilities/99999999', { token });
    assert.equal(r.status, 404);
    assert.equal(r.body.code, 40400);
  });

  it('批量改状态返回 requested/updated/failed', async () => {
    const token = await adminToken();
    const list = await call('GET', '/vulnerabilities?pageSize=2', { token });
    const ids = list.body.data.list.map((v) => v.id);
    const r = await call('POST', '/vulnerabilities/batch-status', {
      token,
      body: { ids, status: 'ignored', comment: '集成测试批量' },
    });
    assert.equal(r.body.data.requested, ids.length);
    assert.equal(r.body.data.updated, ids.length);
    assert.equal(r.body.data.failed.length, 0);
  });

  it('指派与取消指派写入时间线', async () => {
    const token = await adminToken();
    const list = await call('GET', '/vulnerabilities?pageSize=1', { token });
    const id = list.body.data.list[0].id;

    const assign = await call('PATCH', `/vulnerabilities/${id}/assignee`, {
      token,
      body: { assignee: 1, comment: '集成测试指派' },
    });
    assert.equal(assign.body.data.assignee, 1);

    const unassign = await call('PATCH', `/vulnerabilities/${id}/assignee`, {
      token,
      body: { assignee: null },
    });
    assert.equal(unassign.body.data.assignee, null);

    const detail = await call('GET', `/vulnerabilities/${id}`, { token });
    assert.equal(detail.body.data.assignee, null);
    assert.ok(detail.body.data.events.filter((e) => e.action === 'assigned').length >= 2);
  });

  it('指派到不存在的用户返回 40001', async () => {
    const token = await adminToken();
    const list = await call('GET', '/vulnerabilities?pageSize=1', { token });
    const r = await call('PATCH', `/vulnerabilities/${list.body.data.list[0].id}/assignee`, {
      token,
      body: { assignee: 999999 },
    });
    assert.equal(r.status, 400);
    assert.equal(r.body.code, 40001);
  });

  it('新增备注写入 commented 事件', async () => {
    const token = await adminToken();
    const list = await call('GET', '/vulnerabilities?pageSize=1', { token });
    const id = list.body.data.list[0].id;
    const r = await call('POST', `/vulnerabilities/${id}/comments`, {
      token,
      body: { comment: '集成测试备注' },
    });
    assert.equal(r.status, 201);
    const detail = await call('GET', `/vulnerabilities/${id}`, { token });
    assert.ok(detail.body.data.events.some((e) => e.comment === '集成测试备注'));
  });

  it('导出 CSV 带表头与 BOM', async () => {
    const token = await adminToken();
    const res = await fetch(`${baseUrl}/vulnerabilities/export?severity=high`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type'), /text\/csv/);
    assert.match(res.headers.get('content-disposition') ?? '', /attachment; filename="vulnerabilities_.*\.csv"/);

    // 用字节判断 BOM，避免响应解码时被吞掉
    const buf = new Uint8Array(await res.arrayBuffer());
    assert.deepEqual(
      Array.from(buf.slice(0, 3)),
      [0xef, 0xbb, 0xbf],
      'CSV 应以 UTF-8 BOM（EF BB BF）开头，否则 Excel 打开中文会乱码',
    );
    const text = new TextDecoder('utf-8').decode(buf).replace(/^\uFEFF/, '');
    assert.match(text.split('\r\n')[0], /漏洞编号,标题,等级,状态,规则ID,规则名/);
    assert.ok(text.split('\r\n').length > 1, '应有数据行');
  });
});

describe('统计口径', () => {
  it('overview 的 vulnOpen 等于 open+confirmed+fixing', async () => {
    const token = await adminToken();
    const ov = await call('GET', '/stats/overview?days=365', { token });
    const st = await call('GET', '/stats/status', { token });
    const map = Object.fromEntries(st.body.data.list.map((x) => [x.status, x.count]));
    const expected = (map.open ?? 0) + (map.confirmed ?? 0) + (map.fixing ?? 0);
    assert.equal(ov.body.data.vulnOpen, expected);
  });

  it('overview 的 vulnTotal 不含误报与已忽略', async () => {
    const token = await adminToken();
    const ov = await call('GET', '/stats/overview', { token });
    const st = await call('GET', '/stats/status', { token });
    const map = Object.fromEntries(st.body.data.list.map((x) => [x.status, x.count]));
    const all = Object.values(map).reduce((a, b) => a + b, 0);
    assert.equal(ov.body.data.vulnTotal, all - (map.false_positive ?? 0) - (map.ignored ?? 0));
  });

  it('severity 分布的总和与漏洞总数一致', async () => {
    const token = await adminToken();
    const sev = await call('GET', '/stats/severity', { token });
    const ov = await call('GET', '/stats/overview', { token });
    const sum = sev.body.data.list.reduce((a, b) => a + b.count, 0);
    assert.equal(sum, ov.body.data.vulnTotal);
  });

  it('trend 返回请求天数个点且字段完整', async () => {
    const token = await adminToken();
    const r = await call('GET', '/stats/trend?days=14', { token });
    assert.equal(r.body.data.list.length, 14);
    for (const p of r.body.data.list) {
      assert.match(p.date, /^\d{4}-\d{2}-\d{2}$/);
      assert.equal(typeof p.newCount, 'number');
      assert.equal(typeof p.fixedCount, 'number');
      assert.ok(p.openCount >= 0);
    }
  });

  it('top-rules / top-projects 按数量倒序', async () => {
    const token = await adminToken();
    const rules = await call('GET', '/stats/top-rules?limit=5', { token });
    const counts = rules.body.data.list.map((r) => r.count);
    assert.deepEqual(counts, [...counts].sort((a, b) => b - a));
    const projs = await call('GET', '/stats/top-projects?limit=5', { token });
    const opens = projs.body.data.list.map((p) => p.vulnOpen);
    assert.deepEqual(opens, [...opens].sort((a, b) => b - a));
  });
});

describe('项目与扫描记录', () => {
  it('项目列表带统计并支持按关键字筛选', async () => {
    const token = await adminToken();
    const r = await call('GET', '/projects?keyword=integration', { token });
    assert.equal(r.body.code, 0);
    const p = r.body.data.list[0];
    assert.ok(p.stats.scanCount >= 1);
    assert.equal(typeof p.stats.vulnTotal, 'number');
  });

  it('新建项目后按 (repoType,repoUrl) 唯一，重复创建返回 40900', async () => {
    const token = await adminToken();
    const body = {
      name: 'dup-check',
      repoType: 'github',
      repoUrl: 'https://github.com/test/dup-check',
    };
    const a = await call('POST', '/projects', { token, body });
    assert.equal(a.status, 201);
    const b = await call('POST', '/projects', { token, body });
    assert.equal(b.status, 409);
    assert.equal(b.body.code, 40900);
  });

  it('扫描记录可按状态筛选，批次详情含等级分布', async () => {
    const token = await adminToken();
    const list = await call('GET', '/scans?status=success&pageSize=5', { token });
    assert.equal(list.body.code, 0);
    for (const s of list.body.data.list) assert.equal(s.status, 'success');
    if (list.body.data.list.length) {
      const scanNo = list.body.data.list[0].scanNo;
      const detail = await call('GET', `/scans/${encodeURIComponent(scanNo)}`, { token });
      assert.equal(detail.body.code, 0);
      assert.ok(detail.body.data.vulnSummary);
      assert.ok(Array.isArray(detail.body.data.topRules));
    }
  });

  it('样本库支持按 label 筛选并返回 summary', async () => {
    const token = await adminToken();
    const r = await call('GET', '/samples?label=negative&pageSize=5', { token });
    assert.equal(r.body.code, 0);
    for (const s of r.body.data.list) assert.equal(s.label, 'negative');
    assert.equal(typeof r.body.data.summary.positive, 'number');
  });

  it('样本详情返回完整片段与哈希', async () => {
    const token = await adminToken();
    const list = await call('GET', '/samples?pageSize=1', { token });
    const id = list.body.data.list[0].id;
    const r = await call('GET', `/samples/${id}`, { token });
    assert.equal(r.body.data.snippetHash.length, 64);
    assert.ok('snippet' in r.body.data);
  });
});

describe('API Key 管理', () => {
  it('创建返回明文一次，列表只返回掩码', async () => {
    const token = await adminToken();
    const created = await call('POST', '/api-keys', {
      token,
      body: { name: 'it-managed', scopes: ['ingest'] },
    });
    assert.equal(created.status, 201);
    assert.match(created.body.data.apiKey, /^vuln_sk_[a-f0-9]{32}$/);

    const list = await call('GET', '/api-keys?pageSize=50', { token });
    const item = list.body.data.list.find((k) => k.id === created.body.data.id);
    assert.ok(item.maskedKey.includes('****'));
    assert.equal(item.apiKey, undefined, '列表不应返回明文');
  });

  it('吊销后该 Key 立即失效，恢复后可用', async () => {
    const token = await adminToken();
    const created = await call('POST', '/api-keys', { token, body: { name: 'it-revoke' } });
    const plain = created.body.data.apiKey;
    const id = created.body.data.id;

    assert.equal((await call('GET', '/ingest/ping', { key: plain })).body.code, 0);

    const revoke = await call('DELETE', `/api-keys/${id}`, { token });
    assert.deepEqual(revoke.body.data, { id, status: 0 });
    assert.equal((await call('GET', '/ingest/ping', { key: plain })).body.code, 40101);

    const restore = await call('POST', `/api-keys/${id}/restore`, { token });
    assert.deepEqual(restore.body.data, { id, status: 1 });
    assert.equal((await call('GET', '/ingest/ping', { key: plain })).body.code, 0);
  });
});

describe('权限（角色矩阵）', () => {
  async function tokenFor(username, password) {
    const r = await call('POST', '/auth/login', { body: { username, password } });
    assert.equal(r.body.code, 0, `${username} 应能登录`);
    return r.body.data.accessToken;
  }

  before(async () => {
    const token = await adminToken();
    for (const u of [
      { username: 'it-auditor', role: 'auditor' },
      { username: 'it-viewer', role: 'viewer' },
    ]) {
      await call('POST', '/users', {
        token,
        body: { username: u.username, password: 'Test@12345', role: u.role, displayName: u.username },
      });
    }
  });

  it('viewer 可查看漏洞但不能改状态（40300）', async () => {
    const token = await tokenFor('it-viewer', 'Test@12345');
    const list = await call('GET', '/vulnerabilities?pageSize=1', { token });
    assert.equal(list.body.code, 0);

    const patch = await call('PATCH', `/vulnerabilities/${list.body.data.list[0].id}/status`, {
      token,
      body: { status: 'fixed' },
    });
    assert.equal(patch.status, 403);
    assert.equal(patch.body.code, 40300);
  });

  it('viewer 看不到 API Key 与用户管理（40300）', async () => {
    const token = await tokenFor('it-viewer', 'Test@12345');
    assert.equal((await call('GET', '/api-keys', { token })).body.code, 40300);
    assert.equal((await call('GET', '/users', { token })).body.code, 40300);
  });

  it('auditor 可改漏洞状态，但不能管 Key', async () => {
    const token = await tokenFor('it-auditor', 'Test@12345');
    const list = await call('GET', '/vulnerabilities?pageSize=1', { token });
    const patch = await call('PATCH', `/vulnerabilities/${list.body.data.list[0].id}/status`, {
      token,
      body: { status: 'confirmed', comment: '审计员操作' },
    });
    assert.equal(patch.body.code, 0);
    assert.equal((await call('GET', '/api-keys', { token })).body.code, 40300);
  });

  it('auditor 可导出报表', async () => {
    const token = await tokenFor('it-auditor', 'Test@12345');
    const res = await fetch(`${baseUrl}/vulnerabilities/export`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 200);
  });
});

describe('修改密码', () => {
  it('旧密码错误返回 40002，弱密码返回 40003，成功后新密码可登录', async () => {
    const token = await adminToken();
    const created = await call('POST', '/users', {
      token,
      body: { username: 'it-pwd', password: 'Test@12345', role: 'viewer' },
    });
    assert.equal(created.status, 201);

    const login1 = await call('POST', '/auth/login', {
      body: { username: 'it-pwd', password: 'Test@12345' },
    });
    const t = login1.body.data.accessToken;

    const wrongOld = await call('POST', '/auth/change-password', {
      token: t,
      body: { oldPassword: 'WrongOld@1', newPassword: 'NewPass@123' },
    });
    assert.equal(wrongOld.body.code, 40002);

    const weak = await call('POST', '/auth/change-password', {
      token: t,
      body: { oldPassword: 'Test@12345', newPassword: 'aaaaaaaa' },
    });
    assert.equal(weak.body.code, 40003);

    const okChange = await call('POST', '/auth/change-password', {
      token: t,
      body: { oldPassword: 'Test@12345', newPassword: 'NewPass@123' },
    });
    assert.equal(okChange.body.code, 0);

    const login2 = await call('POST', '/auth/login', {
      body: { username: 'it-pwd', password: 'NewPass@123' },
    });
    assert.equal(login2.body.code, 0, '改密后应能用新密码登录');
  });

  it('登录失败不泄露账号是否存在（统一 40100）', async () => {
    const noUser = await call('POST', '/auth/login', {
      body: { username: 'no-such-user-xyz', password: 'whatever' },
    });
    const badPwd = await call('POST', '/auth/login', {
      body: { username: 'admin', password: 'definitely-wrong' },
    });
    assert.equal(noUser.body.code, 40100);
    assert.equal(badPwd.body.code, 40100);
    assert.equal(noUser.body.message, badPwd.body.message);
  });
});

describe('模型检测模块', () => {
  it('/ml/status 在模型服务离线时也返回结构完整的响应', async () => {
    const token = await adminToken();
    const r = await call('GET', '/ml/status', { token });
    assert.equal(r.body.code, 0);
    assert.equal(typeof r.body.data.online, 'boolean');
    assert.ok(r.body.data.url);
    assert.ok(r.body.data.checkedAt);
  });

  it('/ml/detect 在模型离线时降级，且明确标记 degraded', async () => {
    const token = await adminToken();
    const r = await call('POST', '/ml/detect', {
      token,
      body: {
        code: 'void f(char *s){ char b[10]; strcpy(b, s); }',
        mode: 'auto',
        threshold: 0.5,
      },
    });
    assert.equal(r.body.code, 0);
    const d = r.body.data;
    // 契约：降级时必须自曝，不能冒充模型输出
    if (d.degraded) {
      assert.equal(d.modelServed, false);
      assert.ok(d.degradedReason, '降级必须给出原因');
      assert.ok(d.verdict === 'vulnerable' || d.verdict === 'safe');
    } else {
      assert.equal(d.modelServed, true);
    }
    assert.equal(typeof d.latencyMs, 'number');
    assert.ok(Array.isArray(d.topCwe));
  });

  it('/ml/detect 空代码返回 40001', async () => {
    const token = await adminToken();
    const r = await call('POST', '/ml/detect', { token, body: { code: '' } });
    assert.equal(r.status, 400);
    assert.equal(r.body.code, 40001);
  });

  it('/ml/analyze 把判定结果落库为批次与样本', async () => {
    const token = await adminToken();
    const r = await call('POST', '/ml/analyze', {
      token,
      body: {
        code: 'def ping(host):\n    return os.popen("ping -c 1 " + host).read()',
        mode: 'auto',
        filePath: 'it/ml_analyze.py',
        language: 'python',
        title: '集成测试：模型检测归档',
      },
    });
    assert.equal(r.body.code, 0);
    const { scan, result } = r.body.data;
    assert.ok(scan.scanId > 0);
    assert.match(scan.scanNo, /^ml-detect-/);

    const dbScan = db.get('SELECT status, vuln_count, sample_count FROM scan_tasks WHERE id = ?', [scan.scanId]);
    assert.equal(dbScan.status, 'success');
    assert.equal(Number(dbScan.sample_count), 1, '被检测代码应沉淀为 1 条样本');

    if (result.verdict === 'vulnerable') {
      assert.equal(Number(dbScan.vuln_count), 1, '判定为漏洞时应建 1 条漏洞记录');
      assert.equal(scan.positiveSamples, 1);
    } else {
      assert.equal(Number(dbScan.vuln_count), 0);
      assert.equal(scan.negativeSamples, 1);
    }
  });
});

describe('错误处理与响应格式', () => {
  it('未知接口返回 40400 且带 traceId', async () => {
    const token = await adminToken();
    const r = await call('GET', '/no-such-endpoint', { token });
    assert.equal(r.status, 404);
    assert.equal(r.body.code, 40400);
    assert.ok(r.body.traceId, '响应应带 traceId');
  });

  it('响应回传 X-Trace-Id 头，且可用请求头指定', async () => {
    const res = await fetch(`${baseUrl}/ingest/ping`, {
      headers: { 'X-API-Key': makeKey('it-trace'), 'X-Trace-Id': 'my-trace-123' },
    });
    assert.equal(res.headers.get('x-trace-id'), 'my-trace-123');
    assert.equal((await res.json()).traceId, 'my-trace-123');
  });

  it('非法 JSON 返回 40001', async () => {
    const res = await fetch(`${baseUrl}/ingest/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': makeKey('it-badjson') },
      body: '{ this is not json',
    });
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.code, 40001);
  });

  it('统一响应结构包含 code/message/data/traceId', async () => {
    const key = makeKey('it-shape');
    const r = await call('GET', '/ingest/ping', { key });
    for (const f of ['code', 'message', 'data', 'traceId']) {
      assert.ok(f in r.body, `响应应包含 ${f}`);
    }
  });
});

describe('限流', () => {
  it('登录限流：同一 IP 第 11 次返回 42902；不同 IP 互不影响', async () => {
    const { loginRateLimit, setRateLimitDisabled } = await import('../src/core/rateLimit.ts');
    // 测试套件默认关闭限流，这里显式打开来验证限流本身
    setRateLimitDisabled(false);

    const res = () => {
      const state = { status: 0, body: null, headers: {} };
      return {
        // reject() 会写 res.locals.traceId，mock 里必须有
        locals: { traceId: 'test-trace' },
        status(code) {
          state.status = code;
          return this;
        },
        setHeader(k, v) {
          state.headers[k] = v;
        },
        json(payload) {
          state.body = payload;
          return this;
        },
        get state() {
          return state;
        },
      };
    };
    const req = (ip) => ({ header: (n) => (n === 'X-Forwarded-For' ? ip : undefined), ip, socket: {} });
    let called = 0;
    const next = () => {
      called += 1;
    };

    // 契约：登录 10 次/分钟 / IP
    let lastStatus = 0;
    for (let i = 0; i < 10; i += 1) {
      const r = res();
      loginRateLimit(req('10.1.1.1'), r, next);
      lastStatus = r.state.status;
    }
    assert.equal(lastStatus, 0, '前 10 次不应被拒');
    assert.equal(called, 10);

    const blocked = res();
    loginRateLimit(req('10.1.1.1'), blocked, next);
    assert.equal(blocked.state.status, 429);
    assert.equal(blocked.state.body.code, 42902);
    assert.ok(blocked.state.headers['Retry-After'], '应返回 Retry-After 头');

    // 另一个 IP 不受影响
    const other = res();
    loginRateLimit(req('10.2.2.2'), other, next);
    assert.equal(other.state.status, 0, '不同 IP 的计数应独立');

    // 还原，避免影响其它用例
    setRateLimitDisabled(true);
  });
});
