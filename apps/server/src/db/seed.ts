/**
 * 初始化数据：
 *  1. 默认管理员（来自 config.admin，密码 bcrypt 存储）
 *  2. 演示用户 / 项目 / 扫描批次 / 漏洞 / 正负样本 / 时间线
 *
 * 重要设计：演示数据不是手写 INSERT 拼出来的，而是**调用与生产完全相同的 ingest 服务**
 * （createScan → ingestVulnerabilities → ingestSamples → completeScan）。
 * 这样演示库里的指纹、去重、状态流转、命中次数、复现（resurfaced）语义
 * 与扫描工具真实上报时一模一样，看板数字才可信。
 *
 * 仅首次启动灌入（幂等），并由 meta 表记录。
 */
import bcrypt from 'bcryptjs';
import type { Db } from './index.js';
import { getMeta, setMeta, tableCount } from './index.js';
import {
  DEFAULT_USER_PASSWORD,
  DEMO_USERS,
  PROJECT_CATALOG,
  RULE_CATALOG,
} from './seedData.js';
import { apiKeyHash, shortId } from '../services/fingerprint.js';
import {
  completeScan,
  createScan,
  ingestSamples,
  ingestVulnerabilities,
} from '../modules/ingest/service.js';

const BCRYPT_ROUNDS = 10;

// ------------------------------------------------------------------ 工具
/** 确定性伪随机（mulberry32），保证每次灌种子得到一致的看板曲线 */
function makeRng(seed: number) {
  let a = seed >>> 0;
  return function rng(): number {
    a += 0x6d2b79f5;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const pick = <T>(rng: () => number, arr: readonly T[]): T => arr[Math.floor(rng() * arr.length)]!;
const randInt = (rng: () => number, min: number, max: number): number =>
  Math.floor(rng() * (max - min + 1)) + min;

function iso(d: Date): string {
  return d.toISOString();
}

function daysAgo(n: number, hour = 9, minute = 0): Date {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - n);
  d.setUTCHours(hour, minute, 0, 0);
  return d;
}

// ------------------------------------------------------------ 用户 / 管理员
export function seedAdminUser(db: Db, username: string, password: string): void {
  const existing = db.get<{ id: number }>(`SELECT id FROM users WHERE username = ?`, [username]);
  if (existing) return;
  const now = iso(new Date());
  db.run(
    `INSERT INTO users(username, password_hash, display_name, email, role, status, created_at, updated_at)
     VALUES(?, ?, ?, ?, 'admin', 1, ?, ?)`,
    [username, bcrypt.hashSync(password, BCRYPT_ROUNDS), '系统管理员', 'admin@example.com', now, now],
  );
}

function seedDemoUsers(db: Db): Map<string, number> {
  const now = iso(new Date());
  const ids = new Map<string, number>();
  const admin = db.get<{ id: number }>(`SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1`);
  if (admin) ids.set('admin', admin.id);

  const hash = bcrypt.hashSync(DEFAULT_USER_PASSWORD, BCRYPT_ROUNDS);
  for (const u of DEMO_USERS) {
    const row = db.get<{ id: number }>(`SELECT id FROM users WHERE username = ?`, [u.username]);
    if (row) {
      ids.set(u.username, row.id);
      continue;
    }
    const r = db.run(
      `INSERT INTO users(username, password_hash, display_name, email, role, status, created_at, updated_at)
       VALUES(?, ?, ?, ?, ?, 1, ?, ?)`,
      [u.username, hash, u.displayName, u.email, u.role, now, now],
    );
    ids.set(u.username, r.lastInsertRowid);
  }
  return ids;
}

// ---------------------------------------------------------------- 演示数据
/**
 * 环境变量 SCALE 可放大数据量，便于压测看板与列表分页：
 *   SCALE=3 pnpm -C apps/server db:reset
 */
const SCALE = Math.max(1, Number(process.env.SEED_SCALE ?? 1) || 1);

export function seedDemoDataIfEmpty(db: Db): { seeded: boolean; reason: string } {
  if (getMeta(db, 'demo_seeded') === 'true') return { seeded: false, reason: 'already-seeded' };
  if (tableCount(db, 'projects') > 0 || tableCount(db, 'vulnerabilities') > 0) {
    setMeta(db, 'demo_seeded', 'true');
    return { seeded: false, reason: 'data-exists' };
  }

  const rng = makeRng(20250101);
  const userMap = seedDemoUsers(db);
  const assigneeIds = [...userMap.entries()]
    .filter(([name]) => name !== 'viewer' && name !== 'admin')
    .map(([, id]) => id);

  const COMMIT_MESSAGES = [
    'fix: 修复登录逻辑的空指针',
    'feat: 新增订单导出接口',
    'refactor: 抽离鉴权中间件',
    'chore: 升级依赖版本',
    'fix: 处理上传文件重名问题',
    'perf: 优化列表查询索引',
    'feat: 支持批量导入用户',
  ];
  const AUTHORS = ['zhangsan', 'lisi', 'wangwu', 'zhaoliu', 'sunqi', 'zhouba'];

  let totalScans = 0;
  let totalNewVulns = 0;
  let totalPositive = 0;
  let totalNegative = 0;

  db.tx(() => {
    PROJECT_CATALOG.forEach((p, pIdx) => {
      const projectCreatedAt = daysAgo(120, 8);
      const projectRes = db.run(
        `INSERT INTO projects(name, repo_type, repo_url, repo_full_name, default_branch, owner, description, status, created_at, updated_at)
         VALUES(?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
        [
          p.name,
          p.repoType,
          p.repoUrl,
          p.repoFullName,
          p.defaultBranch,
          p.owner,
          p.description,
          iso(projectCreatedAt),
          iso(projectCreatedAt),
        ],
      );
      const projectId = projectRes.lastInsertRowid;

      // 本项目的扫描时间点：均匀铺满最近 88 天（老 → 新）。
      // 必须均匀，否则看板的趋势曲线会出现「前 29 天全是 0、最后一天暴涨」的假象。
      const mode = (pIdx % 3) as 0 | 1 | 2;
      const spanPerScan = 4 + mode * 3; // 本项目每次扫描之间间隔 4~10 天
      const newestOffset = 1 + (pIdx % 5); // 最新一批落在 1~5 天前
      const scanCount = Math.min(16, Math.floor((88 - newestOffset) / spanPerScan) + 1) * SCALE;
      const offsets: number[] = [];
      for (let i = 0; i < scanCount; i += 1) {
        const o = newestOffset + i * spanPerScan;
        if (o > 88) break;
        offsets.push(o);
      }
      offsets.sort((a, b) => b - a); // 老 → 新

      /**
       * 本项目每个 (ruleId, filePath) 对应的漏洞 ID 与状态。
       * 键必须是 ruleId + filePath —— 指纹就是这两者加片段算出来的，
       * 只用 ruleId 做键会把「同规则不同文件」误判成同一条漏洞。
       */
      const known = new Map<string, { vulnId: number | null; status: string }>();

      offsets.forEach((offset) => {
        const isLatest = offset === offsets[offsets.length - 1];
        const startedAt = daysAgo(offset, randInt(rng, 1, 20), randInt(rng, 0, 59));
        const durationMs = randInt(rng, 45_000, 480_000);
        const finishedAt = new Date(startedAt.getTime() + durationMs);
        const totalFiles = randInt(rng, 600, 4200);
        const scannedFiles = Math.max(1, totalFiles - randInt(rng, 0, 15));

        let status: 'running' | 'success' | 'failed' | 'partial' = 'success';
        const roll = rng();
        if (roll < 0.06) status = 'failed';
        else if (roll < 0.15) status = 'partial';
        // 只允许最近一批处于 running，模拟「扫描进行中」
        if (isLatest && rng() < 0.35) status = 'running';

        const commitId = shortId(40);
        const scanNo = `${p.repoType === 'github' ? 'gh' : 'gl'}-${p.name}-${iso(startedAt)
          .slice(0, 10)
          .replace(/-/g, '')}-${commitId.slice(0, 7)}`;

        const scanRef = createScan(db, {
          scanNo,
          scanner: { name: 'ScanMan', version: `1.${randInt(rng, 0, 4)}.${randInt(rng, 0, 9)}` },
          triggerType: pick(rng, ['push', 'push', 'push', 'merge_request', 'schedule', 'manual'] as const),
          scan: {
            repoType: p.repoType,
            repoUrl: p.repoUrl,
            repoFullName: p.repoFullName,
            projectName: p.name,
            branch: p.defaultBranch,
            commitId,
            commitMessage: pick(rng, COMMIT_MESSAGES),
            commitAuthor: pick(rng, AUTHORS),
            commitTime: iso(new Date(startedAt.getTime() - 180_000)),
          },
          startedAt: iso(startedAt),
          totalFiles,
        });
        if (scanRef.projectId !== projectId) {
          // 理论上不会发生（项目地址唯一）；发生时以库中解析结果为准
          db.run(`UPDATE scan_tasks SET project_id = ? WHERE id = ?`, [projectId, scanRef.scanId]);
        }
        totalScans += 1;

        // ---------- 漏洞 ----------
        // 每轮命中 3~9 条规则。历史命中的继续命中（模拟未修复或复现），
        // 少量新规则在后续批次首次出现（模拟新代码引入新问题）。
        const hitRules = RULE_CATALOG.filter(() => rng() < 0.45).slice(
          0,
          Math.min(RULE_CATALOG.length, randInt(rng, 3, 9)),
        );
        // 保证至少 3 条
        if (hitRules.length < 3) {
          hitRules.push(...RULE_CATALOG.slice(0, 3 - hitRules.length));
        }

        const vulnItems: Array<Record<string, unknown>> = [];
        const newKeys = new Set<string>();

        for (const rule of hitRules) {
          const key = `${rule.ruleId}|${rule.filePath}`;
          const isNew = !known.has(key);
          if (isNew) newKeys.add(key);

          // 已存在的漏洞：如果上一轮是终态，按概率复现（复现后状态由服务置回 open）
          if (!isNew && !isLatest) {
            const prev = known.get(key)!;
            if (['fixed', 'ignored', 'false_positive'].includes(prev.status) && rng() < 0.25) {
              prev.status = 'open';
            }
          }

          vulnItems.push({
            externalVulnId: `P${pIdx}-${rule.ruleId}`,
            ruleId: rule.ruleId,
            ruleName: rule.ruleName,
            title: rule.title,
            severity: rule.severity,
            category: rule.category,
            cwe: rule.cwe,
            language: rule.language,
            filePath: rule.filePath,
            lineStart: randInt(rng, 10, 480),
            codeSnippet: rule.snippet,
            description: rule.description,
            suggestion: rule.suggestion,
            confidence: Math.round((0.62 + rng() * 0.37) * 1000) / 1000,
          });
        }

        const vulnSummary = ingestVulnerabilities(
          db,
          { scanId: scanRef.scanId, projectId, scanNo: scanRef.scanNo },
          vulnItems,
        );
        totalNewVulns += vulnSummary.created;

        // 把服务处理结果同步进 known，并给「新漏洞」按发现时间补一个合理状态
        for (const detail of vulnSummary.details) {
          if (detail.result === 'skipped') continue;
          const item = vulnItems[detail.index] as { ruleId: string; filePath: string };
          const key = `${item.ruleId}|${item.filePath}`;
          const prev = known.get(key);
          if (prev) {
            known.set(key, { vulnId: detail.vulnId, status: prev.status });
            continue;
          }

          // 新漏洞：越早发现越可能已处置；近期的也保留一定修复率，
          // 否则「平均修复时长 / 近 30 天修复数」会全是 0，看板不真实。
          let vStatus = 'open';
          const sr = rng();
          if (offset > 45) {
            if (sr < 0.55) vStatus = 'fixed';
            else if (sr < 0.66) vStatus = 'ignored';
            else if (sr < 0.73) vStatus = 'false_positive';
            else if (sr < 0.85) vStatus = 'fixing';
            else vStatus = 'open';
          } else if (offset > 15) {
            if (sr < 0.4) vStatus = 'fixed';
            else if (sr < 0.53) vStatus = 'fixing';
            else if (sr < 0.65) vStatus = 'confirmed';
            else if (sr < 0.7) vStatus = 'false_positive';
            else vStatus = 'open';
          } else {
            if (sr < 0.22) vStatus = 'fixed';
            else if (sr < 0.35) vStatus = 'fixing';
            else if (sr < 0.5) vStatus = 'confirmed';
            else if (sr < 0.55) vStatus = 'ignored';
            else vStatus = 'open';
          }

          const discoveredAt = iso(startedAt);
          const assignee =
            ['open', 'confirmed', 'fixing'].includes(vStatus) && rng() < 0.72 && assigneeIds.length
              ? pick(rng, assigneeIds)
              : null;
          const fixedAt =
            vStatus === 'fixed'
              ? iso(new Date(startedAt.getTime() + randInt(rng, 2, 240) * 3600_000))
              : null;

          db.run(
            `UPDATE vulnerabilities
                SET status = ?, assignee = ?, fixed_at = ?, first_found_at = ?, last_found_at = ?,
                    created_at = ?, updated_at = ?
              WHERE id = ?`,
            [vStatus, assignee, fixedAt, discoveredAt, discoveredAt, discoveredAt, discoveredAt, detail.vulnId],
          );
          known.set(key, { vulnId: detail.vulnId, status: vStatus });

          // 时间线补一条状态变更，让详情的处置时间线看起来真实
          if (vStatus !== 'open') {
            db.run(
              `INSERT INTO vuln_events(vuln_id, action, from_value, to_value, operator_id, operator_name, comment, created_at)
               VALUES(?, 'status_changed', 'open', ?, ?, ?, ?, ?)`,
              [
                detail.vulnId,
                vStatus,
                assignee,
                assignee ? '李四' : 'system',
                vStatus === 'fixed'
                  ? '已合并修复 PR'
                  : vStatus === 'false_positive'
                    ? '与开发确认为误报'
                    : vStatus === 'ignored'
                      ? '存量代码，接受风险'
                      : '已确认并排期修复',
                iso(new Date(startedAt.getTime() + randInt(rng, 1, 72) * 3600_000)),
              ],
            );
          }
        }

        // ---------- 正负样本 ----------
        const sampleItems: Array<Record<string, unknown>> = [];

        // 正样本：有漏洞的代码片段（只上报本批次命中过的，且不是每次都全量上报）
        for (const rule of hitRules) {
          if (rng() < 0.3) continue;
          sampleItems.push({
            externalSampleId: `S-P-${shortId(8)}`,
            label: 'positive',
            filePath: rule.filePath,
            language: rule.language,
            lineStart: 1,
            lineEnd: rule.snippet.split('\n').length,
            snippet: rule.snippet,
            externalVulnId: `P${pIdx}-${rule.ruleId}`,
          });
        }

        // 负样本：扫描过但无漏洞的文件
        const negativeTarget = Math.min(
          320,
          Math.max(20, Math.round(scannedFiles * (isLatest ? 0.05 : 0.025) * SCALE)),
        );
        for (let i = 0; i < negativeTarget; i += 1) {
          const lang = pick(rng, ['java', 'javascript', 'python', 'go', 'c', 'php'] as const);
          const folder = pick(rng, ['service', 'util', 'model', 'handler', 'config', 'common'] as const);
          const ext = lang === 'javascript' ? 'js' : lang;
          const filePath = `src/${lang}/${folder}/Module${randInt(rng, 1, 400)}.${ext}`;
          const snippet = [
            `// ${filePath} —— ScanMan 扫描判定为无漏洞的样本`,
            `package ${folder};`,
            ``,
            `public class Module${randInt(rng, 1, 999)} {`,
            `  private String name;`,
            `  public String getName() { return this.name; }`,
            `}`,
          ].join('\n');
          sampleItems.push({
            externalSampleId: `S-N-${shortId(8)}`,
            label: 'negative',
            filePath,
            language: lang,
            lineStart: 1,
            lineEnd: snippet.split('\n').length,
            snippet,
          });
        }

        const sampleSummary = ingestSamples(
          db,
          { scanId: scanRef.scanId, projectId, scanNo: scanRef.scanNo },
          sampleItems,
        );
        totalPositive += sampleSummary.positiveCount;
        totalNegative += sampleSummary.negativeCount;

        // ---------- 结束批次 ----------
        completeScan(db, scanRef.scanNo, {
          status: status === 'running' ? 'partial' : status,
          finishedAt: iso(finishedAt),
          totalFiles,
          scannedFiles: status === 'running' ? 0 : scannedFiles,
          errorMessage: status === 'failed' ? '扫描进程被 OOM Killer 终止（exit code 137）' : null,
        });
        // running 只是「进行中」的展示态，这里保留 running 便于前端展示进度条
        if (status === 'running') {
          db.run(
            `UPDATE scan_tasks SET status = 'running', finished_at = NULL, scanned_files = ?, error_message = NULL WHERE id = ?`,
            [Math.round(scannedFiles * 0.6), scanRef.scanId],
          );
        }
      });

      db.run(`UPDATE projects SET updated_at = ? WHERE id = ?`, [iso(new Date()), projectId]);
    });
  });

  // 演示用 API Key（明文固定，方便扫描侧 / Postman 直接联调）
  seedDemoApiKey(db, userMap.get('admin') ?? null);

  setMeta(db, 'demo_seeded', 'true');
  console.log(
    `  演示数据：批次 ${totalScans} · 新增漏洞 ${totalNewVulns} · 正样本 ${totalPositive} · 负样本 ${totalNegative}`,
  );
  return { seeded: true, reason: 'ok' };
}

function seedDemoApiKey(db: Db, createdBy: number | null): void {
  const demoKey = 'vuln_sk_demo00000000000000000000000001';
  const hash = apiKeyHash(demoKey);
  const exists = db.get<{ id: number }>(`SELECT id FROM api_keys WHERE key_hash = ?`, [hash]);
  if (exists) return;
  const now = iso(new Date());
  db.run(
    `INSERT INTO api_keys(name, key_prefix, key_hash, scopes, repo_scope, expires_at, status, created_by, created_at, updated_at)
     VALUES(?, ?, ?, 'ingest', NULL, NULL, 1, ?, ?, ?)`,
    ['demo-scanner-key（演示用，勿用于生产）', demoKey.slice(0, 12), hash, createdBy, now, now],
  );
}
