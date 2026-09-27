import { LIMITS, type RepoType, type SampleLabel, type Severity } from '@vuln/shared';
import type { Db } from '../../db/index.js';
import { AppError } from '../../core/errors.js';
import { vulnerabilityFingerprint, snippetHash } from '../../services/fingerprint.js';
import { vulnerabilityItemSchema, sampleItemSchema } from './schema.js';

// ------------------------------------------------------------------ 类型
export interface ProjectRef {
  id: number;
  created: boolean;
  name: string;
}

export interface ScanRef {
  scanId: number;
  scanNo: string;
  projectId: number;
  projectCreated: boolean;
  status: string;
  duplicated: boolean;
  createdAt: string;
}

export type VulnIngestResult = 'created' | 'updated' | 'resurfaced' | 'skipped';

export interface VulnIngestDetail {
  index: number;
  externalVulnId: string | null;
  vulnId: number | null;
  vulnNo: string | null;
  fingerprint: string | null;
  result: VulnIngestResult;
}

export interface VulnIngestSummary {
  received: number;
  created: number;
  updated: number;
  resurfaced: number;
  skipped: number;
  details: VulnIngestDetail[];
  skippedItems: Array<{ index: number; externalVulnId: string | null; reason: string }>;
}

export interface SampleIngestSummary {
  received: number;
  created: number;
  duplicated: number;
  truncated: number;
  positiveCount: number;
  negativeCount: number;
}

// --------------------------------------------------------------- 项目解析
interface ProjectRow {
  id: number;
  name: string;
  repo_type: RepoType;
  repo_url: string;
}

/** 平台以 (repoType, repoUrl) 唯一标识项目；不存在则自动创建 */
export function resolveProject(
  db: Db,
  scan: Nullable<{
    repoType: RepoType;
    repoUrl: string;
    repoFullName: string;
    projectName: string;
    branch: string;
  }> & { repoType: RepoType; repoUrl: string },
): ProjectRef {
  const repoUrl = scan.repoUrl.trim().replace(/\/+$/, '');
  const existing = db.get<ProjectRow>(
    `SELECT id, name, repo_type, repo_url FROM projects WHERE repo_type = ? AND repo_url = ?`,
    [scan.repoType, repoUrl],
  );
  if (existing) {
    // 后续上报忽略 projectName，但补齐缺失的补充信息
    if (scan.repoFullName) {
      db.run(
        `UPDATE projects SET repo_full_name = COALESCE(repo_full_name, ?), default_branch = COALESCE(default_branch, ?), updated_at = ? WHERE id = ?`,
        [scan.repoFullName, scan.branch ?? null, new Date().toISOString(), existing.id],
      );
    }
    return { id: existing.id, created: false, name: existing.name };
  }

  const name =
    scan.projectName?.trim() ||
    scan.repoFullName?.split('/').pop()?.trim() ||
    repoUrl.split('/').pop()?.replace(/\.git$/, '').trim() ||
    'unnamed-project';

  const now = new Date().toISOString();
  const res = db.run(
    `INSERT INTO projects(name, repo_type, repo_url, repo_full_name, default_branch, status, created_at, updated_at)
     VALUES(?, ?, ?, ?, ?, 1, ?, ?)`,
    [name, scan.repoType, repoUrl, scan.repoFullName ?? null, scan.branch ?? null, now, now],
  );
  return { id: res.lastInsertRowid, created: true, name };
}

// ------------------------------------------------------------- 创建批次
/** 上报报文中文本字段统一允许 null（平台按 null 入库，不报错） */
type Nullable<T> = { [K in keyof T]?: T[K] | null };

export interface CreateScanInput {
  scanNo: string;
  scanner?: { name?: string | null; version?: string | null };
  triggerType?: string | null;
  scan: Nullable<{
    repoType: RepoType;
    repoUrl: string;
    repoFullName: string;
    projectName: string;
    branch: string;
    commitId: string;
    commitMessage: string;
    commitAuthor: string;
    commitTime: string;
  }> & { repoType: RepoType; repoUrl: string };
  startedAt?: string | null;
  totalFiles?: number | null;
}

export function createScan(db: Db, input: CreateScanInput): ScanRef {
  const existing = db.get<{
    id: number;
    scan_no: string;
    project_id: number;
    status: string;
    created_at: string;
  }>(`SELECT id, scan_no, project_id, status, created_at FROM scan_tasks WHERE scan_no = ?`, [input.scanNo]);

  if (existing) {
    // 幂等：同 scanNo 直接返回原记录，不产生脏数据
    return {
      scanId: existing.id,
      scanNo: existing.scan_no,
      projectId: existing.project_id,
      projectCreated: false,
      status: existing.status,
      duplicated: true,
      createdAt: existing.created_at,
    };
  }

  const project = resolveProject(db, input.scan);
  const now = new Date().toISOString();
  const res = db.run(
    `INSERT INTO scan_tasks(
       scan_no, project_id, scanner_name, scanner_version, trigger_type, branch,
       commit_id, commit_message, commit_author, commit_time, started_at, status,
       total_files, scanned_files, created_at, updated_at)
     VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, 0, ?, ?)`,
    [
      input.scanNo,
      project.id,
      input.scanner?.name ?? null,
      input.scanner?.version ?? null,
      input.triggerType ?? 'push',
      input.scan.branch ?? null,
      input.scan.commitId ?? null,
      input.scan.commitMessage ?? null,      input.scan.commitAuthor ?? null,
      input.scan.commitTime ?? null,
      input.startedAt ?? now,
      input.totalFiles ?? 0,
      now,
      now,
    ],
  );

  return {
    scanId: res.lastInsertRowid,
    scanNo: input.scanNo,
    projectId: project.id,
    projectCreated: project.created,
    status: 'running',
    duplicated: false,
    createdAt: now,
  };
}

// -------------------------------------------------------------- 漏洞入库
/** 生成 VUL-YYYYMMDD-#### 编号，冲突时自增重试 */
function nextVulnNo(db: Db, when: Date): string {
  const y = when.getUTCFullYear();
  const m = String(when.getUTCMonth() + 1).padStart(2, '0');
  const d = String(when.getUTCDate()).padStart(2, '0');
  const prefix = `VUL-${y}${m}${d}-`;
  const row = db.get<{ c: number }>(
    `SELECT COUNT(*) AS c FROM vulnerabilities WHERE vuln_no LIKE ?`,
    [`${prefix}%`],
  );
  let seq = Number(row?.c ?? 0) + 1;
  for (;;) {
    const candidate = `${prefix}${String(seq).padStart(4, '0')}`;
    const hit = db.get<{ id: number }>(`SELECT id FROM vulnerabilities WHERE vuln_no = ?`, [candidate]);
    if (!hit) return candidate;
    seq += 1;
  }
}

interface VulnRow {
  id: number;
  vuln_no: string;
  status: string;
  occurrence_count: number;
  fixed_at: string | null;
}

const TERMINAL_STATUSES = new Set(['fixed', 'ignored', 'false_positive']);

/**
 * 批量上报漏洞。逐条处理，部分成功语义：
 *  - 校验失败的条目跳过并记录原因，不影响其它条目
 *  - 指纹已存在 → 更新 last_found_at / scan_id / occurrence_count，保留人工处置的状态
 *  - 指纹已存在但原状态是终态 → 视为 resurfaced，自动置回 open 并写事件
 */
export function ingestVulnerabilities(
  db: Db,
  scan: { scanId: number; projectId: number; scanNo: string },
  items: unknown[],
): VulnIngestSummary {
  const summary: VulnIngestSummary = {
    received: items.length,
    created: 0,
    updated: 0,
    resurfaced: 0,
    skipped: 0,
    details: [],
    skippedItems: [],
  };

  const now = new Date();
  const nowIso = now.toISOString();
  // 批次内 externalVulnId → vulnId，供随后上报样本时关联
  const externalMap = new Map<string, number>();

  db.tx(() => {
    items.forEach((raw, index) => {
      const parsed = vulnerabilityItemSchema.safeParse(raw);
      if (!parsed.success) {
        const reason = parsed.error.issues.map((i) => `${i.path.join('.') || 'item'}: ${i.message}`).join('; ');
        summary.skipped += 1;
        summary.skippedItems.push({
          index,
          externalVulnId:
            raw && typeof raw === 'object' && 'externalVulnId' in raw
              ? String((raw as { externalVulnId?: unknown }).externalVulnId ?? '') || null
              : null,
          reason,
        });
        summary.details.push({
          index,
          externalVulnId: null,
          vulnId: null,
          vulnNo: null,
          fingerprint: null,
          result: 'skipped',
        });
        return;
      }

      const item = parsed.data;
      const snippet = item.codeSnippet ? item.codeSnippet.slice(0, LIMITS.MAX_SNIPPET_BYTES) : null;
      const filePath = item.filePath.replace(/^\/+/, '');
      const fingerprint = vulnerabilityFingerprint({
        projectId: scan.projectId,
        ruleId: item.ruleId,
        filePath,
        codeSnippet: snippet,
      });

      const existing = db.get<VulnRow>(
        `SELECT id, vuln_no, status, occurrence_count, fixed_at FROM vulnerabilities WHERE fingerprint = ?`,
        [fingerprint],
      );

      if (existing) {
        const wasTerminal = TERMINAL_STATUSES.has(existing.status);
        const nextStatus = wasTerminal ? 'open' : existing.status;
        db.run(
          `UPDATE vulnerabilities
              SET scan_id = ?, last_found_at = ?, occurrence_count = occurrence_count + 1,
                  status = ?, fixed_at = CASE WHEN ? = 'fixed' THEN fixed_at ELSE NULL END,
                  title = ?, severity = ?, rule_name = COALESCE(?, rule_name),
                  updated_at = ?
            WHERE id = ?`,
          [
            scan.scanId,
            nowIso,
            nextStatus,
            nextStatus,
            item.title,
            item.severity,
            item.ruleName ?? null,
            nowIso,
            existing.id,
          ],
        );

        if (wasTerminal) {
          db.run(
            `INSERT INTO vuln_events(vuln_id, action, from_value, to_value, operator_name, comment, created_at)
             VALUES(?, 'resurfaced', ?, 'open', 'system', ?, ?)`,
            [
              existing.id,
              existing.status,
              `该漏洞在扫描批次 ${scan.scanNo} 中再次出现，已自动置回待处理`,
              nowIso,
            ],
          );
          summary.resurfaced += 1;
        } else {
          summary.updated += 1;
        }

        if (item.externalVulnId) externalMap.set(item.externalVulnId, existing.id);
        summary.details.push({
          index,
          externalVulnId: item.externalVulnId ?? null,
          vulnId: existing.id,
          vulnNo: existing.vuln_no,
          fingerprint,
          result: wasTerminal ? 'resurfaced' : 'updated',
        });
        return;
      }

      const vulnNo = nextVulnNo(db, now);
      const res = db.run(
        `INSERT INTO vulnerabilities(
           vuln_no, fingerprint, scan_id, project_id, external_vuln_id, rule_id, rule_name, title,
           severity, category, cwe, cve, language, file_path, line_start, line_end, code_snippet,
           description, suggestion, confidence, status, assignee, occurrence_count,
           first_found_at, last_found_at, fixed_at, remark, created_at, updated_at)
         VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', NULL, 1, ?, ?, NULL, NULL, ?, ?)`,
        [
          vulnNo,
          fingerprint,
          scan.scanId,
          scan.projectId,
          item.externalVulnId ?? null,
          item.ruleId,
          item.ruleName ?? null,
          item.title,
          item.severity,
          item.category ?? null,
          item.cwe ?? null,
          item.cve ?? null,
          item.language ?? null,
          filePath,
          item.lineStart ?? null,
          item.lineEnd ?? null,
          snippet,
          item.description ?? null,
          item.suggestion ?? null,
          item.confidence ?? null,
          nowIso,
          nowIso,
          nowIso,
          nowIso,
        ],
      );
      const vulnId = res.lastInsertRowid;

      db.run(
        `INSERT INTO vuln_events(vuln_id, action, from_value, to_value, operator_name, comment, created_at)
         VALUES(?, 'created', NULL, 'open', 'scanner', ?, ?)`,
        [vulnId, `首次由扫描工具上报，批次 ${scan.scanNo}`, nowIso],
      );

      if (item.externalVulnId) externalMap.set(item.externalVulnId, vulnId);
      summary.created += 1;
      summary.details.push({
        index,
        externalVulnId: item.externalVulnId ?? null,
        vulnId,
        vulnNo,
        fingerprint,
        result: 'created',
      });
    });

    // 回写批次内已入库漏洞数
    const cnt = db.get<{ c: number }>(
      `SELECT COUNT(*) AS c FROM vulnerabilities WHERE scan_id = ?`,
      [scan.scanId],
    );
    db.run(`UPDATE scan_tasks SET vuln_count = ?, updated_at = ? WHERE id = ?`, [
      Number(cnt?.c ?? 0),
      nowIso,
      scan.scanId,
    ]);
  });

  // 把 externalVulnId → vulnId 映射暂存到扫描批次上，供 Step 3 关联正样本
  setExternalVulnMap(db, scan.scanNo, externalMap);

  return summary;
}

// ----------------------------------------------------- externalVulnId 映射
/**
 * Step 3（上报样本）需要把 externalVulnId 关联到本批次已入库的漏洞。
 * 映射随批次短暂保存在内存中即可（同一批次 4 步调用是连续发生的），
 * 进程重启导致丢失时，样本的 vuln_id 退化为 null，不影响其它字段入库。
 */
const externalVulnMaps = new Map<string, Map<string, number>>();

function setExternalVulnMap(db: Db, scanNo: string, map: Map<string, number>): void {
  const prev = externalVulnMaps.get(scanNo);
  if (prev) for (const [k, v] of map) prev.set(k, v);
  else externalVulnMaps.set(scanNo, map);

  // 兜底：也可从库中按 external_vuln_id 反查，避免进程重启后丢关联
  const rows = db.all<{ id: number; external_vuln_id: string }>(
    `SELECT v.id, v.external_vuln_id FROM vulnerabilities v
      JOIN scan_tasks s ON s.id = v.scan_id
     WHERE s.scan_no = ? AND v.external_vuln_id IS NOT NULL`,
    [scanNo],
  );
  const m = externalVulnMaps.get(scanNo) ?? new Map<string, number>();
  for (const r of rows) if (!m.has(r.external_vuln_id)) m.set(r.external_vuln_id, r.id);
  externalVulnMaps.set(scanNo, m);
}

export function lookupExternalVuln(db: Db, scanNo: string, externalVulnId: string): number | null {
  const fromMemory = externalVulnMaps.get(scanNo)?.get(externalVulnId);
  if (fromMemory) return fromMemory;
  const row = db.get<{ id: number }>(
    `SELECT v.id FROM vulnerabilities v
       JOIN scan_tasks s ON s.id = v.scan_id
      WHERE s.scan_no = ? AND v.external_vuln_id = ?
      ORDER BY v.id DESC LIMIT 1`,
    [scanNo, externalVulnId],
  );
  return row?.id ?? null;
}

// -------------------------------------------------------------- 样本入库
/** 批量上报正负样本。幂等键 (scanId, filePath, snippetHash)，已存在则跳过 */
export function ingestSamples(
  db: Db,
  scan: { scanId: number; projectId: number; scanNo: string },
  items: unknown[],
): SampleIngestSummary {
  const summary: SampleIngestSummary = {
    received: items.length,
    created: 0,
    duplicated: 0,
    truncated: 0,
    positiveCount: 0,
    negativeCount: 0,
  };
  const nowIso = new Date().toISOString();

  db.tx(() => {
    for (const raw of items) {
      const parsed = sampleItemSchema.safeParse(raw);
      if (!parsed.success) continue;
      const s = parsed.data;

      let snippet = s.snippet ?? null;
      if (snippet && Buffer.byteLength(snippet, 'utf8') > LIMITS.MAX_SNIPPET_BYTES) {
        snippet = snippet.slice(0, LIMITS.MAX_SNIPPET_BYTES);
        summary.truncated += 1;
      }
      const hash = s.snippetHash ?? snippetHash(snippet);
      const filePath = s.filePath.replace(/^\/+/, '');

      const vulnId = s.externalVulnId
        ? lookupExternalVuln(db, scan.scanNo, s.externalVulnId)
        : null;

      const res = db.run(
        `INSERT OR IGNORE INTO samples(
           scan_id, project_id, external_sample_id, label, rule_id, vuln_id, file_path,
           language, line_start, line_end, snippet, snippet_hash, file_hash, created_at)
         VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          scan.scanId,
          scan.projectId,
          s.externalSampleId ?? null,
          s.label,
          null,
          vulnId,
          filePath,
          s.language ?? null,
          s.lineStart ?? null,
          s.lineEnd ?? null,
          snippet,
          hash,
          s.fileHash ?? null,
          nowIso,
        ],
      );

      if (res.changes > 0) {
        summary.created += 1;
        if (s.label === 'positive') summary.positiveCount += 1;
        else summary.negativeCount += 1;
      } else {
        summary.duplicated += 1;
      }
    }

    // 正样本的 ruleId 从关联漏洞回填，便于按规则筛选样本
    db.run(
      `UPDATE samples
          SET rule_id = (SELECT v.rule_id FROM vulnerabilities v WHERE v.id = samples.vuln_id)
        WHERE scan_id = ? AND vuln_id IS NOT NULL AND rule_id IS NULL`,
      [scan.scanId],
    );

    const counts = db.get<{ total: number; pos: number; neg: number }>(
      `SELECT COUNT(*) AS total,
              SUM(CASE WHEN label = 'positive' THEN 1 ELSE 0 END) AS pos,
              SUM(CASE WHEN label = 'negative' THEN 1 ELSE 0 END) AS neg
         FROM samples WHERE scan_id = ?`,
      [scan.scanId],
    );
    db.run(
      `UPDATE scan_tasks SET sample_count = ?, positive_count = ?, negative_count = ?, updated_at = ? WHERE id = ?`,
      [Number(counts?.total ?? 0), Number(counts?.pos ?? 0), Number(counts?.neg ?? 0), nowIso, scan.scanId],
    );
  });

  return summary;
}

// -------------------------------------------------------------- 结束批次
export interface CompleteScanResult {
  scanId: number;
  scanNo: string;
  status: string;
  vulnCount: number;
  sampleCount: number;
  positiveCount: number;
  negativeCount: number;
  durationMs: number | null;
}

export function completeScan(
  db: Db,
  scanNo: string,
  input: {
    status: 'success' | 'failed' | 'partial';
    finishedAt?: string | null;
    totalFiles?: number;
    scannedFiles?: number;
    errorMessage?: string | null;
  },
): CompleteScanResult {
  const scan = db.get<{
    id: number;
    scan_no: string;
    project_id: number;
    started_at: string | null;
    created_at: string;
    status: string;
  }>(`SELECT id, scan_no, project_id, started_at, created_at, status FROM scan_tasks WHERE scan_no = ?`, [scanNo]);
  if (!scan) throw AppError.notFound(`扫描批次不存在：${scanNo}`);
  if (scan.status !== 'running') {
    // 已结束的批次重复 complete：按幂等处理，返回当前统计而不是报错
    const cur = db.get<{
      vuln_count: number;
      sample_count: number;
      positive_count: number;
      negative_count: number;
      started_at: string | null;
      finished_at: string | null;
      status: string;
    }>(
      `SELECT vuln_count, sample_count, positive_count, negative_count, started_at, finished_at, status
         FROM scan_tasks WHERE id = ?`,
      [scan.id],
    );
    return {
      scanId: scan.id,
      scanNo: scan.scan_no,
      status: cur?.status ?? scan.status,
      vulnCount: Number(cur?.vuln_count ?? 0),
      sampleCount: Number(cur?.sample_count ?? 0),
      positiveCount: Number(cur?.positive_count ?? 0),
      negativeCount: Number(cur?.negative_count ?? 0),
      durationMs:
        cur?.started_at && cur?.finished_at
          ? Date.parse(cur.finished_at) - Date.parse(cur.started_at)
          : null,
    };
  }

  const finishedIso = input.finishedAt ?? new Date().toISOString();
  const counts = db.get<{
    total: number;
    pos: number;
    neg: number;
  }>(
    `SELECT COUNT(*) AS total,
            SUM(CASE WHEN label = 'positive' THEN 1 ELSE 0 END) AS pos,
            SUM(CASE WHEN label = 'negative' THEN 1 ELSE 0 END) AS neg
       FROM samples WHERE scan_id = ?`,
    [scan.id],
  );
  const vulnCnt = db.get<{ c: number }>(
    `SELECT COUNT(*) AS c FROM vulnerabilities WHERE scan_id = ?`,
    [scan.id],
  );

  db.run(
    `UPDATE scan_tasks
        SET status = ?, finished_at = ?, total_files = COALESCE(?, total_files),
            scanned_files = COALESCE(?, scanned_files), error_message = ?,
            vuln_count = ?, sample_count = ?, positive_count = ?, negative_count = ?, updated_at = ?
      WHERE id = ?`,
    [
      input.status,
      finishedIso,
      input.totalFiles ?? null,
      input.scannedFiles ?? null,
      input.errorMessage ?? null,
      Number(vulnCnt?.c ?? 0),
      Number(counts?.total ?? 0),
      Number(counts?.pos ?? 0),
      Number(counts?.neg ?? 0),
      finishedIso,
      scan.id,
    ],
  );

  const startedAt = scan.started_at ?? scan.created_at;
  return {
    scanId: scan.id,
    scanNo: scan.scan_no,
    status: input.status,
    vulnCount: Number(vulnCnt?.c ?? 0),
    sampleCount: Number(counts?.total ?? 0),
    positiveCount: Number(counts?.pos ?? 0),
    negativeCount: Number(counts?.neg ?? 0),
    durationMs: startedAt ? Math.max(0, Date.parse(finishedIso) - Date.parse(startedAt)) : null,
  };
}

/** 找到批次；不存在则 404（契约：上报未先创建批次 → 404 / 40400） */
export function requireScanByNo(db: Db, scanNo: string) {
  const scan = db.get<{
    id: number;
    scan_no: string;
    project_id: number;
    status: string;
  }>(`SELECT id, scan_no, project_id, status FROM scan_tasks WHERE scan_no = ?`, [scanNo]);
  if (!scan) throw AppError.notFound(`扫描批次不存在，请先调用 POST /ingest/scans 创建：${scanNo}`);
  return scan;
}
