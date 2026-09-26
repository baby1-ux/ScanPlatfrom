import crypto from 'node:crypto';

/**
 * 代码片段规范化 + 指纹算法。
 * 严格按 docs/02-API接口文档.md 第 2.2 节实现（平台侧计算，扫描侧不计算 fingerprint）。
 *
 * 规范化规则：
 *   1. 去除首尾空白
 *   2. 统一换行符为 \n
 *   3. 将连续空白字符折叠为单个空格
 *   4. 全部转小写
 */
export function normalizeSnippet(input: string | null | undefined): string {
  if (!input) return '';
  return input
    .replace(/\r\n?/g, '\n')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

export function sha256(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

/** 代码片段哈希：sha256(规范化片段) */
export function snippetHash(snippet: string | null | undefined): string {
  return sha256(normalizeSnippet(snippet));
}

/** 漏洞去重指纹：sha256(projectId | ruleId | filePath | snippetHash) */
export function vulnerabilityFingerprint(params: {
  projectId: number;
  ruleId: string;
  filePath: string;
  codeSnippet?: string | null;
}): string {
  const { projectId, ruleId, filePath, codeSnippet } = params;
  const h = snippetHash(codeSnippet);
  return sha256(`${projectId}|${ruleId}|${filePath}|${h}`);
}

/** API Key 明文 → 存储用 hash */
export function apiKeyHash(plain: string): string {
  return sha256(plain);
}

const ALPHABET = 'abcdef0123456789';

/** 生成一个 API Key 明文：vuln_sk_ + 32 位十六进制 */
export function generateApiKey(): string {
  const bytes = crypto.randomBytes(32);
  let out = '';
  for (const b of bytes) out += ALPHABET[b % ALPHABET.length];
  return `vuln_sk_${out.slice(0, 32)}`;
}

/** 只保留前 12 位与后 4 位，用于列表展示 */
export function maskApiKey(plain: string): string {
  if (plain.length <= 18) return `${plain.slice(0, 6)}****`;
  return `${plain.slice(0, 12)}****${plain.slice(-4)}`;
}

/** 短随机串，用于 traceId / scanNo 后缀 */
export function shortId(len = 12): string {
  return crypto.randomBytes(Math.ceil(len / 2)).toString('hex').slice(0, len);
}
