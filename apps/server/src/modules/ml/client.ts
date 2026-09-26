import { config } from '../../config/index.js';

/**
 * ScanMan 模型推理服务客户端（apps/server → model-service）。
 * 契约见 model-service/README.md；服务不可用时按 ML_FALLBACK 决定降级还是报错。
 */

export interface MlPredictResult {
  modelServed: boolean;
  degraded: boolean;
  degradedReason: string | null;
  modelName: string;
  latencyMs: number;
  verdict: 'vulnerable' | 'safe' | null;
  vulnerableProbability: number | null;
  safeProbability: number | null;
  threshold: number;
  predictedCwe: string | null;
  predictedCweName: string | null;
  cweConfidence: number | null;
  topCwe: Array<{ cwe: string; name: string | null; probability: number }>;
}

export interface MlModelInfo {
  tasks: {
    detection: { available: boolean; checkpoint: string | null; numLabels: number | null; labelMap: Record<string, number> | null };
    classification: {
      available: boolean;
      checkpoint: string | null;
      numLabels: number | null;
      labelMap: Record<string, number> | null;
      cweCount: number | null;
    };
  };
  device: string | null;
  maxLength: number;
  detectionThreshold: number;
  degraded: boolean;
  degradedReason: string | null;
}

export interface MlClientResult<T> {
  ok: boolean;
  data: T | null;
  error: string | null;
}

async function request<T>(path: string, init?: RequestInit): Promise<MlClientResult<T>> {
  const url = `${config.ml.url}${path}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.ml.timeoutMs);
  try {
    const res = await fetch(url, {
      ...init,
      signal: controller.signal,
      headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      return { ok: false, data: null, error: `模型服务返回 HTTP ${res.status}: ${text.slice(0, 300)}` };
    }
    return { ok: true, data: (await res.json()) as T, error: null };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return {
      ok: false,
      data: null,
      error: msg.includes('abort') ? `调用模型服务超时（>${config.ml.timeoutMs}ms）` : `无法连接模型服务：${msg}`,
    };
  } finally {
    clearTimeout(timer);
  }
}

export function predict(input: {
  code: string;
  mode?: 'auto' | 'detection' | 'classification';
  threshold?: number;
  topK?: number;
  filePath?: string;
  language?: string;
}): Promise<MlClientResult<MlPredictResult>> {
  return request<MlPredictResult>('/predict', { method: 'POST', body: JSON.stringify(input) });
}

export function health(): Promise<MlClientResult<Record<string, unknown>>> {
  return request<Record<string, unknown>>('/health');
}

export function modelInfo(): Promise<MlClientResult<MlModelInfo>> {
  return request<MlModelInfo>('/model/info');
}

/**
 * 模型服务不可用时的本地降级：按高信号特征做启发式判定。
 * 明确标记 degraded=true / modelServed=false，绝不冒充真实模型输出。
 */
export function degradedPredict(
  code: string,
  reason: string,
  threshold = 0.5,
): MlPredictResult {
  const started = Date.now();
  const patterns: Array<{ re: RegExp; cwe: string; name: string }> = [
    { re: /\b(strcpy|strcat|sprintf|gets|memcpy)\s*\(/, cwe: 'CWE-787', name: 'Out-of-bounds Write' },
    { re: /(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,200}["'`]\s*\+/i, cwe: 'CWE-89', name: 'SQL Injection' },
    { re: /\b(eval|exec)\s*\(/, cwe: 'CWE-94', name: 'Code Injection' },
    { re: /\.innerHTML\s*=|document\.write\s*\(/, cwe: 'CWE-79', name: 'Cross-site Scripting' },
    { re: /\b(system|popen|Runtime\.getRuntime\(\)\.exec)\s*\(/, cwe: 'CWE-78', name: 'OS Command Injection' },
    { re: /pickle\.loads|ObjectInputStream|yaml\.load\s*\(/, cwe: 'CWE-502', name: 'Deserialization of Untrusted Data' },
    { re: /(password|passwd|secret|apiKey|token)\s*[:=]\s*["'][^"']{4,}["']/i, cwe: 'CWE-798', name: 'Hard-coded Credentials' },
    { re: /path\.join\s*\([^)]*(req\.|params|query)/, cwe: 'CWE-22', name: 'Path Traversal' },
    { re: /md5\s*\(|sha1\s*\(/i, cwe: 'CWE-327', name: 'Broken Crypto Algorithm' },
    { re: /requests\.(get|post)\s*\(\s*(url|target|req\.)/, cwe: 'CWE-918', name: 'Server-Side Request Forgery' },
  ];

  const hits = patterns.filter((p) => p.re.test(code));
  const vulnerable = hits.length > 0;
  // 命中越多，置信度越高；无命中给一个偏安全的低分
  const prob = vulnerable ? Math.min(0.97, 0.6 + hits.length * 0.09) : 0.12;

  return {
    modelServed: false,
    degraded: true,
    degradedReason: reason,
    modelName: 'heuristic-fallback（非模型输出）',
    latencyMs: Date.now() - started,
    verdict: prob >= threshold ? 'vulnerable' : 'safe',
    vulnerableProbability: prob,
    safeProbability: Math.round((1 - prob) * 10000) / 10000,
    threshold,
    predictedCwe: hits[0]?.cwe ?? null,
    predictedCweName: hits[0]?.name ?? null,
    cweConfidence: hits[0] ? Math.round(prob * 10000) / 10000 : null,
    topCwe: hits.slice(0, 5).map((h, i) => ({
      cwe: h.cwe,
      name: h.name,
      probability: Math.round(Math.max(0.05, prob - i * 0.12) * 10000) / 10000,
    })),
  };
}
