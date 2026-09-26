import type { NextFunction, Request, Response } from 'express';
import { ERROR_CODES, LIMITS } from '@vuln/shared';
import { AppError } from './errors.js';

interface Bucket {
  count: number;
  resetAt: number;
}

/**
 * 轻量内存令牌桶。单进程部署足够；多实例需换 Redis。
 *  - 上报接口：按 API Key 50 次/秒
 *  - 登录接口：按 IP 10 次/分钟
 *  - 其他接口：按用户 200 次/秒
 */
class SlidingWindow {
  private buckets = new Map<string, Bucket>();
  private lastSweep = Date.now();

  hit(key: string, limit: number, windowMs: number): { allowed: boolean; retryAfterSec: number } {
    const now = Date.now();
    this.sweep(now);
    const b = this.buckets.get(key);
    if (!b || b.resetAt <= now) {
      this.buckets.set(key, { count: 1, resetAt: now + windowMs });
      return { allowed: true, retryAfterSec: 0 };
    }
    if (b.count >= limit) {
      return { allowed: false, retryAfterSec: Math.max(1, Math.ceil((b.resetAt - now) / 1000)) };
    }
    b.count += 1;
    return { allowed: true, retryAfterSec: 0 };
  }

  private sweep(now: number): void {
    if (now - this.lastSweep < 60_000) return;
    this.lastSweep = now;
    for (const [k, v] of this.buckets) if (v.resetAt <= now) this.buckets.delete(k);
  }
}

const window = new SlidingWindow();

/**
 * 集成测试需要反复登录同一账号，会被登录限流（10 次/分钟）挡住。
 *
 * 读取方式刻意做成「每次请求都读」，而不是模块加载时读一次：
 * 这样测试可以在运行时开关，也避免 environment 变化后行为不一致。
 * 正式环境保持 RATE_LIMIT_DISABLED 未设置即可。
 */
let testOverride: boolean | null = null;

/** 仅供测试使用：强制开关限流 */
export function setRateLimitDisabled(value: boolean | null): void {
  testOverride = value;
}

function isDisabled(): boolean {
  if (testOverride !== null) return testOverride;
  return ['1', 'true', 'yes', 'on'].includes((process.env.RATE_LIMIT_DISABLED ?? '').toLowerCase());
}

function clientIp(req: Request): string {
  const fwd = req.header('X-Forwarded-For');
  if (fwd) return fwd.split(',')[0]!.trim();
  return req.ip ?? req.socket.remoteAddress ?? 'unknown';
}

function reject(res: Response, code: number, retryAfterSec: number): void {
  res.setHeader('Retry-After', String(retryAfterSec));
  res.status(429).json({ code, message: '请求过于频繁', data: null, traceId: res.locals.traceId });
}

/** 上报接口限流：50 次/秒 / API Key */
export function ingestRateLimit(req: Request, res: Response, next: NextFunction): void {
  if (isDisabled()) return next();
  const key = req.header('X-API-Key') ?? clientIp(req);
  const r = window.hit(`ingest:${key}`, 50, 1000);
  if (!r.allowed) return reject(res, ERROR_CODES.RATE_LIMITED, r.retryAfterSec);
  next();
}

/** 登录接口限流：10 次/分钟 / IP */
export function loginRateLimit(req: Request, res: Response, next: NextFunction): void {
  if (isDisabled()) return next();
  const r = window.hit(`login:${clientIp(req)}`, LIMITS.LOGIN_RATE_LIMIT, 60_000);
  if (!r.allowed) return reject(res, ERROR_CODES.LOGIN_RATE_LIMITED, r.retryAfterSec);
  next();
}

/** 其他接口限流：200 次/秒 / 用户 */
export function generalRateLimit(req: Request, res: Response, next: NextFunction): void {
  if (isDisabled()) return next();
  const key = req.user ? `user:${req.user.id}` : `ip:${clientIp(req)}`;
  const r = window.hit(key, 200, 1000);
  if (!r.allowed) return reject(res, ERROR_CODES.RATE_LIMITED, r.retryAfterSec);
  next();
}

/** 请求体大小守卫：> 5MB 返回 41300（express.json 也会拦，这里给出契约错误码） */
export function payloadGuard(err: unknown, _req: Request, res: Response, next: NextFunction): void {
  const e = err as { type?: string; status?: number };
  if (e?.type === 'entity.too.large' || e?.status === 413) {
    res.status(413).json({
      code: ERROR_CODES.PAYLOAD_TOO_LARGE,
      message: '请求体过大，请使用分片上报接口',
      data: null,
      traceId: res.locals.traceId,
    });
    return;
  }
  next(err);
}

/** 显式抛出 41300，用于单批元素数超限的场景（契约要求 400/413） */
export function assertBatchSize(n: number, label: string): void {
  if (n > LIMITS.MAX_BATCH_ITEMS) {
    throw new AppError(
      ERROR_CODES.PARAM_INVALID,
      `${label} 单批上限 ${LIMITS.MAX_BATCH_ITEMS} 条，当前 ${n} 条，请使用分片上报`,
      400,
      { errors: [{ field: label, message: `单批最多 ${LIMITS.MAX_BATCH_ITEMS} 条` }] },
    );
  }
}
