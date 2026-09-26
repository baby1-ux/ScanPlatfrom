import type { NextFunction, Request, Response } from 'express';
import { ERROR_CODES } from '@vuln/shared';
import { shortId } from '../services/fingerprint.js';
import type { AppError } from './errors.js';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      traceId: string;
      /** JWT 鉴权成功后注入 */
      user?: {
        id: number;
        username: string;
        displayName: string | null;
        role: 'admin' | 'auditor' | 'viewer';
        permissions: string[];
      };
      /** API Key 鉴权成功后注入 */
      apiKey?: {
        id: number;
        name: string;
        scopes: string[];
        repoScope: string[] | null;
      };
    }
  }
}

/** 统一响应格式：{ code, message, data, traceId } */
export function ok<T>(res: Response, data: T, message = 'success', status = 200): void {
  res.status(status).json({ code: ERROR_CODES.OK, message, data: data ?? null, traceId: res.locals.traceId });
}

export function created<T>(res: Response, data: T, message = 'success'): void {
  ok(res, data, message, 201);
}

/** 给请求打 traceId；同时回写响应头，便于扫描侧排查 */
export function traceMiddleware(req: Request, res: Response, next: NextFunction): void {
  const incoming = req.header('X-Trace-Id');
  const traceId = incoming && /^[A-Za-z0-9_-]{6,64}$/.test(incoming) ? incoming : shortId(12);
  req.traceId = traceId;
  res.locals.traceId = traceId;
  res.setHeader('X-Trace-Id', traceId);
  next();
}

/** 把 AppError / zod 错误 / 未知错误统一成契约响应 */
export function errorHandler(
  err: unknown,
  req: Request,
  res: Response,
  _next: NextFunction,
): void {
  const traceId = req.traceId ?? shortId(12);
  const anyErr = err as Partial<AppError> & { name?: string; message?: string; code?: string };

  // zod 校验错误（由 validate 中间件抛出）
  if (anyErr?.name === 'ZodError') {
    const issues = (err as unknown as { issues: Array<{ path: (string | number)[]; message: string }> }).issues;
    res.status(400).json({
      code: ERROR_CODES.PARAM_INVALID,
      message: '参数校验失败',
      data: {
        errors: issues.map((i) => ({ field: i.path.join('.') || 'body', message: i.message })),
      },
      traceId,
    });
    return;
  }

  // JSON 解析失败（body-parser）
  if (anyErr?.name === 'SyntaxError' && 'body' in (err as object)) {
    res.status(400).json({
      code: ERROR_CODES.PARAM_INVALID,
      message: '请求体不是合法 JSON',
      data: { errors: [{ field: 'body', message: anyErr.message ?? 'JSON 解析失败' }] },
      traceId,
    });
    return;
  }

  // SQLite 唯一约束冲突 → 409
  if (typeof anyErr?.message === 'string' && anyErr.message.includes('UNIQUE constraint failed')) {
    res.status(409).json({
      code: ERROR_CODES.CONFLICT,
      message: '资源冲突：已存在相同唯一键的记录',
      data: { detail: anyErr.message },
      traceId,
    });
    return;
  }

  if (typeof anyErr?.code === 'number' && typeof anyErr?.httpStatus === 'number') {
    res.status(anyErr.httpStatus).json({
      code: anyErr.code,
      message: anyErr.message ?? '请求失败',
      data: anyErr.data ?? null,
      traceId,
    });
    return;
  }

  // eslint-disable-next-line no-console
  console.error(`[error] traceId=${traceId} ${req.method} ${req.originalUrl}`, err);
  res.status(500).json({
    code: ERROR_CODES.INTERNAL_ERROR,
    message: '服务器内部错误',
    data: null,
    traceId,
  });
}

/** 包装 async handler，异常自动进 errorHandler */
export function asyncHandler<T extends Request = Request>(
  fn: (req: T, res: Response, next: NextFunction) => unknown | Promise<unknown>,
) {
  return (req: Request, res: Response, next: NextFunction): void => {
    Promise.resolve(fn(req as T, res, next)).catch(next);
  };
}
