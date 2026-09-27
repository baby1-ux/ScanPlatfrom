import type { NextFunction, Request, Response } from 'express';
import { z, type ZodTypeAny } from 'zod';
import { AppError } from './errors.js';

/** 把 zod 校验失败转成契约里的 40001 + errors[] */
export function parseOrThrow<T extends ZodTypeAny>(schema: T, input: unknown, where = 'body'): z.infer<T> {
  const r = schema.safeParse(input);
  if (!r.success) {
    const errors = r.error.issues.map((i) => ({
      field: [where, ...i.path.map(String)].filter(Boolean).join('.'),
      message: i.message,
    }));
    throw AppError.badRequest(errors);
  }
  return r.data;
}

export const validateBody =
  (schema: ZodTypeAny) =>
  (req: Request, _res: Response, next: NextFunction): void => {
    req.body = parseOrThrow(schema, req.body, 'body');
    next();
  };

export const validateQuery =
  (schema: ZodTypeAny) =>
  (req: Request, res: Response, next: NextFunction): void => {
    res.locals.query = parseOrThrow(schema, req.query, 'query');
    next();
  };

// -------------------------------------------------------------- 通用 zod
export const zId = z.coerce.number().int().positive();
export const zIsoDateTime = z.string().refine((s) => Number.isFinite(Date.parse(s)), {
  message: '必须是 ISO 8601 时间字符串',
});

/** "1,2,3" 或 ["1","2"] → number[] */
export const zIdList = z
  .union([z.string(), z.array(z.string()), z.array(z.number()), z.number()])
  .optional()
  .transform((v): number[] | undefined => {
    if (v === undefined || v === null || v === '') return undefined;
    const raw = Array.isArray(v) ? v : String(v).split(',');
    const out = raw
      .map((x) => Number(String(x).trim()))
      .filter((n) => Number.isInteger(n) && n > 0);
    return out.length ? out : undefined;
  });

/** "critical,high" → string[] */
export const zEnumList = <T extends readonly [string, ...string[]]>(values: T) =>
  z
    .union([z.string(), z.array(z.string())])
    .optional()
    .transform((v): Array<T[number]> | undefined => {
      if (v === undefined || v === null || v === '') return undefined;
      const raw = (Array.isArray(v) ? v : String(v).split(',')).map((s) => s.trim()).filter(Boolean);
      const out = raw.filter((s): s is T[number] => (values as readonly string[]).includes(s));
      return out.length ? out : undefined;
    });

export const zPagination = {
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(200).default(20),
  sortBy: z.string().optional(),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
};
