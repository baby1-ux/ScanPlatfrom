import express, { type Express, Router } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { ERROR_CODES, LIMITS } from '@vuln/shared';
import { config } from './config/index.js';
import { getDb } from './db/index.js';
import { AppError } from './core/errors.js';
import { asyncHandler, errorHandler, ok, traceMiddleware } from './core/http.js';
import { jwtAuth, requirePermission } from './core/auth.js';
import { payloadGuard } from './core/rateLimit.js';
import { authRouter } from './modules/auth/routes.js';
import { ingestRouter } from './modules/ingest/routes.js';
import { vulnerabilityRouter } from './modules/vulnerability/routes.js';
import { projectRouter } from './modules/project/routes.js';
import { scanRouter } from './modules/scan/routes.js';
import { sampleRouter } from './modules/sample/routes.js';
import { statsRouter } from './modules/stats/routes.js';
import { apiKeyRouter } from './modules/apiKey/routes.js';
import { userRouter } from './modules/user/routes.js';
import { mlRouter } from './modules/ml/routes.js';

export function createApp(): Express {
  const app = express();

  app.disable('x-powered-by');
  app.set('trust proxy', true);

  app.use(
    helmet({
      // 前端是同仓独立部署，这里不做 CSP 限制；由 Nginx 层统一处理
      contentSecurityPolicy: false,
      crossOriginResourcePolicy: false,
    }),
  );

  app.use(
    cors({
      origin(origin, cb) {
        if (!origin) return cb(null, true);
        if (config.corsOrigins.includes('*') || config.corsOrigins.includes(origin)) {
          return cb(null, true);
        }
        // 开发便利：允许任意 localhost / 127.0.0.1 端口
        if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return cb(null, true);
        return cb(null, false);
      },
      credentials: true,
      exposedHeaders: ['X-Trace-Id', 'X-ML-Degraded', 'Content-Disposition', 'Retry-After'],
    }),
  );

  app.use(traceMiddleware);

  // 上报接口可能上万条样本，按 5MB 上限放行；超限由 payloadGuard 转成 41300
  app.use(
    express.json({
      limit: LIMITS.MAX_BODY_BYTES,
      type: ['application/json', 'application/*+json'],
    }),
  );
  app.use(express.urlencoded({ extended: false, limit: '1mb' }));

  // 健康检查（不鉴权、不记业务日志）
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'vuln-platform-server', time: new Date().toISOString() });
  });

  const api = Router();
  api.use('/auth', authRouter);
  api.use('/ingest', ingestRouter);
  api.use('/vulnerabilities', vulnerabilityRouter);
  api.use('/projects', projectRouter);
  api.use('/scans', scanRouter);
  api.use('/samples', sampleRouter);
  api.use('/stats', statsRouter);
  api.use('/api-keys', apiKeyRouter);
  api.use('/users', userRouter);
  api.use('/ml', mlRouter);

  /**
   * 指派下拉数据源。用户管理接口限 admin，但漏洞指派是 auditor 的日常操作，
   * 因此单独开一个只读、只返回最小字段的接口。
   */
  api.get(
    '/assignees',
    jwtAuth,
    requirePermission('vuln:read'),
    asyncHandler((_req, res) => {
      const list = getDb().all<{
        id: number;
        username: string;
        display_name: string | null;
        role: string;
      }>(`SELECT id, username, display_name, role FROM users WHERE status = 1 ORDER BY role ASC, id ASC`);
      ok(res, {
        list: list.map((u) => ({
          id: u.id,
          username: u.username,
          displayName: u.display_name,
          role: u.role,
        })),
      });
    }),
  );

  app.use(config.apiPrefix, api);

  // 404
  app.use((req, _res, next) => {
    next(AppError.notFound(`接口不存在：${req.method} ${req.originalUrl}`));
  });

  app.use(payloadGuard);
  app.use(errorHandler);

  return app;
}

export { ERROR_CODES };
