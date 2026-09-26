import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
/** apps/server 目录 */
export const SERVER_ROOT = path.resolve(__dirname, '..', '..');
/** 单仓根目录 */
export const REPO_ROOT = path.resolve(SERVER_ROOT, '..', '..');

function num(v: string | undefined, fallback: number): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function bool(v: string | undefined, fallback: boolean): boolean {
  if (v === undefined || v === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(v.toLowerCase());
}

export const config = {
  env: process.env.NODE_ENV ?? 'development',
  port: num(process.env.PORT, 3000),
  apiPrefix: '/api/v1',

  db: {
    client: (process.env.DB_CLIENT ?? 'sqlite').toLowerCase(),
    sqlitePath: path.isAbsolute(process.env.SQLITE_PATH ?? '')
      ? (process.env.SQLITE_PATH as string)
      : path.resolve(SERVER_ROOT, process.env.SQLITE_PATH ?? '../../data/vuln_platform.db'),
    mysql: {
      host: process.env.MYSQL_HOST ?? '127.0.0.1',
      port: num(process.env.MYSQL_PORT, 3306),
      user: process.env.MYSQL_USER ?? 'root',
      password: process.env.MYSQL_PASSWORD ?? '',
      database: process.env.MYSQL_DATABASE ?? 'vuln_platform',
    },
  },

  jwt: {
    secret: process.env.JWT_SECRET ?? 'dev-only-change-me-in-production',
    expiresIn: process.env.JWT_EXPIRES_IN ?? '8h',
  },

  admin: {
    username: process.env.ADMIN_USERNAME ?? 'admin',
    password: process.env.ADMIN_PASSWORD ?? 'Admin@12345',
  },

  seedDemoData: bool(process.env.SEED_DEMO_DATA, true),

  corsOrigins: (process.env.CORS_ORIGIN ?? 'http://localhost:5173,http://127.0.0.1:5173')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),

  logLevel: process.env.LOG_LEVEL ?? 'info',

  ml: {
    url: (process.env.ML_SERVICE_URL ?? 'http://127.0.0.1:8000').replace(/\/+$/, ''),
    fallback: (process.env.ML_FALLBACK ?? 'fallback').toLowerCase() as 'fallback' | 'strict',
    timeoutMs: num(process.env.ML_TIMEOUT_MS, 8000),
  },
} as const;

if (config.jwt.secret === 'dev-only-change-me-in-production' && config.env === 'production') {
  // 生产环境务必覆盖，否则任何人可伪造 token
  throw new Error('生产环境必须设置 JWT_SECRET');
}
