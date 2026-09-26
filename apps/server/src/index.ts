import { createApp } from './app.js';
import { config } from './config/index.js';
import { getDb, initDatabase, tableCount } from './db/index.js';

function main(): void {
  const db = getDb();
  const started = Date.now();
  initDatabase(db);

  const app = createApp();
  const server = app.listen(config.port, () => {
    const boot = Date.now() - started;
    /* eslint-disable no-console */
    console.log('');
    console.log('  漏洞管理平台 · 后端已启动');
    console.log(`  ─────────────────────────────────────────────`);
    console.log(`  地址        http://127.0.0.1:${config.port}${config.apiPrefix}`);
    console.log(`  健康检查    http://127.0.0.1:${config.port}/health`);
    console.log(`  数据库      ${config.db.client} → ${config.db.sqlitePath}`);
    console.log(`  模型服务    ${config.ml.url}（fallback=${config.ml.fallback}）`);
    console.log(`  数据量      项目 ${tableCount(db, 'projects')} / 批次 ${tableCount(db, 'scan_tasks')} / ` +
      `漏洞 ${tableCount(db, 'vulnerabilities')} / 样本 ${tableCount(db, 'samples')}`);
    console.log(`  初始化耗时  ${boot}ms`);
    console.log(`  默认账号    ${config.admin.username} / ${config.admin.password}（演示库；生产请立即改密）`);
    console.log('');
    /* eslint-enable no-console */
  });

  const shutdown = (signal: string) => {
    console.log(`\n收到 ${signal}，正在关闭…`);
    server.close(() => {
      try {
        db.close();
      } catch {
        /* ignore */
      }
      process.exit(0);
    });
    // 兜底：10s 内没关干净就强退
    setTimeout(() => process.exit(0), 10_000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main();
