/**
 * 重置数据库：清空所有业务表并重新灌入演示数据。
 * 用法：pnpm -C apps/server db:reset
 */
import { getDb, initDatabase, resetDatabase, setMeta, tableCount } from '../db/index.js';
import { seedDemoDataIfEmpty } from '../db/seed.js';

const db = getDb();
// 只建表 + 管理员，不灌演示数据
initDatabase(db, { demoData: false });
resetDatabase(db);
setMeta(db, 'demo_seeded', 'false');
const r = seedDemoDataIfEmpty(db);

console.log(`数据库已重置（${r.seeded ? '演示数据已重新灌入' : `未灌入：${r.reason}`}）`);
console.log(`  项目 ${tableCount(db, 'projects')}`);
console.log(`  批次 ${tableCount(db, 'scan_tasks')}`);
console.log(`  漏洞 ${tableCount(db, 'vulnerabilities')}`);
console.log(`  样本 ${tableCount(db, 'samples')}`);
console.log(`  事件 ${tableCount(db, 'vuln_events')}`);
console.log(`  用户 ${tableCount(db, 'users')}`);
console.log(`  Key  ${tableCount(db, 'api_keys')}`);
db.close();
