/**
 * 只灌演示数据（表为空时才写）。
 * 用法：pnpm -C apps/server db:seed
 */
import { getDb, initDatabase } from '../db/index.js';
import { seedDemoDataIfEmpty } from '../db/seed.js';

const db = getDb();
initDatabase(db, { demoData: false });
const r = seedDemoDataIfEmpty(db);
console.log(r.seeded ? '演示数据已灌入' : `跳过灌入（原因：${r.reason}）`);
db.close();
