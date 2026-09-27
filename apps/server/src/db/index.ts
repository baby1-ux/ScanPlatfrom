/**
 * 数据库适配层。
 *
 * 设计目标：业务代码只依赖 `Db` 接口，不依赖具体驱动。
 *  - 当前实现：SQLite（`node:sqlite`，Node 20.11+ 内置，零原生依赖、零编译）
 *  - 后续切 MySQL：实现 `Db` 接口（`?` 占位符 + `run/get/all/exec/tx` 语义一致），
 *    在 `createDb()` 里按 `DB_CLIENT` 分支即可，业务模块无需改动。
 *
 * 之所以先用 SQLite 落地：需求方指定 MySQL 8.0，但本地无数据库实例时
 * 用同样的表结构与 SQL 语义先跑通全链路，换库时只换这一层。
 */
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { config } from '../config/index.js';
import { SCHEMA_SQL, TABLE_NAMES } from './schema.js';
import { seedAdminUser, seedDemoDataIfEmpty } from './seed.js';

export type SqlValue = string | number | null | Uint8Array;

export interface Db {
  readonly client: 'sqlite' | 'mysql';
  /** 执行一段不含参数的 DDL/多语句 */
  exec(sql: string): void;
  /** 写入，返回受影响行数与自增主键 */
  run(sql: string, params?: SqlValue[]): { changes: number; lastInsertRowid: number };
  get<T = Record<string, unknown>>(sql: string, params?: SqlValue[]): T | undefined;
  all<T = Record<string, unknown>>(sql: string, params?: SqlValue[]): T[];
  /** 事务包装：回调抛错则整体回滚；支持嵌套 */
  tx<T>(fn: () => T): T;
  close(): void;
}

class SqliteDb implements Db {
  readonly client = 'sqlite' as const;
  private db: DatabaseSync;
  private txDepth = 0;

  constructor(file: string) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    this.db = new DatabaseSync(file);
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec('PRAGMA foreign_keys = ON;');
    this.db.exec('PRAGMA busy_timeout = 5000;');
  }

  exec(sql: string): void {
    this.db.exec(sql);
  }

  run(sql: string, params: SqlValue[] = []) {
    const r = this.db.prepare(sql).run(...(params as never[]));
    return {
      changes: Number(r.changes ?? 0),
      lastInsertRowid: Number(r.lastInsertRowid ?? 0),
    };
  }

  get<T = Record<string, unknown>>(sql: string, params: SqlValue[] = []) {
    return this.db.prepare(sql).get(...(params as never[])) as T | undefined;
  }

  all<T = Record<string, unknown>>(sql: string, params: SqlValue[] = []) {
    return this.db.prepare(sql).all(...(params as never[])) as T[];
  }

  tx<T>(fn: () => T): T {
    if (this.txDepth > 0) {
      this.txDepth += 1;
      try {
        return fn();
      } finally {
        this.txDepth -= 1;
      }
    }
    this.db.exec('BEGIN IMMEDIATE');
    this.txDepth = 1;
    try {
      const out = fn();
      this.db.exec('COMMIT');
      return out;
    } catch (err) {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        /* 回滚失败不应掩盖原始错误 */
      }
      throw err;
    } finally {
      this.txDepth = 0;
    }
  }

  close(): void {
    this.db.close();
  }
}

let instance: Db | null = null;

export function createDb(): Db {
  if (config.db.client === 'mysql') {
    throw new Error(
      'DB_CLIENT=mysql 尚未接入。请实现 src/db/index.ts 中 SqliteDb 对应的 MySQL 适配器' +
        '（Db 接口已定义好，业务模块无需改动），或设 DB_CLIENT=sqlite 使用内置 SQLite。',
    );
  }
  return new SqliteDb(config.db.sqlitePath);
}

export function getDb(): Db {
  if (!instance) instance = createDb();
  return instance;
}

/** 建表 + 默认管理员 + （可选）演示数据；仅首次启动做重活 */
export function initDatabase(db: Db, opts: { demoData?: boolean } = {}): void {
  db.exec(SCHEMA_SQL);
  seedAdminUser(db, config.admin.username, config.admin.password);
  if (opts.demoData ?? config.seedDemoData) {
    seedDemoDataIfEmpty(db);
  }
}

export function resetDatabase(db: Db): void {
  db.tx(() => {
    for (const t of TABLE_NAMES) db.exec(`DELETE FROM ${t};`);
    try {
      db.exec(`DELETE FROM sqlite_sequence;`);
    } catch {
      /* 表不存在时忽略 */
    }
  });
}

export function tableCount(db: Db, table: string): number {
  const row = db.get<{ c: number }>(`SELECT COUNT(*) AS c FROM ${table}`);
  return Number(row?.c ?? 0);
}

export function setMeta(db: Db, k: string, v: string): void {
  db.run(
    `INSERT INTO meta(k, v, updated_at) VALUES(?, ?, ?)
     ON CONFLICT(k) DO UPDATE SET v = excluded.v, updated_at = excluded.updated_at`,
    [k, v, new Date().toISOString()],
  );
}

export function getMeta(db: Db, k: string): string | null {
  const row = db.get<{ v: string }>(`SELECT v FROM meta WHERE k = ?`, [k]);
  return row?.v ?? null;
}
