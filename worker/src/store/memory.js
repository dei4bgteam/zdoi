/* Склад в паметта: за тестовете и локалния сървър. Същият интерфейс като SharePoint склада. */

import { SCHEMA, toFields, readCell } from '../schema.js';

export class MemoryStore {
  constructor() {
    this.tables = {};
    this.seq = 0;
    Object.keys(SCHEMA).forEach(k => { this.tables[k] = new Map(); });
  }

  out(table, id, rec) {
    const o = { _id: id };
    Object.keys(SCHEMA[table][1]).forEach(k => { o[k] = readCell(rec[k]); });
    return o;
  }

  async list(table, where = {}) {
    const rows = [];
    for (const [id, rec] of this.tables[table]) {
      if (Object.keys(where).every(k => String(rec[k] || '') === String(where[k]))) rows.push(this.out(table, id, rec));
    }
    return rows;
  }

  async get(table, id) {
    const rec = this.tables[table].get(String(id));
    return rec ? this.out(table, String(id), rec) : null;
  }

  async insert(table, obj) {
    const id = String(++this.seq);
    this.tables[table].set(id, toFields(table, obj));
    return this.get(table, id);
  }

  async patch(table, id, obj) {
    const rec = this.tables[table].get(String(id));
    if (!rec) throw new Error('missing ' + table + '/' + id);
    Object.assign(rec, toFields(table, obj));
  }

  async remove(table, id) {
    this.tables[table].delete(String(id));
  }

  async ensureSchema() { return { created: [] }; }

  async uploadFile(path, bytes, contentType) {
    this.files = this.files || new Map();
    const id = 'f' + (++this.seq);
    this.files.set(id, { path, bytes: new Uint8Array(bytes), contentType });
    return { id, webUrl: 'memory://ADM/' + path, name: path.split('/').pop(), size: bytes.length };
  }

  async downloadFile(id) {
    const f = this.files && this.files.get(id);
    if (!f) throw new Error('missing file ' + id);
    return f.bytes;
  }
}

/* ключ-стойност с изтичане – заместител на Workers KV */
export class MemoryKV {
  constructor() { this.m = new Map(); }
  async get(k) {
    const e = this.m.get(k);
    if (!e) return null;
    if (e.exp && e.exp < Date.now()) { this.m.delete(k); return null; }
    return e.v;
  }
  async put(k, v, opts) {
    const ttl = opts && opts.expirationTtl;
    this.m.set(k, { v: String(v), exp: ttl ? Date.now() + ttl * 1000 : 0 });
  }
  async delete(k) { this.m.delete(k); }
}
