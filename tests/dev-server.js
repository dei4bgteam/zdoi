/*
 * Локален преглед: node tests/dev-server.js → http://127.0.0.1:8787
 * Сайтът и Worker-ът на един адрес, с данни в паметта (без SharePoint). Писмата се печатат в конзолата.
 * Създава администратор admin с парола „admin-parola-123“ и примерни преписки.
 */

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, extname, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import worker, { setup } from '../worker/src/index.js';
import { MemoryStore, MemoryKV } from '../worker/src/store/memory.js';
import { makeApp } from '../worker/src/core.js';
import * as auth from '../worker/src/auth.js';
import { webcrypto } from 'node:crypto';

const PORT = Number(process.env.PORT) || 8787;
const ORIGIN = 'http://127.0.0.1:' + PORT;
const SITE = fileURLToPath(new URL('../site/', import.meta.url));
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.ico': 'image/x-icon', '.txt': 'text/plain' };

const env = {
  APP_URL: ORIGIN + '/', PEPPER: 'dev-pepper-'.padEnd(48, 'x'), SETUP_KEY: 'dev',
  __store: new MemoryStore(), __kv: new MemoryKV(),
  __mailer: async (to, subject, text) => console.log('\n✉  ' + to + ' – ' + subject + '\n' + text.split('\n').map(l => '   ' + l).join('\n'))
};

/* същото PBKDF2 като в браузъра */
async function preHash(username, password) {
  const enc = new TextEncoder();
  const key = await webcrypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await webcrypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', iterations: 600000, salt: enc.encode(`zdoi-adm:v1:${username}`) }, key, 256);
  return Buffer.from(bits).toString('base64');
}

async function seed() {
  const app = makeApp(env, env.__store, env.__kv, null);
  await setup(app, { username: 'admin', email: 'admin@example.org', name: 'Администратор' });
  const u = await auth.findUser(app, 'admin');
  await env.__store.patch('users', u._id, Object.assign(await auth.setPassword(app, await preHash('admin', 'admin-parola-123')), { inviteHash: '', inviteExp: '' }));
  const ctx = { username: 'admin', name: 'Администратор', role: 'Администратор', perms: auth.permsOf(u) };
  const { caseCreate, courtSave } = await import('../worker/src/cases.js');
  const base = { kind: 'Достъп до обществена информация', channel: 'Писмено', applicantType: 'Гражданин' };
  const day = n => new Date(Date.now() - n * 864e5).toISOString().slice(0, 10);
  await caseCreate(Object.assign({}, base, { regDate: day(20), applicantName: 'Иван Петров', applicantEmail: 'ivan@example.org', subject: 'Договори за почистване за 2025 г.', owner: 'admin' }), ctx, app);
  await caseCreate(Object.assign({}, base, { regDate: day(12), applicantName: 'Сдружение „Прозрачност“', applicantType: 'Неправителствена организация', applicantEmail: 'office@example.org', subject: 'Разходи за реклама', owner: 'admin' }), ctx, app);
  const { regNo } = await caseCreate(Object.assign({}, base, { regDate: day(2), applicantName: 'Мария Георгиева', applicantAddress: 'гр. София, ул. Шипка 1', subject: 'Протоколи от общински съвет' }), ctx, app);
  await courtSave({ regNo, court: 'Административен съд – София-град', caseNo: '4521', year: String(new Date().getFullYear()), kind: 'Жалба срещу мълчалив отказ', instance: 'Административен съд', status: 'Насрочено', nextHearing: day(-10) }, ctx, app);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, ORIGIN);
    if (url.pathname.startsWith('/api')) {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const headers = new Headers();
      Object.entries(req.headers).forEach(([k, v]) => headers.set(k, Array.isArray(v) ? v.join(', ') : v));
      headers.set('CF-Connecting-IP', '127.0.0.1');
      const r = await worker.fetch(new Request(url, { method: req.method, headers, body: req.method === 'POST' ? Buffer.concat(chunks) : undefined }), env);
      res.writeHead(r.status, Object.fromEntries(r.headers));
      res.end(Buffer.from(await r.arrayBuffer()));
      return;
    }
    const path = normalize(join(SITE, url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname)));
    if (!path.startsWith(SITE)) { res.writeHead(403); res.end(); return; }
    try {
      const body = await readFile(path);
      res.writeHead(200, { 'Content-Type': TYPES[extname(path)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
      res.end(body);
    } catch (_) {
      res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(await readFile(join(SITE, '404.html')));
    }
  } catch (e) {
    console.error(e);
    res.writeHead(500); res.end('error');
  }
});

await seed();
server.listen(PORT, '127.0.0.1', () => console.log('\nADM ЗДОИ4You (локално): ' + ORIGIN + '\nВход: admin / admin-parola-123\n'));
