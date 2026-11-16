/* SharePoint складът срещу имитация на Microsoft Graph: вход със сертификат, списъци, филтри, записи. */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createVerify } from 'node:crypto';
import { SharePointStore } from '../worker/src/store/sharepoint.js';
import { SCHEMA } from '../worker/src/schema.js';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const PEM = privateKey.export({ type: 'pkcs8', format: 'pem' });

function fakeGraph() {
  const state = { lists: {}, items: {}, seq: 0, calls: [], assertions: [] };
  globalThis.fetch = async (url, opts = {}) => {
    const u = new URL(url), method = opts.method || 'GET';
    state.calls.push(method + ' ' + decodeURIComponent(u.pathname + u.search));
    const ok = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
    if (u.host === 'login.microsoftonline.com') {
      const p = new URLSearchParams(opts.body.toString());
      state.assertions.push(p.get('client_assertion'));
      return ok({ access_token: 'tok', expires_in: 3600 });
    }
    assert.equal(opts.headers.Authorization, 'Bearer tok');
    const path = u.pathname.replace('/v1.0', '');
    let m;
    if (path === '/sites/contoso.sharepoint.com:/sites/adm') return ok({ id: 'site1' });
    if (path === '/sites/site1/lists' && method === 'GET') return ok({ value: Object.entries(state.lists).map(([displayName, id]) => ({ id, displayName })) });
    if (path === '/sites/site1/lists' && method === 'POST') {
      const b = JSON.parse(opts.body), id = 'L' + (++state.seq);
      state.lists[b.displayName] = id; state.items[id] = [];
      state.cols = state.cols || {}; state.cols[id] = b.columns;
      return ok({ id }, 201);
    }
    if ((m = /^\/sites\/site1\/lists\/(L\d+)\/columns$/.exec(path))) return ok({ value: (state.cols[m[1]] || []).map(c => ({ name: c.name })) });
    if ((m = /^\/sites\/site1\/lists\/(L\d+)\/items$/.exec(path))) {
      const list = state.items[m[1]];
      if (method === 'POST') {
        const it = { id: String(++state.seq), eTag: '"x,1"', fields: JSON.parse(opts.body).fields };
        list.push(it);
        return ok(it, 201);
      }
      const f = u.searchParams.get('$filter');
      let rows = list;
      if (f) {
        assert.equal(opts.headers.Prefer, 'HonorNonIndexedQueriesWarningMayFailRandomly');
        const conds = [...f.matchAll(/fields\/(\w+) eq '((?:[^']|'')*)'/g)].map(x => [x[1], x[2].replace(/''/g, "'")]);
        rows = list.filter(it => conds.every(([k, v]) => String(it.fields[k] || '') === v));
      }
      return ok({ value: rows });
    }
    if ((m = /^\/sites\/site1\/lists\/(L\d+)\/items\/(\d+)\/fields$/.exec(path)) && method === 'PATCH') {
      const it = state.items[m[1]].find(x => x.id === m[2]);
      Object.assign(it.fields, JSON.parse(opts.body));
      return ok(it.fields);
    }
    if ((m = /^\/sites\/site1\/lists\/(L\d+)\/items\/(\d+)$/.exec(path)) && method === 'DELETE') {
      state.items[m[1]] = state.items[m[1]].filter(x => x.id !== m[2]);
      return new Response(null, { status: 204 });
    }
    return ok({ error: { code: 'notFound', message: path } }, 404);
  };
  return state;
}

let lastAssertion = null;
const env = { SP_SITE: 'contoso.sharepoint.com:/sites/adm', MS_TENANT: 't', MS_CLIENT_ID: 'c', MS_PRIVATE_KEY: PEM, MS_CERT_SHA1: 'ab'.repeat(20), MS_CERT_SHA256: 'cd'.repeat(32) };

test('SharePoint: списъци, колони, записи и филтри', async () => {
  const g = fakeGraph();
  const store = new SharePointStore(env);
  const r = await store.ensureSchema();
  assert.equal(r.created.length, Object.keys(SCHEMA).length);
  // колоните: вътрешни имена със „z“, индексирани и многоредови
  const userCols = g.cols[g.lists['ADM Потребители']];
  assert.ok(userCols.find(c => c.name === 'zUsername').indexed);
  const caseCols = g.cols[g.lists['ADM Преписки']];
  assert.equal(caseCols.find(c => c.name === 'zSubject').text.allowMultipleLines, true);
  // повторната настройка не създава нищо
  assert.equal((await store.ensureSchema()).created.length, 0);

  const a = await store.insert('users', { username: "o'neil", name: '=HYPERLINK("x")', role: 'Служител' });
  await store.insert('users', { username: 'maria', name: 'Мария' });
  assert.equal(a.username, "o'neil");
  assert.equal(a.name, '=HYPERLINK("x")'); // формулата се пази като текст и се връща без апострофа
  const raw = g.items[g.lists['ADM Потребители']][0].fields;
  assert.equal(raw.zName, '\'=HYPERLINK("x")');
  assert.equal(raw.Title, "o'neil");
  const found = await store.list('users', { username: "o'neil" });
  assert.equal(found.length, 1);
  await store.patch('users', a._id, { active: 'Да', unknownField: 'x' });
  assert.equal((await store.list('users', { username: "o'neil" }))[0].active, 'Да');
  assert.equal((await store.list('users')).length, 2);
  await store.remove('users', a._id);
  assert.equal((await store.list('users')).length, 1);
  lastAssertion = g.assertions[0];
});

test('вход със сертификат: валидно RS256 твърдение', async () => {
  // токенът е взет в предишния тест; тук се проверява твърдението, с което е поискан
  const jwt = lastAssertion;
  assert.ok(jwt, 'няма твърдение');
  const [h, p, s] = jwt.split('.');
  const head = JSON.parse(Buffer.from(h, 'base64url'));
  assert.equal(head.alg, 'RS256');
  assert.ok(head.x5t && head['x5t#S256']);
  const claims = JSON.parse(Buffer.from(p, 'base64url'));
  assert.equal(claims.aud, 'https://login.microsoftonline.com/t/oauth2/v2.0/token');
  assert.equal(claims.iss, 'c');
  const v = createVerify('RSA-SHA256');
  v.update(h + '.' + p);
  assert.ok(v.verify(publicKey, Buffer.from(s, 'base64url')));
});
