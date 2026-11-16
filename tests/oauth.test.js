import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker/src/index.js';
import { ready, addUser, ORIGIN } from './helpers.js';

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

const b64u = o => Buffer.from(JSON.stringify(o)).toString('base64url');
const idToken = claims => b64u({ alg: 'none' }) + '.' + b64u(claims) + '.x';

function oauthEnv(env) {
  return Object.assign(env, { GOOGLE_CLIENT_ID: 'gid', GOOGLE_CLIENT_SECRET: 'gsecret', DISCORD_CLIENT_ID: 'did', DISCORD_CLIENT_SECRET: 'dsecret' });
}

/* доставчикът: подменя fetch към Google/Discord; claims – какво „връща“ доставчикът */
function fakeProvider(claims, discordUser) {
  const seen = [];
  globalThis.fetch = async (url, init) => {
    const u = String(url);
    if (u.startsWith('https://oauth2.googleapis.com/token')) {
      seen.push(Object.fromEntries(init.body));
      return new Response(JSON.stringify({ access_token: 'at', id_token: idToken(Object.assign({ iss: 'https://accounts.google.com', aud: 'gid', exp: Date.now() / 1000 + 300 }, claims())) }), { status: 200 });
    }
    if (u.startsWith('https://discord.com/api/oauth2/token')) { seen.push(Object.fromEntries(init.body)); return new Response(JSON.stringify({ access_token: 'dt' }), { status: 200 }); }
    if (u.startsWith('https://discord.com/api/users/@me')) return new Response(JSON.stringify(discordUser), { status: 200 });
    return realFetch(url, init);
  };
  return seen;
}

async function get(env, path, cookie = '') {
  const r = await worker.fetch(new Request(ORIGIN + path, { headers: Object.assign({ 'CF-Connecting-IP': '203.0.113.9' }, cookie ? { Cookie: cookie } : {}) }), env);
  return { status: r.status, location: r.headers.get('Location') || '', cookies: r.headers.getSetCookie ? r.headers.getSetCookie() : [r.headers.get('Set-Cookie')].filter(Boolean) };
}

/* пълен вход: start → (доставчик) → callback; връща пренасочването и бисквитките */
async function flow(env, p, { link = '', session = '', state: forceState } = {}) {
  const s = await get(env, '/api/oauth/' + p + '/start' + (link ? '?link=1' : ''), session);
  assert.equal(s.status, 302);
  const loc = new URL(s.location);
  const state = loc.searchParams.get('state'), nonce = loc.searchParams.get('nonce');
  const oc = (s.cookies.find(c => c.startsWith('adm_o=')) || '').split(';')[0];
  const cb = await get(env, '/api/oauth/' + p + '/callback?code=abc&state=' + (forceState || state), oc);
  return { start: loc, nonce, cb };
}

test('Google: свързване по потвърден имейл, после вход по профила; непознат имейл – отказ', async () => {
  const { env, outbox, admin } = await ready();
  oauthEnv(env);
  await addUser(env, outbox, admin, 'maria', 'Служител');
  let claims = {};
  const seen = fakeProvider(() => claims);

  // кои доставчици има
  const pr = await admin.call('oauth.providers');
  assert.deepEqual(pr.providers.map(p => p.id), ['google', 'discord']);

  // имейлът съвпада и е потвърден → свързва и влиза
  let st = await get(env, '/api/oauth/google/start');
  const loc = new URL(st.location);
  assert.equal(loc.origin + loc.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
  assert.equal(loc.searchParams.get('redirect_uri'), ORIGIN + '/api/oauth/google/callback');
  assert.equal(loc.searchParams.get('code_challenge_method'), 'S256');
  const oc = st.cookies.find(c => c.startsWith('adm_o=')).split(';')[0];
  claims = { sub: 'g-1', email: 'Maria@Example.org', email_verified: true, nonce: loc.searchParams.get('nonce') };
  let cb = await get(env, '/api/oauth/google/callback?code=abc&state=' + loc.searchParams.get('state'), oc);
  assert.equal(cb.location, ORIGIN + '/#/dashboard');
  assert.ok(cb.cookies.some(c => /^adm_s=[0-9a-f]{64}/.test(c)));
  assert.ok(seen[0].code_verifier && seen[0].client_secret === 'gsecret');
  // повторно ползване на същия state – отказ
  cb = await get(env, '/api/oauth/google/callback?code=abc&state=' + loc.searchParams.get('state'), oc);
  assert.match(decodeURIComponent(cb.location), /изтече/);

  // вече свързан: вход по sub дори при друг имейл
  st = await get(env, '/api/oauth/google/start');
  let l2 = new URL(st.location);
  claims = { sub: 'g-1', email: 'other@gmail.com', email_verified: true, nonce: l2.searchParams.get('nonce') };
  cb = await get(env, '/api/oauth/google/callback?code=x&state=' + l2.searchParams.get('state'), st.cookies.find(c => c.startsWith('adm_o=')).split(';')[0]);
  assert.equal(cb.location, ORIGIN + '/#/dashboard');

  // непознат имейл → отказ, без нов потребител
  st = await get(env, '/api/oauth/google/start');
  l2 = new URL(st.location);
  claims = { sub: 'g-2', email: 'stranger@gmail.com', email_verified: true, nonce: l2.searchParams.get('nonce') };
  cb = await get(env, '/api/oauth/google/callback?code=x&state=' + l2.searchParams.get('state'), st.cookies.find(c => c.startsWith('adm_o=')).split(';')[0]);
  assert.match(decodeURIComponent(cb.location), /#\/login\?err=Няма потребител/);
  assert.ok(!cb.cookies.some(c => /^adm_s=[0-9a-f]{64}/.test(c)));
  assert.equal((await admin.call('users.list')).users.length, 2);

  // непотвърден имейл → не се свързва
  st = await get(env, '/api/oauth/google/start');
  l2 = new URL(st.location);
  claims = { sub: 'g-3', email: 'admin@example.org', email_verified: false, nonce: l2.searchParams.get('nonce') };
  cb = await get(env, '/api/oauth/google/callback?code=x&state=' + l2.searchParams.get('state'), st.cookies.find(c => c.startsWith('adm_o=')).split(';')[0]);
  assert.match(decodeURIComponent(cb.location), /err=/);

  // грешен nonce
  st = await get(env, '/api/oauth/google/start');
  l2 = new URL(st.location);
  claims = { sub: 'g-1', email: 'maria@example.org', email_verified: true, nonce: 'wrong' };
  cb = await get(env, '/api/oauth/google/callback?code=x&state=' + l2.searchParams.get('state'), st.cookies.find(c => c.startsWith('adm_o=')).split(';')[0]);
  assert.match(decodeURIComponent(cb.location), /nonce/);
});

test('защити: state от друг браузър, изключен доставчик, спрян потребител', async () => {
  const { env, outbox, admin } = await ready();
  oauthEnv(env);
  await addUser(env, outbox, admin, 'ivan', 'Служител');
  let claims = {};
  fakeProvider(() => claims);
  // state без бисквитката на същия браузър
  const st = await get(env, '/api/oauth/google/start');
  const loc = new URL(st.location);
  claims = { sub: 'g-9', email: 'ivan@example.org', email_verified: true, nonce: loc.searchParams.get('nonce') };
  const cb = await get(env, '/api/oauth/google/callback?code=x&state=' + loc.searchParams.get('state'), 'adm_o=' + 'a'.repeat(64));
  assert.match(decodeURIComponent(cb.location), /друг браузър/);

  // администраторът изключва Google
  assert.equal((await admin.call('oauth.save', { google: false, discord: true, microsoft: true, autoLink: true })).ok, true);
  assert.deepEqual((await admin.call('oauth.providers')).providers.map(p => p.id), ['discord']);
  const off = await get(env, '/api/oauth/google/start');
  assert.match(decodeURIComponent(off.location), /изключен/);
  await admin.call('oauth.save', { google: true, discord: true, microsoft: true, autoLink: true });

  // спрян потребител не влиза
  const list = (await admin.call('users.list')).users;
  const ivan = list.find(u => u.username === 'ivan');
  await admin.call('users.save', Object.assign({}, ivan, { active: false }));
  const st2 = await get(env, '/api/oauth/google/start');
  const l2 = new URL(st2.location);
  claims = { sub: 'g-9', email: 'ivan@example.org', email_verified: true, nonce: l2.searchParams.get('nonce') };
  const cb2 = await get(env, '/api/oauth/google/callback?code=x&state=' + l2.searchParams.get('state'), st2.cookies.find(c => c.startsWith('adm_o=')).split(';')[0]);
  assert.ok(!cb2.cookies.some(c => /^adm_s=[0-9a-f]{64}/.test(c)));
  assert.match(decodeURIComponent(cb2.location), /спрян/);
});

test('Discord: свързване от „Моят профил“ и вход с 2FA код', async () => {
  const { env, admin, outbox } = await ready();
  oauthEnv(env);
  fakeProvider(() => ({}), { id: 'd-7', email: 'nick@gmail.com', verified: true, username: 'nick' });
  // без автоматично свързване (имейлът е различен) – първо отказ
  let s = await get(env, '/api/oauth/discord/start');
  let cb = await get(env, '/api/oauth/discord/callback?code=x&state=' + new URL(s.location).searchParams.get('state'), s.cookies.find(c => c.startsWith('adm_o=')).split(';')[0]);
  assert.match(decodeURIComponent(cb.location), /err=/);

  // свързване: само с валидна сесия
  const noSession = await get(env, '/api/oauth/discord/start?link=1');
  assert.match(decodeURIComponent(noSession.location), /err=/);
  s = await get(env, '/api/oauth/discord/start?link=1', admin.cookie);
  cb = await get(env, '/api/oauth/discord/callback?code=x&state=' + new URL(s.location).searchParams.get('state'), s.cookies.find(c => c.startsWith('adm_o=')).split(';')[0]);
  assert.match(decodeURIComponent(cb.location), /#\/profile\?ok=/);
  const me = await admin.call('me');
  assert.equal(me.me.linked.discord.email, 'nick@gmail.com');

  // 2FA: включване и вход с Discord → код по имейл
  const st = await admin.call('twofa.start', { hash: Buffer.from('pw:admin-pass'.padEnd(32, '.')).toString('base64') });
  const code = /Код: (\d{8})/.exec(outbox.pop().text)[1];
  await admin.call('twofa.confirm', { ticket: st.ticket, code });
  s = await get(env, '/api/oauth/discord/start');
  cb = await get(env, '/api/oauth/discord/callback?code=x&state=' + new URL(s.location).searchParams.get('state'), s.cookies.find(c => c.startsWith('adm_o=')).split(';')[0]);
  assert.match(cb.location, /#\/code\/[0-9a-f]{64}$/);
  assert.ok(!cb.cookies.some(c => /^adm_s=[0-9a-f]{64}/.test(c)));
  assert.match(outbox.pop().subject, /код за вход/);

  // премахване
  assert.equal((await admin.call('oauth.unlink', { provider: 'discord' })).ok, true);
  assert.equal((await admin.call('me')).me.linked.discord, undefined);
});
