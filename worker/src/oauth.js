/*
 * Вход с Google, Microsoft (само акаунтите на организацията) и Discord.
 *
 * Системата е вътрешна: външният вход НЕ създава потребители. Пуска само активен потребител, който
 *   – е свързал профила си от „Моят профил“, или
 *   – има в системата същия имейл, потвърден от доставчика (ако администраторът не е изключил това).
 * Двуфакторният вход с код по имейл важи и тук.
 *
 * GET /api/oauth/<доставчик>/start[?link=1]  → към доставчика (link=1: свързване към влезлия потребител)
 * GET /api/oauth/<доставчик>/callback        → обратно; сесия и пренасочване към #/dashboard
 *
 * Защити: state в KV, вързан с бисквитка adm_o (SameSite=Lax) на същия браузър; nonce в id_token; PKCE (Google, Microsoft).
 * id_token се взема пряко от доставчика по TLS с удостоверяване на клиента, затова не се проверява подписът му (OIDC Core 3.1.3.7).
 */

import { fail, str, line, stamp } from './util.js';
import { sha256, randomToken, b64url, sameText, clientAssertion } from './crypto.js';
import { msConfig } from './graph.js';
import { audit, throttle, setting, setSetting } from './core.js';
import { findUser, dropUser, openSession, startCode, recordLogin, oauthOf, cookieToken, authenticate } from './auth.js';

export const PROVIDERS = {
  google: {
    label: 'Google',
    configured: env => !!(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET),
    clientId: env => env.GOOGLE_CLIENT_ID,
    authUrl: () => 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: () => 'https://oauth2.googleapis.com/token',
    scope: 'openid email profile', pkce: true, extra: { prompt: 'select_account' },
    secret: async (env, body) => { body.set('client_secret', env.GOOGLE_CLIENT_SECRET); },
    async identity(env, tok, st) {
      const c = idClaims(tok, st, env.GOOGLE_CLIENT_ID);
      if (!['https://accounts.google.com', 'accounts.google.com'].includes(c.iss)) fail('oauth', 'Невалиден отговор от Google.');
      return { id: String(c.sub), email: c.email, verified: c.email_verified === true || c.email_verified === 'true', name: c.name || '' };
    }
  },
  microsoft: {
    label: 'Microsoft',
    configured: env => !!(env.MS_LOGIN_CLIENT_ID && msConfig(env)),
    clientId: env => env.MS_LOGIN_CLIENT_ID,
    authUrl: env => 'https://login.microsoftonline.com/' + env.MS_TENANT + '/oauth2/v2.0/authorize',
    tokenUrl: env => 'https://login.microsoftonline.com/' + env.MS_TENANT + '/oauth2/v2.0/token',
    scope: 'openid email profile', pkce: true, extra: { prompt: 'select_account' },
    // без client secret: същият сертификат като сървърното приложение
    secret: async (env, body, url) => {
      body.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
      body.set('client_assertion', await clientAssertion(Object.assign({}, msConfig(env), { clientId: env.MS_LOGIN_CLIENT_ID }), url));
    },
    async identity(env, tok, st) {
      const c = idClaims(tok, st, env.MS_LOGIN_CLIENT_ID);
      // само акаунти от организацията (тенанта) – там имейлите се управляват от администратора
      if (c.tid !== env.MS_TENANT || c.iss !== 'https://login.microsoftonline.com/' + env.MS_TENANT + '/v2.0') fail('oauth', 'Влезте с акаунт на организацията.');
      const email = c.email || c.preferred_username || '';
      return { id: String(c.oid), email, verified: !!email, name: c.name || '' };
    }
  },
  discord: {
    label: 'Discord',
    configured: env => !!(env.DISCORD_CLIENT_ID && env.DISCORD_CLIENT_SECRET),
    clientId: env => env.DISCORD_CLIENT_ID,
    authUrl: () => 'https://discord.com/oauth2/authorize',
    tokenUrl: () => 'https://discord.com/api/oauth2/token',
    scope: 'identify email', pkce: false, extra: { prompt: 'consent' },
    secret: async (env, body) => { body.set('client_id', env.DISCORD_CLIENT_ID); body.set('client_secret', env.DISCORD_CLIENT_SECRET); },
    async identity(env, tok) {
      const r = await fetch('https://discord.com/api/users/@me', { headers: { Authorization: 'Bearer ' + tok.access_token } });
      if (!r.ok) fail('oauth', 'Discord не върна профила (' + r.status + ').');
      const u = await r.json();
      return { id: String(u.id), email: u.email || '', verified: u.verified === true, name: u.global_name || u.username || '' };
    }
  }
};

const NAMES = Object.keys(PROVIDERS);
/* КЕП не е OAuth: вход с подпис на карта през BISS (kep.js), но се включва/изключва и свързва оттук */
const ALL = NAMES.concat('kep');
const kepReady = async app => !!(await app.kv.get('kep:cert'));
const redirectUri = (app, p) => app.cfg.appUrl.replace(/\/$/, '') + '/api/oauth/' + p + '/callback';

function jwtClaims(t) {
  const part = String(t || '').split('.')[1];
  if (!part) fail('oauth', 'Липсва id_token.');
  const bin = atob(part.replace(/-/g, '+').replace(/_/g, '/'));
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, ch => ch.charCodeAt(0))));
}

function idClaims(tok, st, clientId) {
  const c = jwtClaims(tok.id_token);
  const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (!aud.includes(clientId)) fail('oauth', 'id_token е за друго приложение.');
  if (!c.exp || c.exp * 1000 < Date.now() - 60000) fail('oauth', 'id_token е изтекъл.');
  if (!st.nonce || !sameText(String(c.nonce || ''), st.nonce)) fail('oauth', 'Невалиден nonce.');
  return c;
}

/* ---------- настройки (управляват се от „Система“) ---------- */

export async function oauthSettings(app) {
  let off = [];
  try { off = JSON.parse((await setting(app, 'oauthOff', '[]')) || '[]'); } catch (_) { off = []; }
  return { off: Array.isArray(off) ? off : [], autoLink: (await setting(app, 'oauthAutoLink', 'Да')) === 'Да' };
}

export async function enabledProviders(app) {
  const s = await oauthSettings(app);
  const out = NAMES.filter(p => PROVIDERS[p].configured(app.env) && !s.off.includes(p));
  if (!s.off.includes('kep') && (await kepReady(app))) out.push('kep');
  return out;
}

/* публично: кои бутони да има на страницата за вход */
export async function providersList(d, ctx, app) {
  return { providers: (await enabledProviders(app)).map(p => ({ id: p, label: p === 'kep' ? 'КЕП' : PROVIDERS[p].label })) };
}

export async function oauthSystem(app) {
  const s = await oauthSettings(app);
  return NAMES.map(p => ({ id: p, label: PROVIDERS[p].label, configured: PROVIDERS[p].configured(app.env), on: !s.off.includes(p), redirect: redirectUri(app, p) }))
    .concat([{ id: 'kep', label: 'КЕП (смарт карта през BISS)', configured: await kepReady(app), on: !s.off.includes('kep'), redirect: 'вход с подпис на картата; свързва се от „Моят профил“' }, { id: '_autoLink', on: s.autoLink }]);
}

export async function oauthSystemSave(d, ctx, app) {
  const off = ALL.filter(p => d[p] === false);
  await setSetting(app, 'oauthOff', JSON.stringify(off));
  await setSetting(app, 'oauthAutoLink', d.autoLink === false ? 'Не' : 'Да');
  await audit(app, ctx.username, 'Настройки за външен вход', '', 'изключени: ' + (off.join(', ') || 'няма') + '; свързване по имейл: ' + (d.autoLink === false ? 'не' : 'да'));
  return {};
}

/* премахване на свързан профил: потребителят за себе си, администраторът – за всеки */
export async function oauthUnlink(d, ctx, app) {
  const p = line(d.provider, 20);
  if (!ALL.includes(p)) fail('value', 'Непознат доставчик.');
  const username = d.username && ctx.admin ? str(d.username, 40).toLowerCase() : ctx.username;
  const u = await findUser(app, username);
  if (!u) fail('notfound', 'Потребителят не е намерен.');
  const o = oauthOf(u);
  if (!o[p]) return {};
  delete o[p];
  await app.store.patch('users', u._id, { oauth: JSON.stringify(o) });
  await dropUser(app, username);
  await audit(app, ctx.username, 'Премахнат вход с ' + (p === 'kep' ? 'КЕП' : PROVIDERS[p].label), username, '');
  return {};
}

/* ---------- HTTP ---------- */

function redirect(to, cookies = []) {
  const h = new Headers({ Location: to, 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
  cookies.forEach(c => h.append('Set-Cookie', c));
  return new Response(null, { status: 302, headers: h });
}

const secure = app => app.cfg.appUrl.startsWith('https:') ? '; Secure' : '';
const stateCookie = (app, v) => 'adm_o=' + v + '; Path=/api/oauth; HttpOnly; SameSite=Lax; Max-Age=' + (v ? 600 : 0) + secure(app);
const back = (app, hash) => app.cfg.appUrl + '#' + hash;
const fromCookie = req => { const m = /(?:^|;\s*)adm_o=([0-9a-f]{64})(?:;|$)/.exec(req.headers.get('Cookie') || ''); return m ? m[1] : ''; };

/* sessionCookie: (app, token) → Set-Cookie за сесията (от index.js) */
export async function handleOAuth(req, app, sessionCookie) {
  const url = new URL(req.url);
  const [, , , p, step] = url.pathname.split('/'); // /api/oauth/<p>/<step>
  const err = (m, hashBase = '/login') => redirect(back(app, hashBase + '?err=' + encodeURIComponent(m)), [stateCookie(app, '')]);
  if (req.method !== 'GET' || !PROVIDERS[p] || !['start', 'callback'].includes(step)) return new Response('Not found', { status: 404 });
  const prov = PROVIDERS[p];
  try {
    if (!(await enabledProviders(app)).includes(p)) return err('Входът с ' + prov.label + ' е изключен.');

    if (step === 'start') {
      const st = { p, mode: 'login', nonce: randomToken() };
      if (url.searchParams.get('link') === '1') {
        // свързване: само за влязъл потребител (бисквитката на сесията не се праща от чужди сайтове – SameSite=Strict)
        const ctx = await authenticate(app, cookieToken(req), 'user');
        Object.assign(st, { mode: 'link', u: ctx.username });
      }
      const state = randomToken(), q = new URLSearchParams({
        client_id: prov.clientId(app.env), redirect_uri: redirectUri(app, p), response_type: 'code', scope: prov.scope, state, nonce: st.nonce
      });
      Object.entries(prov.extra || {}).forEach(([k, v]) => q.set(k, v));
      if (prov.pkce) {
        st.verifier = randomToken() + randomToken().slice(0, 32);
        q.set('code_challenge', b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(st.verifier))));
        q.set('code_challenge_method', 'S256');
      }
      await app.kv.put('o:' + (await sha256(state)), JSON.stringify(st), { expirationTtl: 600 });
      return redirect(prov.authUrl(app.env) + '?' + q, [stateCookie(app, state)]);
    }

    // callback
    const state = str(url.searchParams.get('state'), 64), code = str(url.searchParams.get('code'), 2000);
    const key = 'o:' + (await sha256(state || '-'));
    const raw = /^[0-9a-f]{64}$/.test(state) ? await app.kv.get(key) : null;
    if (raw) await app.kv.delete(key);
    const st = raw ? JSON.parse(raw) : null;
    const ret = st && st.mode === 'link' ? '/profile' : '/login';
    if (url.searchParams.get('error')) return err(url.searchParams.get('error') === 'access_denied' ? 'Входът е отказан.' : 'Грешка от ' + prov.label + ': ' + str(url.searchParams.get('error'), 80), ret);
    if (!st || st.p !== p || !sameText(fromCookie(req), state)) return err('Входът изтече или е започнат от друг браузър. Опитайте отново.', ret);
    if (!code) return err('Липсва код от ' + prov.label + '.', ret);

    const byIp = app.ip ? await throttle(app, 'ip|' + app.ip) : null;
    if (byIp && (await byIp.blocked())) return err('Твърде много неуспешни опити. Опитайте отново след 15 минути.');

    const tokenUrl = prov.tokenUrl(app.env);
    const body = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri(app, p) });
    if (p !== 'discord') body.set('client_id', prov.clientId(app.env));
    if (st.verifier) body.set('code_verifier', st.verifier);
    await prov.secret(app.env, body, tokenUrl);
    const tr = await fetch(tokenUrl, { method: 'POST', body, headers: { Accept: 'application/json' } });
    const tok = await tr.json().catch(() => ({}));
    if (!tr.ok || !tok.access_token) {
      console.error('oauth token ' + p + ': ' + tr.status + ' ' + String(tok.error || '') + ' ' + String(tok.error_description || '').slice(0, 200));
      return err(prov.label + ' не потвърди входа (' + (tok.error || tr.status) + ').', ret);
    }
    const who = await prov.identity(app.env, tok, st);
    who.email = String(who.email || '').trim().toLowerCase();
    const users = await app.store.list('users');

    if (st.mode === 'link') {
      const u = users.find(x => x.username === st.u);
      if (!u || u.active !== 'Да') return err('Потребителят не е активен.', ret);
      const other = users.find(x => x.username !== u.username && oauthOf(x)[p] && oauthOf(x)[p].id === who.id);
      if (other) return err('Този профил в ' + prov.label + ' вече е свързан с друг потребител.', ret);
      await link(app, u, p, who);
      await audit(app, u.username, 'Свързан вход с ' + prov.label, '', who.email);
      return redirect(back(app, '/profile?ok=' + encodeURIComponent('Входът с ' + prov.label + ' е свързан.')), [stateCookie(app, '')]);
    }

    let u = users.find(x => oauthOf(x)[p] && oauthOf(x)[p].id === who.id);
    if (!u && who.verified && who.email && (await oauthSettings(app)).autoLink) {
      const same = users.filter(x => String(x.email || '').trim().toLowerCase() === who.email);
      // нов профил се свързва автоматично само при еднозначно съвпадение и ако потребителят няма друг профил от същия доставчик
      if (same.length === 1 && !oauthOf(same[0])[p]) {
        u = same[0];
        await link(app, u, p, who);
        await audit(app, u.username, 'Свързан вход с ' + prov.label + ' (по имейл)', '', who.email);
      }
    }
    if (!u || u.active !== 'Да') {
      if (byIp) await byIp.hit();
      await recordLogin(app, u ? u.username : '(непознат)', 'Отказан вход с ' + prov.label + (who.email ? ': ' + who.email : '') + (u ? ' (спрян потребител)' : ''));
      return err(u ? 'Достъпът ви е спрян.' : 'Няма потребител в системата с ' + (who.email ? 'имейл ' + who.email : 'този профил') +
        '. Входът с ' + prov.label + ' работи само за служители, добавени от администратор. Влезте с паролата си и свържете профила от „Моят профил“.');
    }
    if (u.twofa === 'Да') {
      const r = await startCode(app, u);
      return redirect(back(app, '/code/' + r.ticket), [stateCookie(app, '')]);
    }
    const r = await openSession(app, u, prov.label);
    return redirect(back(app, '/dashboard'), [stateCookie(app, ''), sessionCookie(app, r.__cookie)]);
  } catch (e) {
    console.error('oauth ' + p + ': ' + (e && e.stack || e));
    return err(e && e.code ? e.message : 'Грешка при входа с ' + prov.label + '. Опитайте отново.');
  }
}

async function link(app, u, p, who) {
  const o = oauthOf(u);
  o[p] = { id: who.id, email: who.email, name: line(who.name, 120), at: stamp() };
  await app.store.patch('users', u._id, { oauth: JSON.stringify(o) });
  u.oauth = JSON.stringify(o);
  await dropUser(app, u.username);
}
