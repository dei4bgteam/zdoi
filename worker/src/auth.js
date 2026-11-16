/*
 * Локален вход: потребител + парола, с потребителите в SharePoint (списък „ADM Потребители“).
 *
 * Браузърът изчислява PBKDF2-SHA256 (600 000 итерации) от паролата и никога не я изпраща. Сървърът пази
 * HMAC-SHA256(резултат | сол) с тайния ключ PEPPER на Worker-а, затова хешовете в SharePoint не могат да се
 * проверяват офлайн без ключа. Сесията е в бисквитка HttpOnly; в KV се пази само хешът на ключа ѝ.
 */

import { CFG, ROLE_ADMIN, ROLE_PERMS, PERMS } from './config.js';
import { fail, str, stamp } from './util.js';
import { sha256, randomToken, randomCode, hmac, sameText } from './crypto.js';
import { audit, mail, throttle, cached, dropCache } from './core.js';

export const USER_RE = /^[a-z0-9._-]{3,40}$/;
export const PREHASH_RE = /^[A-Za-z0-9+/=]{40,64}$/;

export async function serverHash(app, preHash, salt) {
  if (!app.env.PEPPER) fail('setup', 'Системата още не е настроена (липсва PEPPER).');
  return hmac(app.env.PEPPER, preHash + '|' + salt);
}

export async function setPassword(app, preHash) {
  const salt = randomToken().slice(0, 32);
  return { salt, hash: await serverHash(app, preHash, salt) };
}

export async function newInvite(hours) {
  const token = randomToken();
  return { token, hash: await sha256(token), exp: String(Date.now() + hours * 36e5) };
}

export const inviteLink = (app, username, token) => app.cfg.appUrl + '#/activate/' + encodeURIComponent(username) + '/' + token;

/* еднократна връзка за парола; самата парола не се изпраща */
export function accessMail(app, to, username, link, validFor) {
  return mail(app, to, app.cfg.appName + ' – достъп',
    'Потребител: ' + username + '\n\n' +
    'Задайте парола с тази еднократна връзка. Тя важи ' + validFor + ':\n' + link + '\n\n' +
    'Не препращайте това писмо. Ако не го очаквате, не отваряйте връзката и пишете на ' + app.cfg.support + '.');
}

export const findUser = async (app, username) => (await app.store.list('users', { username }))[0] || null;
export const dropUser = (app, username) => dropCache(app, 'usr:' + username);

export function permsOf(u) {
  let list = null;
  if (u.perms) { try { list = JSON.parse(u.perms); } catch (_) { list = null; } }
  if (!Array.isArray(list)) list = ROLE_PERMS[u.role] || [];
  const out = {};
  list.forEach(k => { if (PERMS.includes(k)) out[k] = true; });
  // наблюдателят само преглежда, каквито и права да са записани
  if (u.role !== ROLE_ADMIN && !(ROLE_PERMS[u.role] || []).includes('casesEdit')) ['casesEdit', 'courts', 'addressees', 'departments'].forEach(k => delete out[k]);
  return out;
}

export function notifyOf(u) {
  let n = {};
  try { n = JSON.parse(u.notify || '{}') || {}; } catch (_) { n = {}; }
  return { assign: n.assign !== false, deadline: n.deadline !== false, mail: n.mail !== false, status: !!n.status, comments: !!n.comments, all: !!n.all };
}

const meInfo = u => ({
  username: u.username, name: u.name, role: u.role, perms: permsOf(u), twofa: u.twofa === 'Да',
  email: u.email, position: u.position, phone: u.phone, department: u.department, notify: notifyOf(u)
});

/* ---------- вход ---------- */

const badLogin = left => fail('login', 'Грешен потребител или парола.' + (left ? ' Остават ' + left + (left === 1 ? ' опит.' : ' опита.') : ''));
const LOCKED = 'Твърде много неуспешни опити. Опитайте отново след 15 минути или поискайте нова парола по имейл.';

const recordLogin = (app, username, result) =>
  app.store.insert('logins', { at: stamp(), username, ip: app.ip, agent: app.agent, result });

export async function login(d, ctx, app) {
  const username = str(d.username, 40).toLowerCase(), preHash = str(d.hash, 64);
  if (!USER_RE.test(username) || !PREHASH_RE.test(preHash)) badLogin();
  const t = await throttle(app, 'login|' + username), byIp = app.ip ? await throttle(app, 'ip|' + app.ip, CFG.MAX_IP_FAILS) : null;
  if ((await t.blocked()) || (byIp && (await byIp.blocked()))) fail('locked', LOCKED);
  const u = await findUser(app, username);
  const ok = u && u.active === 'Да' && u.salt && sameText(await serverHash(app, preHash, u.salt), u.hash);
  if (!ok) {
    const count = await t.hit();
    if (byIp) await byIp.hit();
    // въведеното име може да е парола, написана погрешно, затова непознато име не се записва
    await recordLogin(app, u ? username : '(непознат)', !u ? 'Непознат потребител' : u.active === 'Да' ? 'Грешна парола' : 'Спрян потребител');
    if (u) await audit(app, username, 'Неуспешен вход', '', app.ip);
    if (count >= CFG.MAX_FAILS) {
      await recordLogin(app, u ? username : '(непознат)', 'Заключен за 15 минути');
      if (u && u.email) await mail(app, u.email, app.cfg.appName + ' – спрян вход', 'Входът за потребител ' + u.username + ' е спрян за 15 минути след ' + count + ' неуспешни опита' + (app.ip ? ' (последен IP адрес: ' + app.ip + ')' : '') + '.\n\nАко не сте опитвали вие, сменете паролата си и уведомете администратора.');
      fail('locked', LOCKED);
    }
    badLogin(CFG.MAX_FAILS - count);
  }
  // при двуфакторен вход неуспешните опити се нулират едва след верния код
  if (u.twofa === 'Да') return startCode(app, u);
  await t.clear();
  return openSession(app, u);
}

async function startCode(app, u) {
  const sent = await throttle(app, 'codesent|' + u.username, 5);
  if (await sent.blocked()) fail('locked', 'Изпратени са твърде много кодове. Опитайте отново след 15 минути.');
  await sent.hit();
  const code = randomCode(), ticket = randomToken();
  await app.store.patch('users', u._id, { codeHash: await hmac(app.env.PEPPER, code + '|' + ticket), codeExp: String(Date.now() + CFG.CODE_MIN * 6e4) });
  await app.kv.put('t:' + (await sha256(ticket)), u.username, { expirationTtl: 900 });
  const ok = await mail(app, u.email, app.cfg.appName + ' – код за вход', 'Код: ' + code + '\n\nКодът важи ' + CFG.CODE_MIN + ' минути и се използва веднъж. Ако не влизате вие, сменете паролата си.');
  if (!ok) fail('mail', 'Кодът не можа да бъде изпратен. Опитайте отново по-късно.');
  return { twofa: true, ticket };
}

async function codeOk(app, u, ticket, code) {
  return /^[0-9a-f]{64}$/.test(ticket) && /^\d{8}$/.test(code) && !!u && !!u.codeHash && Number(u.codeExp) >= Date.now() &&
    sameText(await hmac(app.env.PEPPER, code + '|' + ticket), u.codeHash);
}

export async function loginCode(d, ctx, app) {
  const ticket = str(d.ticket, 64), code = str(d.code, 8);
  if (!/^[0-9a-f]{64}$/.test(ticket)) fail('code', 'Невалиден код.');
  const key = 't:' + (await sha256(ticket)), username = await app.kv.get(key);
  if (!username) fail('code', 'Кодът е изтекъл. Влезте отново.');
  const t = await throttle(app, 'login|' + username);
  if (await t.blocked()) fail('locked', LOCKED);
  const u = await findUser(app, username);
  if (!u || u.active !== 'Да' || !(await codeOk(app, u, ticket, code))) {
    const n = await t.hit();
    if (n >= CFG.MAX_FAILS) fail('locked', LOCKED);
    fail('code', 'Грешен или изтекъл код. Остават ' + (CFG.MAX_FAILS - n) + ' опита.');
  }
  await t.clear();
  await app.kv.delete(key);
  await app.store.patch('users', u._id, { codeHash: '', codeExp: '' });
  return openSession(app, u);
}

async function openSession(app, u) {
  await app.store.patch('users', u._id, { lastLogin: stamp() });
  await recordLogin(app, u.username, 'Успешен');
  await audit(app, u.username, 'Вход', '', app.ip);
  const token = randomToken(), exp = Date.now() + CFG.SESSION_MIN * 6e4;
  await saveSession(app, token, { u: u.username, exp });
  return { __cookie: token, session: exp, me: meInfo(u) };
}

/* ---------- сесии ---------- */

async function saveSession(app, token, s) {
  await app.kv.put('s:' + (await sha256(token)), JSON.stringify(s), { expirationTtl: Math.max(60, Math.ceil((s.exp - Date.now()) / 1000) + 60) });
}

export function cookieToken(req) {
  const m = /(?:^|;\s*)adm_s=([0-9a-f]{64})(?:;|$)/.exec(req.headers.get('Cookie') || '');
  return m ? m[1] : '';
}

const expired = () => fail('session', 'Сесията е изтекла. Влезте отново.');

/* need: user | admin */
export async function authenticate(app, token, need) {
  if (!token) expired();
  const raw = await app.kv.get('s:' + (await sha256(token)));
  const s = raw ? JSON.parse(raw) : null;
  if (!s || s.exp < Date.now()) expired();
  const user = await cached(app, 'usr:' + s.u, 120, async () => {
    const u = await findUser(app, s.u);
    return u ? { _id: u._id, username: u.username, active: u.active, role: u.role, name: u.name, email: u.email, perms: u.perms, notify: u.notify, department: u.department } : null;
  });
  if (!user || user.active !== 'Да') fail('session', 'Достъпът е спрян.');
  if (need === 'admin' && user.role !== ROLE_ADMIN) fail('role', 'Това действие е само за администратор.');
  // плъзгащ се срок; записва се отново най-много веднъж на 5 минути, за да се пестят записите в KV
  const exp = Date.now() + CFG.SESSION_MIN * 6e4;
  if (exp - s.exp > 5 * 6e4) { s.exp = exp; await saveSession(app, token, s); }
  return {
    token, username: s.u, userId: user._id, name: user.name, email: user.email, role: user.role,
    admin: user.role === ROLE_ADMIN, perms: permsOf(user), notify: notifyOf(user), sessionExp: s.exp
  };
}

export async function me(d, ctx, app) {
  return { me: meInfo(await findUser(app, ctx.username)) };
}

export async function logout(d, ctx, app) {
  await app.kv.delete('s:' + (await sha256(ctx.token)));
  await audit(app, ctx.username, 'Изход', '', '');
  return { __cookie: '' };
}

/* ---------- пароли ---------- */

async function checkPassword(app, ctx, preHash) {
  const t = await throttle(app, 'pw|' + ctx.username);
  if (await t.blocked()) fail('locked', 'Твърде много грешни опити. Опитайте отново след 15 минути.');
  const u = await findUser(app, ctx.username);
  if (!PREHASH_RE.test(preHash) || !u.salt || !sameText(await serverHash(app, preHash, u.salt), u.hash)) {
    await t.hit();
    await audit(app, ctx.username, 'Грешна текуща парола', '', '');
    fail('password', 'Текущата парола е грешна.');
  }
  await t.clear();
  return u;
}

export async function changePassword(d, ctx, app) {
  const cur = str(d.current, 64), next = str(d.next, 64);
  if (!PREHASH_RE.test(next)) fail('value', 'Невалидни данни.');
  const u = await checkPassword(app, ctx, cur);
  if (next === cur) fail('password', 'Новата парола трябва да е различна от текущата.');
  await app.store.patch('users', u._id, await setPassword(app, next));
  await audit(app, ctx.username, 'Смяна на парола', '', '');
  return {};
}

const inviteValid = async (u, token) => !!u && u.active === 'Да' && !!u.inviteHash && Number(u.inviteExp) >= Date.now() && sameText(await sha256(token), u.inviteHash);

function linkArgs(d) {
  const username = str(d.username, 40).toLowerCase(), token = str(d.token, 64);
  return { username, token, ok: USER_RE.test(username) && /^[0-9a-f]{64}$/.test(token) };
}

/* при отваряне на връзката: само проверка, която не я изразходва, за да не я затварят скенерите на пощата */
export async function linkCheck(d, ctx, app) {
  const a = linkArgs(d);
  if (!a.ok) return { valid: false };
  const t = await throttle(app, 'linkcheck|' + a.username, 30);
  if (await t.blocked()) return { valid: false };
  await t.hit();
  return { valid: await inviteValid(await findUser(app, a.username), a.token) };
}

export async function activate(d, ctx, app) {
  const a = linkArgs(d), preHash = str(d.hash, 64);
  const invalid = () => fail('invite', 'Връзката е невалидна или изтекла. Поискайте нова от администратора.');
  if (!a.ok || !PREHASH_RE.test(preHash)) invalid();
  const t = await throttle(app, 'activate|' + a.username);
  if (await t.blocked()) fail('locked', 'Твърде много неуспешни опити. Опитайте отново след 15 минути.');
  const u = await findUser(app, a.username);
  if (!(await inviteValid(u, a.token))) { await t.hit(); invalid(); }
  await t.clear();
  await (await throttle(app, 'login|' + a.username)).clear(); // новата парола отменя ограничението за вход
  await app.store.patch('users', u._id, Object.assign(await setPassword(app, preHash), { inviteHash: '', inviteExp: '' }));
  await audit(app, a.username, 'Зададена парола чрез еднократна връзка', '', app.ip);
  return { username: a.username };
}

/* забравена парола: отговорът е еднакъв, за да не се разбира кои потребители съществуват */
export async function forgot(d, ctx, app) {
  const username = str(d.username, 40).toLowerCase();
  if (!USER_RE.test(username)) return {};
  const t = await throttle(app, 'forgot|' + username);
  if (await t.blocked()) return {};
  await t.hit();
  const u = await findUser(app, username);
  if (!u || u.active !== 'Да' || !u.email) return {};
  const inv = await newInvite(CFG.RESET_HOURS);
  await app.store.patch('users', u._id, { inviteHash: inv.hash, inviteExp: inv.exp });
  await audit(app, username, 'Поискана нова парола', '', app.ip);
  await accessMail(app, u.email, username, inviteLink(app, username, inv.token), CFG.RESET_HOURS + ' часа');
  return {};
}

/* ---------- двуфакторен вход с код по имейл ---------- */

export async function twofaStart(d, ctx, app) {
  const u = await checkPassword(app, ctx, str(d.hash, 64));
  if (d.enable === false) {
    await app.store.patch('users', u._id, { twofa: '', codeHash: '', codeExp: '' });
    await dropUser(app, ctx.username);
    await audit(app, ctx.username, 'Изключен двуфакторен вход', '', '');
    return { twofa: false };
  }
  if (!u.email) fail('email', 'Нямате имейл. Помолете администратора да го въведе.');
  return startCode(app, u);
}

export async function twofaConfirm(d, ctx, app) {
  const ticket = str(d.ticket, 64), code = str(d.code, 8);
  const t = await throttle(app, 'twofa|' + ctx.username);
  if (await t.blocked()) fail('locked', 'Твърде много грешни опити. Опитайте отново след 15 минути.');
  const u = await findUser(app, ctx.username);
  if (!(await codeOk(app, u, ticket, code))) { await t.hit(); fail('code', 'Грешен или изтекъл код.'); }
  await t.clear();
  await app.store.patch('users', u._id, { twofa: 'Да', codeHash: '', codeExp: '' });
  await dropUser(app, ctx.username);
  await audit(app, ctx.username, 'Включен двуфакторен вход', '', '');
  return { twofa: true };
}

export async function notifySave(d, ctx, app) {
  const u = await findUser(app, ctx.username);
  const n = { assign: d.assign !== false, deadline: d.deadline !== false, mail: d.mail !== false, status: !!d.status, comments: !!d.comments, all: !!d.all && !!ctx.perms.casesAll };
  await app.store.patch('users', u._id, { notify: JSON.stringify(n) });
  await dropUser(app, ctx.username);
  return { notify: n };
}
