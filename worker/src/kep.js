/*
 * КЕП: сървърната част на подписването на документите (вж. site/js/kep.js).
 *   kep.authorize – подписва заявката към B-Trust BISS със сертификата на системата (acme.js);
 *   kep.complete  – проверява подписания PDF (хеш, подпис, сертификат) и го пази вместо неподписания.
 * Пази се само име, издател и маскиран идентификатор от сертификата, не ЕГН.
 */

import { fail, line, str, stamp } from './util.js';
import { audit, throttle } from './core.js';
import { sha256, hmac, randomToken } from './crypto.js';
import { checkRevocation, verifySig } from './revocation.js';
import { openSession, recordLogin, oauthOf, dropUser } from './auth.js';
import { enabledProviders } from './oauth.js';
import { signingCert, certStatus, ensureCert } from './acme.js';
import { fromB64 } from './mailbox.js';
import * as D from './der.js';

const MAX_PDF = 8 * 1048576;

async function findDoc(app, outNo, ctx) {
  const doc = (await app.store.list('docs', { outNo: line(outNo, 30) }))[0];
  if (!doc) fail('notfound', 'Документът не е намерен.');
  const r = (await app.store.list('requests', { regNo: doc.regNo }))[0];
  if (!r || !(ctx.perms.casesAll || r.owner === ctx.username || r.createdBy === ctx.username)) fail('notfound', 'Документът не е намерен.');
  if (r.locked === 'Да') fail('caselocked', 'Преписката е заключена.');
  return { doc, req: r };
}
const payloadOf = doc => { try { return JSON.parse(doc.payload || '{}'); } catch (_) { return {}; } };

export async function kepAuthorize(d, ctx, app) {
  const { doc } = await findDoc(app, d.outNo, ctx);
  if (payloadOf(doc)._sig) fail('value', 'Документът вече е подписан.');
  if (doc.sentAt) fail('value', 'Документът вече е изпратен. Създайте нов документ, ако трябва подписан вариант.');
  const content = D.unb64(String(d.content || ''));
  if (content.length < 50 || content.length > 4096 || content[0] !== 0x31) fail('value', 'Невалидни данни за подпис.');
  const c = await signingCert(app);
  if (!c) fail('setup', 'Сертификатът на системата за КЕП още не е издаден. Опитайте след няколко минути или от „Система“.');
  // BISS проверява SHA256withRSA върху SHA-256 на данните
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', content));
  const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', c.key, digest));
  await app.kv.put('kep:p:' + (await sha256(D.b64(content))), JSON.stringify({ outNo: doc.outNo, u: ctx.username }), { expirationTtl: 1800 });
  return { signedContents: D.b64(sig), signedContentsCert: c.chain[0] };
}

/* последният подпис в PDF: ByteRange и CMS */
function lastSignature(pdf) {
  const latin = new TextDecoder('latin1').decode(pdf);
  const re = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g;
  let m, last = null;
  while ((m = re.exec(latin))) last = m.slice(1).map(Number);
  if (!last) fail('value', 'PDF файлът не съдържа електронен подпис.');
  const [a, b, c, len] = last;
  if (a !== 0 || c + len !== pdf.length || b >= c) fail('value', 'Подписът не обхваща целия файл.');
  const hexStr = latin.slice(b + 1, c - 1).replace(/0+$/, '');
  const cms = new Uint8Array((hexStr.length + (hexStr.length % 2)) / 2);
  for (let i = 0; i < cms.length; i++) cms[i] = parseInt(hexStr.substr(i * 2, 2).padEnd(2, '0'), 16);
  return { range: last, cms: D.read(cms).raw, signedPart: D.concat([pdf.subarray(0, b), pdf.subarray(c)]) };
}

const eq = (x, y) => x.length === y.length && x.every((v, i) => v === y[i]);

export async function verifyPdf(pdf) {
  const s = lastSignature(pdf);
  let sd;
  try { sd = D.parseSignedData(s.cms); } catch (_) { fail('value', 'Подписът в PDF файла не може да бъде разчетен.'); }
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', s.signedPart));
  if (!sd.digest || !eq(sd.digest, digest)) fail('value', 'Съдържанието на документа не съвпада с подписа.');
  const certDer = sd.certs.find(c => { try { return eq(D.parseCert(c).serial, sd.sidSerial); } catch (_) { return false; } });
  if (!certDer) fail('value', 'Липсва сертификатът на подписващия.');
  const cert = D.parseCert(certDer);
  let ok = false;
  if (cert.keyAlg === D.OID.ec) {
    const curve = cert.curve === D.OID.p384 ? 'P-384' : 'P-256', size = curve === 'P-384' ? 48 : 32;
    const key = await crypto.subtle.importKey('spki', cert.spki, { name: 'ECDSA', namedCurve: curve }, false, ['verify']);
    ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, D.ecdsaRaw(sd.signature, size), sd.attrsDer);
  } else {
    const key = await crypto.subtle.importKey('spki', cert.spki, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sd.signature, sd.attrsDer);
  }
  if (!ok) fail('value', 'Електронният подпис е невалиден.');
  const now = new Date();
  if (cert.notAfter && cert.notAfter < now) fail('value', 'Удостоверението на подписващия е изтекло.');
  if (cert.notBefore && cert.notBefore > now) fail('value', 'Удостоверението на подписващия още не е влязло в сила.');
  return { cert, attrsDer: sd.attrsDer, chain: sd.certs };
}

/* идентификаторът (напр. PNOBG-8001010000) се пази маскиран */
const maskId = id => (id ? String(id).replace(/(\d{2})\d+(\d{2})$/, (m, a, b) => a + '******' + b) : '');

export async function kepComplete(d, ctx, app) {
  const { doc, req } = await findDoc(app, d.outNo, ctx);
  const p = payloadOf(doc);
  if (p._sig) fail('value', 'Документът вече е подписан.');
  const pdf = fromB64(String(d.pdf || ''));
  if (pdf.length < 200 || pdf.length > MAX_PDF || String.fromCharCode(...pdf.slice(0, 4)) !== '%PDF') fail('value', 'Невалиден PDF файл.');
  const { cert, attrsDer, chain } = await verifyPdf(pdf);
  // подписът трябва да е направен през тази система, за този документ и от същия потребител
  const key = 'kep:p:' + (await sha256(D.b64(attrsDer)));
  const pend = JSON.parse((await app.kv.get(key)) || 'null');
  if (!pend || pend.outNo !== doc.outNo || pend.u !== ctx.username) fail('value', 'Подписът не е започнат за този документ в системата. Подпишете отново.');
  // публичните регистри на доставчика: прекратено или спряно удостоверение не подписва
  const rev = await checkRevocation(cert, chain);
  if (rev.status === 'revoked') fail('value', 'Удостоверението на ' + cert.name + ' е прекратено или спряно' + (rev.reason ? ' (' + rev.reason + ')' : '') + ' според ' + rev.method + ' на доставчика.');
  await app.kv.delete(key);
  const f = await app.store.uploadFile(doc.regNo + '/' + doc.outNo + ' ' + doc.kind + ' (подписан).pdf', pdf, 'application/pdf');
  const sig = {
    name: cert.name, org: cert.org, id: maskId(cert.id), issuer: cert.issuerName, qualified: cert.qualified, sscd: cert.sscd,
    notAfter: cert.notAfter ? cert.notAfter.toISOString().slice(0, 10) : '', at: stamp(), by: ctx.username, unsignedFileId: doc.fileId || '',
    rev: { status: rev.status, method: rev.method || '', at: rev.at, note: rev.note || '' }
  };
  p._sig = sig;
  await app.store.patch('docs', doc._id, { fileId: f.id, fileUrl: f.webUrl, payload: JSON.stringify(p) });
  await app.store.insert('events', { regNo: doc.regNo, at: stamp(), user: ctx.username, kind: 'Подпис с КЕП',
    text: doc.kind + ' изх. № ' + doc.outNo + ' е подписано от ' + sig.name + (sig.org ? ' (' + sig.org + ')' : '') + ', издател: ' + sig.issuer + (sig.qualified ? ', квалифициран' : '') +
      (rev.status === 'good' ? '; проверено в ' + rev.method + ' на доставчика – валидно' : '; статусът в регистъра на доставчика не е проверен' + (rev.note ? ' (' + rev.note + ')' : '')) });
  await audit(app, ctx.username, 'Подпис с КЕП', doc.outNo, sig.name + ' · ' + sig.issuer);
  return { signature: sig, fileUrl: f.webUrl, regNo: req.regNo };
}

/* за „Система“ */
export async function kepStatus(d, ctx, app) { return certStatus(app); }
export async function kepRenew(d, ctx, app) {
  const r = await ensureCert(app, true);
  await audit(app, ctx.username, 'Подновен сертификат за КЕП', '', r.error || r.notAfter || '');
  return Object.assign(r, await certStatus(app));
}

/* ---------- вход с КЕП ----------
 * Сървърът дава еднократен текст, картата го подписва през BISS (със същото разрешение като при документите),
 * сървърът проверява подписа, срока, регистъра на доставчика и намира потребителя по свързания КЕП.
 * Връзката е по идентификатора на лицето в сертификата (напр. PNOBG-…), затова важи и след подновяване на КЕП
 * или смяна на доставчика; пази се само HMAC от него.
 */

async function challengeFor(app, extra) {
  const c = await signingCert(app);
  if (!c) fail('setup', 'Входът с КЕП още не е готов (липсва сертификат на системата).');
  const content = new TextEncoder().encode('ADM ZDOI4You – вход с КЕП · ' + new Date().toISOString() + ' · ' + randomToken().slice(0, 32));
  const id = randomToken();
  await app.kv.put('kc:' + (await sha256(id)), JSON.stringify(Object.assign({ c: D.b64(content) }, extra)), { expirationTtl: 300 });
  const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', c.key, new Uint8Array(await crypto.subtle.digest('SHA-256', content))));
  return { id, content: D.b64(content), signedContents: D.b64(sig), signedContentsCert: c.chain[0] };
}

export async function kepChallenge(d, ctx, app) {
  if (!(await enabledProviders(app)).includes('kep')) fail('value', 'Входът с КЕП е изключен.');
  const t = app.ip ? await throttle(app, 'kepch|' + app.ip, 30) : null;
  if (t && (await t.blocked())) fail('locked', 'Твърде много опити. Опитайте отново след 15 минути.');
  if (t) await t.hit();
  return challengeFor(app, { mode: 'login' });
}
export const kepLinkChallenge = (d, ctx, app) => challengeFor(app, { mode: 'link', u: ctx.username });

/* проверка на подписания текст: { cert, key (идентификатор за връзка), rev, st } */
async function proveKep(app, d, mode) {
  const id = str(d.id, 64);
  if (!/^[0-9a-f]{64}$/.test(id)) fail('kep', 'Невалидна заявка.');
  const k = 'kc:' + (await sha256(id)), raw = await app.kv.get(k);
  if (!raw) fail('kep', 'Времето за вход изтече. Опитайте отново.');
  await app.kv.delete(k);
  const st = JSON.parse(raw);
  if (st.mode !== mode) fail('kep', 'Невалидна заявка.');
  const chain = (Array.isArray(d.chain) ? d.chain : []).slice(0, 6).map(x => D.unb64(String(x)));
  if (!chain.length) fail('kep', 'Липсва удостоверението.');
  let cert;
  try { cert = D.parseCert(chain[0]); } catch (_) { fail('kep', 'Удостоверението не може да бъде разчетено.'); }
  let sig = D.unb64(String(d.signature || ''));
  const ec = cert.keyAlg === D.OID.ec;
  if (ec && sig[0] !== 0x30) sig = D.ecdsaDer(sig);
  if (!(await verifySig(cert.spki, ec ? D.OID.ecdsaSha256 : D.OID.sha256Rsa, sig, D.unb64(st.c)))) fail('kep', 'Подписът с КЕП е невалиден.');
  const now = new Date();
  if ((cert.notAfter && cert.notAfter < now) || (cert.notBefore && cert.notBefore > now)) fail('kep', 'Удостоверението не е валидно към днешна дата.');
  if (!cert.qualified) fail('kep', 'За вход е нужен квалифициран електронен подпис (КЕП).');
  const rev = await checkRevocation(cert, chain.slice(1));
  if (rev.status === 'revoked') fail('kep', 'Удостоверението е прекратено или спряно според ' + rev.method + ' на доставчика.');
  // идентификаторът на лицето (PNOBG-… и др.), а ако липсва – отпечатъкът на сертификата
  const who = cert.id ? 'id|' + cert.id : 'cert|' + D.hex(new Uint8Array(await crypto.subtle.digest('SHA-256', cert.der)));
  return { cert, key: await hmac(app.env.PEPPER, 'kep|' + who), rev, st };
}

export async function kepLogin(d, ctx, app) {
  const byIp = app.ip ? await throttle(app, 'ip|' + app.ip) : null;
  if (byIp && (await byIp.blocked())) fail('locked', 'Твърде много неуспешни опити. Опитайте отново след 15 минути.');
  let p;
  try { p = await proveKep(app, d, 'login'); } catch (e) {
    if (byIp) await byIp.hit();
    await recordLogin(app, '(непознат)', 'Отказан вход с КЕП: ' + e.message);
    throw e;
  }
  const u = (await app.store.list('users')).find(x => oauthOf(x).kep && oauthOf(x).kep.id === p.key);
  if (!u || u.active !== 'Да') {
    if (byIp) await byIp.hit();
    await recordLogin(app, u ? u.username : '(непознат)', 'Отказан вход с КЕП: ' + p.cert.name + (u ? ' (спрян потребител)' : ' (не е свързан)'));
    fail('kep', u ? 'Достъпът ви е спрян.' : 'Този КЕП (' + p.cert.name + ') не е свързан с потребител. Влезте с паролата си и го свържете от „Моят профил“.');
  }
  return openSession(app, u, 'КЕП');
}

export async function kepLink(d, ctx, app) {
  const p = await proveKep(app, d, 'link');
  if (p.st.u !== ctx.username) fail('kep', 'Невалидна заявка.');
  const users = await app.store.list('users');
  if (users.some(x => x.username !== ctx.username && oauthOf(x).kep && oauthOf(x).kep.id === p.key)) fail('kep', 'Този КЕП вече е свързан с друг потребител.');
  const u = users.find(x => x.username === ctx.username);
  const o = oauthOf(u);
  o.kep = { id: p.key, name: p.cert.name, email: p.cert.issuerName, at: stamp() };
  await app.store.patch('users', u._id, { oauth: JSON.stringify(o) });
  await dropUser(app, ctx.username);
  await audit(app, ctx.username, 'Свързан вход с КЕП', '', p.cert.name + ' · ' + p.cert.issuerName);
  return { name: p.cert.name };
}

/* ---------- проверка на КЕП (страница „Проверка на КЕП“) ----------
 * Доклад, не отказ: всяка проверка поотделно (✔/✖), за произволен подписан PDF, за сертификат от картата и за тестов подпис.
 */

const SIGNING_TIME = '1.2.840.113549.1.9.5';
const sofia = d => (isNaN(d) ? '' : d.toLocaleString('sv-SE', { timeZone: 'Europe/Sofia' }).replace(' ', 'T'));

/* /M (D:YYYYMMDDHHmmSS+HH'mm'), вкл. с осмични escape-и (напр. „\072“ вместо „:“), както пишат някои програми */
function pdfDate(win) {
  const m = /\/M\s*\(((?:[^)\\]|\\.)*)\)/.exec(win);
  if (!m) return '';
  const s = m[1].replace(/\\([0-7]{1,3})/g, (x, o) => String.fromCharCode(parseInt(o, 8))).replace(/\\(.)/g, '$1');
  const d = /D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(Z|[+-]\d{2}'?\d{2})?/.exec(s);
  if (!d) return '';
  const tz = !d[7] || d[7] === 'Z' ? 'Z' : d[7].slice(0, 3) + ':' + d[7].replace("'", '').slice(3, 5);
  return sofia(new Date(`${d[1]}-${d[2]}-${d[3]}T${d[4]}:${d[5]}:${d[6]}${tz}`));
}

function asn1Time(n) {
  // UTCTime (0x17) – година с 2 цифри, GeneralizedTime (0x18) – с 4
  const s = new TextDecoder().decode(n.body), m = (n.tag === 0x18 ? /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/ : /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/).exec(s);
  if (!m) return '';
  const y = m[1].length === 2 ? (+m[1] < 50 ? 2000 : 1900) + +m[1] : +m[1];
  return sofia(new Date(Date.UTC(y, m[2] - 1, +m[3], +m[4], +m[5], +m[6])));
}

/* данните за сертификата + регистъра на доставчика */
async function certReport(cert, chain) {
  const now = new Date();
  const rev = await checkRevocation(cert, chain);
  return {
    name: cert.name, org: cert.org, id: maskId(cert.id), email: cert.email, issuer: cert.issuerName,
    notBefore: cert.notBefore ? cert.notBefore.toISOString() : '', notAfter: cert.notAfter ? cert.notAfter.toISOString() : '',
    inDate: !!(cert.notAfter && cert.notBefore && cert.notBefore <= now && cert.notAfter >= now),
    qualified: cert.qualified, sscd: cert.sscd, nonRepudiation: cert.nonRepudiation,
    keyAlg: cert.keyAlg === D.OID.ec ? 'EC ' + (cert.curve === D.OID.p384 ? 'P-384' : 'P-256') : 'RSA',
    rev: { status: rev.status, method: rev.method || '', url: rev.url || '', note: rev.note || '', reason: rev.reason || '', revokedAt: rev.revokedAt ? new Date(rev.revokedAt).toISOString() : '', issuerFound: !/издателят/.test(rev.note || '') }
  };
}

/* всички подписи в PDF: цялост, подпис, обхват, време, сертификат и регистър */
export async function analyzePdf(pdf) {
  const latin = new TextDecoder('latin1').decode(pdf);
  const re = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g;
  const out = [];
  let m;
  while ((m = re.exec(latin))) {
    const [a, b, c, len] = m.slice(1).map(Number);
    const s = { byteRange: [a, b, c, len], checks: {} };
    try {
      if (b >= c || c + len > pdf.length) throw new Error('невалиден ByteRange');
      s.checks.coversAll = a === 0 && c + len === pdf.length;
      const hexStr = latin.slice(b + 1, c - 1).replace(/(00)+$/, '');
      const cms = new Uint8Array(hexStr.length / 2 | 0);
      for (let i = 0; i < cms.length; i++) cms[i] = parseInt(hexStr.substr(i * 2, 2), 16);
      const sd = D.parseSignedData(D.read(cms).raw);
      const signed = D.concat([pdf.subarray(a, a + b), pdf.subarray(c, c + len)]);
      s.checks.integrity = !!sd.digest && eq(sd.digest, new Uint8Array(await crypto.subtle.digest('SHA-256', signed)));
      const certDer = sd.certs.find(x => { try { return eq(D.parseCert(x).serial, sd.sidSerial); } catch (_) { return false; } });
      if (!certDer) throw new Error('липсва сертификатът на подписващия');
      const cert = D.parseCert(certDer);
      const ec = cert.keyAlg === D.OID.ec;
      s.checks.signature = await verifySig(cert.spki, ec ? (sd.sigAlg === D.OID.ecdsaSha384 ? D.OID.ecdsaSha384 : D.OID.ecdsaSha256) : D.OID.sha256Rsa, sd.signature, sd.attrsDer);
      // време: атрибут signingTime или /M на подписа (за PAdES – /M)
      const attrs = D.read(sd.attrsDer).children;
      const st = attrs.find(x => D.oidStr(x.children[0].body) === SIGNING_TIME);
      // речникът на подписа без самия /Contents (той е десетки KB)
      const win = latin.slice(Math.max(0, Math.min(m.index, b) - 3000), b) + latin.slice(c, c + 3000);
      const mm = pdfDate(win);
      s.time = st ? asn1Time(st.children[1].children[0]) : mm;
      s.timeSource = st ? 'signingTime' : mm ? '/M (часовник на подписващия)' : '';
      s.subFilter = (/\/SubFilter\s*\/([A-Za-z0-9.]+)/.exec(win) || [])[1] || '';
      s.cert = await certReport(cert, sd.certs);
      s.ok = s.checks.integrity && s.checks.signature && s.cert.inDate && s.cert.rev.status !== 'revoked';
    } catch (e) { s.error = String(e.message || e).slice(0, 200); s.ok = false; }
    out.push(s);
  }
  return out;
}

export async function kepVerify(d, ctx, app) {
  const pdf = fromB64(String(d.pdf || ''));
  if (pdf.length < 100 || pdf.length > MAX_PDF || String.fromCharCode(...pdf.slice(0, 4)) !== '%PDF') fail('value', 'Изберете PDF файл до 8 MB.');
  const t = await throttle(app, 'kepverify|' + ctx.username, 60);
  if (await t.blocked()) fail('locked', 'Твърде много проверки. Опитайте след 15 минути.');
  await t.hit();
  const sigs = await analyzePdf(pdf);
  await audit(app, ctx.username, 'Проверка на подписан PDF', '', sigs.length + ' подписа');
  return { signatures: sigs, size: pdf.length };
}

/* сертификатът от картата (без ПИН) */
export async function kepCheckCert(d, ctx, app) {
  const chain = (Array.isArray(d.chain) ? d.chain : []).slice(0, 6).map(x => D.unb64(String(x)));
  if (!chain.length) fail('value', 'Липсва сертификат.');
  let cert;
  try { cert = D.parseCert(chain[0]); } catch (_) { fail('value', 'Сертификатът не може да бъде разчетен.'); }
  return { cert: await certReport(cert, chain.slice(1)) };
}

/* тестов подпис: разрешение за BISS без документ в преписка */
export async function kepTestAuthorize(d, ctx, app) {
  const content = D.unb64(String(d.content || ''));
  if (content.length < 50 || content.length > 4096 || content[0] !== 0x31) fail('value', 'Невалидни данни за подпис.');
  const t = await throttle(app, 'keptest|' + ctx.username, 20);
  if (await t.blocked()) fail('locked', 'Твърде много тестови подписи. Опитайте след 15 минути.');
  await t.hit();
  const c = await signingCert(app);
  if (!c) fail('setup', 'Сертификатът на системата за КЕП още не е издаден.');
  const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', c.key, new Uint8Array(await crypto.subtle.digest('SHA-256', content))));
  await audit(app, ctx.username, 'Тестов подпис с КЕП', '', '');
  return { signedContents: D.b64(sig), signedContentsCert: c.chain[0] };
}
