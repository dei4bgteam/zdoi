/*
 * КЕП: сървърната част на подписването на документите (вж. site/js/kep.js).
 *   kep.authorize – подписва заявката към B-Trust BISS със сертификата на системата (acme.js);
 *   kep.complete  – проверява подписания PDF (хеш, подпис, сертификат) и го пази вместо неподписания.
 * Пази се само име, издател и маскиран идентификатор от сертификата, не ЕГН.
 */

import { fail, line, stamp } from './util.js';
import { audit } from './core.js';
import { sha256 } from './crypto.js';
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
  return { cert, attrsDer: sd.attrsDer };
}

/* идентификаторът (напр. PNOBG-8001010000) се пази маскиран */
const maskId = id => (id ? String(id).replace(/(\d{2})\d+(\d{2})$/, (m, a, b) => a + '******' + b) : '');

export async function kepComplete(d, ctx, app) {
  const { doc, req } = await findDoc(app, d.outNo, ctx);
  const p = payloadOf(doc);
  if (p._sig) fail('value', 'Документът вече е подписан.');
  const pdf = fromB64(String(d.pdf || ''));
  if (pdf.length < 200 || pdf.length > MAX_PDF || String.fromCharCode(...pdf.slice(0, 4)) !== '%PDF') fail('value', 'Невалиден PDF файл.');
  const { cert, attrsDer } = await verifyPdf(pdf);
  // подписът трябва да е направен през тази система, за този документ и от същия потребител
  const key = 'kep:p:' + (await sha256(D.b64(attrsDer)));
  const pend = JSON.parse((await app.kv.get(key)) || 'null');
  if (!pend || pend.outNo !== doc.outNo || pend.u !== ctx.username) fail('value', 'Подписът не е започнат за този документ в системата. Подпишете отново.');
  await app.kv.delete(key);
  const f = await app.store.uploadFile(doc.regNo + '/' + doc.outNo + ' ' + doc.kind + ' (подписан).pdf', pdf, 'application/pdf');
  const sig = {
    name: cert.name, org: cert.org, id: maskId(cert.id), issuer: cert.issuerName, qualified: cert.qualified, sscd: cert.sscd,
    notAfter: cert.notAfter ? cert.notAfter.toISOString().slice(0, 10) : '', at: stamp(), by: ctx.username, unsignedFileId: doc.fileId || ''
  };
  p._sig = sig;
  await app.store.patch('docs', doc._id, { fileId: f.id, fileUrl: f.webUrl, payload: JSON.stringify(p) });
  await app.store.insert('events', { regNo: doc.regNo, at: stamp(), user: ctx.username, kind: 'Подпис с КЕП',
    text: doc.kind + ' изх. № ' + doc.outNo + ' е подписано от ' + sig.name + (sig.org ? ' (' + sig.org + ')' : '') + ', издател: ' + sig.issuer + (sig.qualified ? ', квалифициран' : '') });
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
