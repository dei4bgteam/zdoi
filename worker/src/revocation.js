/*
 * Проверка дали удостоверението за КЕП е прекратено или спряно – в публичните регистри на доставчика:
 *   1. OCSP (адресът е в сертификата, AIA) – отговорът се проверява с ключа на издателя или на делегиран отговарящ сървър;
 *   2. ако няма OCSP или не отговаря – CRL (списък на прекратените удостоверения, CRL Distribution Points).
 * Издателят се взима от веригата (BISS/подписа) или от адреса в сертификата (AIA caIssuers) и се проверява, че е подписал удостоверението.
 *
 * Резултат: { status: 'good' | 'revoked' | 'unknown', method, url, at, reason?, revokedAt? }
 */

import * as D from './der.js';

const TIMEOUT = 8000;
const eq = (x, y) => x.length === y.length && x.every((v, i) => v === y[i]);

async function get(url, opts = {}) {
  const ac = new AbortController(), t = setTimeout(() => ac.abort(), TIMEOUT);
  try {
    const r = await fetch(url, Object.assign({ signal: ac.signal }, opts));
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return new Uint8Array(await r.arrayBuffer());
  } finally { clearTimeout(t); }
}

/* PEM или DER; PKCS#7 (.p7c) – първият сертификат */
function certFromBytes(b) {
  const s = new TextDecoder('latin1').decode(b.subarray(0, 30));
  if (/-----BEGIN/.test(s)) b = D.unb64(new TextDecoder().decode(b).replace(/-----[A-Z0-9 ]+-----/g, '').replace(/\s+/g, ''));
  const n = D.read(b);
  if (n.children && n.children[0] && n.children[0].tag === 0x06) { // ContentInfo
    const sd = n.children[1].children[0];
    const certs = sd.children.find(x => x.tag === 0xa0);
    return certs ? certs.children.map(x => x.raw) : [];
  }
  return [b];
}

/* подпис върху data с публичния ключ (SPKI DER) според алгоритъма */
export async function verifySig(spki, sigAlg, sig, data) {
  const hash = { [D.OID.sha256Rsa]: 'SHA-256', [D.OID.sha1Rsa]: 'SHA-1', [D.OID.sha384Rsa]: 'SHA-384', [D.OID.sha512Rsa]: 'SHA-512',
    [D.OID.ecdsaSha256]: 'SHA-256', [D.OID.ecdsaSha384]: 'SHA-384' }[sigAlg];
  if (!hash) return false;
  const pk = D.read(spki), keyAlg = D.oidStr(pk.children[0].children[0].body);
  try {
    if (keyAlg === D.OID.ec) {
      const curveOid = D.oidStr(pk.children[0].children[1].body), curve = curveOid === D.OID.p384 ? 'P-384' : 'P-256';
      const key = await crypto.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: curve }, false, ['verify']);
      return crypto.subtle.verify({ name: 'ECDSA', hash }, key, D.ecdsaRaw(sig, curve === 'P-384' ? 48 : 32), data);
    }
    let key;
    try { key = await crypto.subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify']); } catch (_) {
      // WebCrypto в Cloudflare приема само експонент 3 или 65537; някои български CA (напр. B-Trust) ползват други
      return rsaVerify(spki, hash, sig, data);
    }
    return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, data);
  } catch (_) { return false; }
}

/* RSASSA-PKCS1-v1_5 (RFC 8017, 8.2.2) без WebCrypto: s^e mod n и сравнение с EMSA-PKCS1-v1_5 */
const DIGEST_INFO = {
  'SHA-1': '3021300906052b0e03021a05000414', 'SHA-256': '3031300d060960864801650304020105000420',
  'SHA-384': '3041300d060960864801650304020205000430', 'SHA-512': '3051300d060960864801650304020305000440'
};
const big = u8 => (u8.length ? BigInt('0x' + D.hex(u8)) : 0n);
function modPow(b, e, m) {
  let r = 1n;
  b %= m;
  while (e > 0n) { if (e & 1n) r = r * b % m; e >>= 1n; b = b * b % m; }
  return r;
}
export async function rsaVerify(spki, hash, sig, data) {
  const key = D.read(D.read(spki).children[1].body.subarray(1));
  const n = big(key.children[0].body), e = big(key.children[1].body);
  let nBytes = key.children[0].body;
  while (nBytes.length && nBytes[0] === 0) nBytes = nBytes.subarray(1);
  const k = nBytes.length;
  if (sig.length !== k || !DIGEST_INFO[hash]) return false;
  const s = big(sig);
  if (s >= n) return false;
  const em = modPow(s, e, n).toString(16).padStart(k * 2, '0');
  const t = DIGEST_INFO[hash] + D.hex(new Uint8Array(await crypto.subtle.digest(hash, data)));
  const expected = '0001' + 'ff'.repeat(k - 3 - t.length / 2) + '00' + t;
  return k - 3 - t.length / 2 >= 8 && em === expected;
}
const signedBy = (cert, issuer) => verifySig(issuer.spki, cert.sigAlg, cert.signature, cert.tbs);

export async function findIssuer(cert, chain) {
  for (const der of chain || []) {
    try { const c = D.parseCert(der); if (eq(c.subjectRaw, cert.issuerRaw) && (await signedBy(cert, c))) return c; } catch (_) { /* следващият */ }
  }
  for (const url of cert.caIssuers || []) {
    try {
      for (const der of certFromBytes(await get(url))) { const c = D.parseCert(der); if (eq(c.subjectRaw, cert.issuerRaw) && (await signedBy(cert, c))) return c; }
    } catch (_) { /* следващият адрес */ }
  }
  return null;
}

const keyBits = spki => D.read(spki).children[1].body.subarray(1);
const sha1 = async b => new Uint8Array(await crypto.subtle.digest('SHA-1', b));
function genTime(n) {
  const s = new TextDecoder().decode(n.body), m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/.exec(s);
  return m ? new Date(Date.UTC(+m[1], m[2] - 1, +m[3], +m[4], +m[5], +m[6])) : null;
}
function anyTime(n) {
  if (n.tag === 0x18) return genTime(n);
  const s = new TextDecoder().decode(n.body), m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z/.exec(s);
  return m ? new Date(Date.UTC((+m[1] < 50 ? 2000 : 1900) + +m[1], m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0))) : null;
}
const REASONS = ['неуточнена', 'компрометиран ключ', 'компрометиран издател', 'промяна на данните', 'заменено', 'прекратена дейност', 'спряно', '', 'премахнато от CRL', 'оттеглени права', 'компрометиран орган'];

/* ---------- OCSP ---------- */

export async function ocspRequest(cert, issuer) {
  const certId = D.seq(D.algo(D.OID.sha1), D.octets(await sha1(cert.issuerRaw)), D.octets(await sha1(keyBits(issuer.spki))), cert.serialRaw);
  return D.seq(D.seq(D.seq(D.seq(certId))));
}

export async function parseOcsp(bytes, cert, issuer) {
  const resp = D.read(bytes);
  const status = resp.children[0].body[0];
  if (status !== 0) throw new Error('OCSP: отговор със статус ' + status);
  const rb = resp.children[1].children[0];
  if (D.oidStr(rb.children[0].body) !== D.OID.ocspBasic) throw new Error('OCSP: непознат вид отговор');
  const basic = D.read(rb.children[1].body);
  const [tbs, alg, sigBits] = basic.children;
  const sigAlg = D.oidStr(alg.children[0].body), sig = sigBits.body.subarray(1);
  const certsNode = basic.children.find(x => x.tag === 0xa0);
  const parts = tbs.children.filter(x => x.tag !== 0xa0); // без version
  const responder = parts[0], responses = parts[2];
  // кой е подписал: издателят или делегиран сървър, чийто сертификат е издаден от издателя
  let signer = null;
  const issuerKeyHash = await sha1(keyBits(issuer.spki));
  const isIssuer = responder.tag === 0xa2 ? eq(D.read(responder.body).body, issuerKeyHash) : eq(responder.children[0].raw, issuer.subjectRaw);
  if (isIssuer) signer = issuer;
  else if (certsNode) {
    for (const c of certsNode.children[0].children) {
      try {
        const rc = D.parseCert(c.raw);
        const match = responder.tag === 0xa2 ? eq(D.read(responder.body).body, await sha1(keyBits(rc.spki))) : eq(responder.children[0].raw, rc.subjectRaw);
        if (match && eq(rc.issuerRaw, issuer.subjectRaw) && (await signedBy(rc, issuer))) { signer = rc; break; }
      } catch (_) { /* следващият */ }
    }
  }
  if (!signer) throw new Error('OCSP: отговорът не е подписан от издателя');
  if (!(await verifySig(signer.spki, sigAlg, sig, tbs.raw))) throw new Error('OCSP: невалиден подпис на отговора');
  for (const sr of responses.children) {
    const id = sr.children[0];
    if (!eq(id.children[3].body, cert.serial)) continue;
    const st = sr.children[1];
    const thisUpdate = genTime(sr.children[2]);
    const nextNode = sr.children.find(x => x.tag === 0xa0);
    const nextUpdate = nextNode ? genTime(nextNode.children[0]) : null;
    if (thisUpdate && thisUpdate.getTime() > Date.now() + 10 * 60000) throw new Error('OCSP: отговорът е от бъдещето');
    if (nextUpdate && nextUpdate.getTime() < Date.now() - 10 * 60000) throw new Error('OCSP: отговорът е остарял');
    if (st.tag === 0x80) return { status: 'good' };
    if (st.tag === 0xa1) {
      const reasonNode = st.children.find(x => x.tag === 0xa0);
      return { status: 'revoked', revokedAt: genTime(st.children[0]), reason: reasonNode ? REASONS[reasonNode.children[0].body[0]] || '' : '' };
    }
    return { status: 'unknown' };
  }
  throw new Error('OCSP: няма отговор за това удостоверение');
}

/* ---------- CRL ---------- */

export async function checkCrl(bytes, cert, issuer) {
  const crl = D.read(bytes, 0, 2); // плитко: големите списъци не се разчитат изцяло
  const [tbs, alg, sigBits] = crl.children;
  if (!(await verifySig(issuer.spki, D.oidStr(D.read(alg.raw).children[0].body), sigBits.body.subarray(1), tbs.raw))) throw new Error('CRL: невалиден подпис');
  const f = tbs.children;
  let i = f[0].tag === 0x02 ? 1 : 0;
  const issuerName = f[i + 1];
  if (!eq(issuerName.raw, issuer.subjectRaw)) throw new Error('CRL: друг издател');
  const nextNode = f[i + 3] && (f[i + 3].tag === 0x17 || f[i + 3].tag === 0x18) ? f[i + 3] : null;
  const nextUpdate = nextNode ? anyTime(nextNode) : null;
  if (nextUpdate && nextUpdate.getTime() < Date.now() - 3600000) throw new Error('CRL: списъкът е остарял');
  const list = f.find((x, k) => k > i + 2 && x.tag === 0x30);
  if (list) {
    for (let q = list.start; q < list.end;) {
      const entry = D.read(bytes, q, 1);
      q = entry.end;
      const serial = D.read(bytes, entry.start, 0);
      if (eq(serial.body, cert.serial)) {
        let reason = '';
        const e = D.read(entry.raw);
        const exts = e.children[2];
        if (exts) for (const x of exts.children) if (D.oidStr(x.children[0].body) === '2.5.29.21') reason = REASONS[D.read(x.children[x.children.length - 1].body).body[0]] || '';
        return { status: 'revoked', revokedAt: anyTime(e.children[1]), reason };
      }
    }
  }
  return { status: 'good' };
}

/* ---------- обща проверка ---------- */

export async function checkRevocation(cert, chain = []) {
  const at = new Date().toISOString(), notes = [];
  const issuer = await findIssuer(cert, chain);
  if (!issuer) return { status: 'unknown', method: '', at, note: 'не е намерен издателят на удостоверението' };
  for (const url of cert.ocsp || []) {
    try {
      const body = await ocspRequest(cert, issuer);
      const r = await parseOcsp(await get(url, { method: 'POST', headers: { 'Content-Type': 'application/ocsp-request', Accept: 'application/ocsp-response' }, body }), cert, issuer);
      if (r.status !== 'unknown') return Object.assign(r, { method: 'OCSP', url, at, issuer: issuer.name });
      notes.push('OCSP: неизвестно удостоверение');
    } catch (e) { notes.push(String(e.message || e)); }
  }
  for (const url of cert.crl || []) {
    try { return Object.assign(await checkCrl(await get(url), cert, issuer), { method: 'CRL', url, at, issuer: issuer.name }); } catch (e) { notes.push(String(e.message || e)); }
  }
  return { status: 'unknown', method: '', at, note: notes.join('; ').slice(0, 300) || 'няма адреси за проверка в удостоверението' };
}

export const revocationText = r => r.status === 'good' ? 'валидно (' + r.method + ')' : r.status === 'revoked' ? 'прекратено/спряно' : 'не е проверено' + (r.note ? ': ' + r.note : '');
