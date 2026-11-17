/*
 * Сертификат от Let's Encrypt за adm.zdoi.eu – само за подписване на заявките към B-Trust BISS (полето signedContents).
 * BISS приема заявка, подписана със сертификат от доверен издател; самоподписан не се приема.
 *
 * ACME (RFC 8555) с проверка http-01: Worker-ът отговаря на /.well-known/acme-challenge/<token>.
 * Ключът на сертификата (RSA 2048) се пази в KV, шифриран с AES-GCM от PEPPER. Подновяване – 30 дни преди изтичане.
 */

import { seq, set, int, oid, octets, bits, utf8, ctx, algo, OID, read, unb64, b64 } from './der.js';
import { b64url } from './crypto.js';
import { stamp } from './util.js';

const DIRECTORY = 'https://acme-v02.api.letsencrypt.org/directory';
const enc = new TextEncoder();
const RSA = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
const ES = { name: 'ECDSA', namedCurve: 'P-256' };

/* ---------- съхранение ---------- */

async function aesKey(env) {
  const raw = await crypto.subtle.digest('SHA-256', enc.encode('kep-cert|' + env.PEPPER));
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function seal(env, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(env), bytes));
  return b64(iv) + '.' + b64(ct);
}
async function unseal(env, s) {
  const [iv, ct] = String(s).split('.');
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, await aesKey(env), unb64(ct)));
}

/* текущият сертификат за подписване на заявките: { key (CryptoKey), chain [b64 DER], notAfter } */
export async function signingCert(app) {
  const raw = await app.kv.get('kep:cert');
  if (!raw) return null;
  const c = JSON.parse(raw);
  const key = await crypto.subtle.importKey('pkcs8', await unseal(app.env, c.key), RSA, false, ['sign']);
  return { key, chain: c.chain, notAfter: c.notAfter, issuedAt: c.issuedAt };
}

/* записва ключа (PKCS#8) и веригата (base64 DER) – и за тестовете */
export async function storeCert(app, pkcs8, chain, notAfter) {
  await app.kv.put('kep:cert', JSON.stringify({ key: await seal(app.env, pkcs8), chain, notAfter, issuedAt: stamp() }));
}

export async function certStatus(app) {
  const raw = await app.kv.get('kep:cert'), last = await app.kv.get('kep:last');
  const c = raw ? JSON.parse(raw) : null;
  return { has: !!c, notAfter: c ? c.notAfter : '', issuedAt: c ? c.issuedAt : '', last: last ? JSON.parse(last) : null };
}

/* ---------- ACME ---------- */

const pem = s => String(s).split('-----END CERTIFICATE-----').map(p => p.replace(/-----BEGIN CERTIFICATE-----/, '').replace(/\s+/g, '')).filter(Boolean);

async function accountKey(app) {
  const raw = await app.kv.get('acme:account');
  if (raw) {
    const a = JSON.parse(raw);
    return { jwk: a.jwk, kid: a.kid, key: await crypto.subtle.importKey('jwk', a.priv, ES, false, ['sign']) };
  }
  const k = await crypto.subtle.generateKey(ES, true, ['sign', 'verify']);
  const priv = await crypto.subtle.exportKey('jwk', k.privateKey), pub = await crypto.subtle.exportKey('jwk', k.publicKey);
  return { jwk: { crv: pub.crv, kty: pub.kty, x: pub.x, y: pub.y }, kid: '', key: k.privateKey, priv, fresh: true };
}

class Acme {
  constructor(app, acc) { this.app = app; this.acc = acc; this.nonce = ''; }
  async init() { this.dir = await (await fetch(DIRECTORY)).json(); }
  async newNonce() { const r = await fetch(this.dir.newNonce, { method: 'HEAD' }); return r.headers.get('Replay-Nonce'); }
  async post(url, payload, accept) {
    for (let attempt = 0; attempt < 3; attempt++) {
      const nonce = this.nonce || await this.newNonce();
      const prot = { alg: 'ES256', nonce, url };
      if (this.acc.kid) prot.kid = this.acc.kid; else prot.jwk = this.acc.jwk;
      const p = b64url(enc.encode(JSON.stringify(prot))), body = payload === '' ? '' : b64url(enc.encode(JSON.stringify(payload)));
      const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.acc.key, enc.encode(p + '.' + body));
      const r = await fetch(url, { method: 'POST', headers: Object.assign({ 'Content-Type': 'application/jose+json' }, accept ? { Accept: accept } : {}), body: JSON.stringify({ protected: p, payload: body, signature: b64url(sig) }) });
      this.nonce = r.headers.get('Replay-Nonce') || '';
      if (r.status === 400) {
        const e = await r.clone().json().catch(() => ({}));
        if (e.type === 'urn:ietf:params:acme:error:badNonce') continue;
      }
      if (!r.ok) throw new Error('ACME ' + r.status + ' ' + (await r.text()).slice(0, 300));
      return r;
    }
    throw new Error('ACME: badNonce');
  }
  async poll(url, ok, tries = 20) {
    for (let i = 0; i < tries; i++) {
      const o = await (await this.post(url, '')).json();
      if (ok.includes(o.status)) return o;
      if (o.status === 'invalid') throw new Error('ACME invalid: ' + JSON.stringify(o.error || (o.challenges || []).map(c => c.error).filter(Boolean)).slice(0, 400));
      await new Promise(r => setTimeout(r, 2000));
    }
    throw new Error('ACME: изтече времето за чакане');
  }
}

async function thumbprint(jwk) {
  const canon = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return b64url(await crypto.subtle.digest('SHA-256', enc.encode(canon)));
}

/* CSR за домейна с RSA ключ */
async function csr(domain, keys) {
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', keys.publicKey));
  const name = seq(set(seq(oid(OID.cn), utf8(domain))));
  const sanExt = seq(oid(OID.san), octets(seq(new Uint8Array([0x82, domain.length, ...enc.encode(domain)]))));
  const info = seq(int(0), name, spki, ctx(0, seq(oid(OID.extensionRequest), set(seq(sanExt)))));
  const sig = new Uint8Array(await crypto.subtle.sign(RSA, keys.privateKey, info));
  return seq(info, algo(OID.sha256Rsa), bits(sig));
}

export async function issue(app, domain) {
  const acc = await accountKey(app);
  const a = new Acme(app, acc);
  await a.init();
  if (!acc.kid) {
    const r = await a.post(a.dir.newAccount, { termsOfServiceAgreed: true });
    acc.kid = r.headers.get('Location');
    await app.kv.put('acme:account', JSON.stringify({ jwk: acc.jwk, kid: acc.kid, priv: acc.priv }));
  }
  const or = await a.post(a.dir.newOrder, { identifiers: [{ type: 'dns', value: domain }] });
  const orderUrl = or.headers.get('Location');
  const order = await or.json();
  const tp = await thumbprint(acc.jwk);
  for (const az of order.authorizations) {
    const auth = await (await a.post(az, '')).json();
    if (auth.status === 'valid') continue;
    const ch = auth.challenges.find(c => c.type === 'http-01');
    if (!ch) throw new Error('ACME: няма http-01');
    await app.kv.put('acme:ch:' + ch.token, ch.token + '.' + tp, { expirationTtl: 3600 });
    await a.post(ch.url, {});
    await a.poll(az, ['valid']);
  }
  const keys = await crypto.subtle.generateKey(Object.assign({ modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) }, RSA), true, ['sign', 'verify']);
  await a.post(order.finalize, { csr: b64url(await csr(domain, keys)) });
  const done = await a.poll(orderUrl, ['valid']);
  const chain = pem(await (await a.post(done.certificate, '', 'application/pem-certificate-chain')).text());
  const leaf = read(unb64(chain[0]));
  const validity = leaf.children[0].children[(leaf.children[0].children[0].tag === 0xa0 ? 1 : 0) + 3];
  const na = new TextDecoder().decode(validity.children[1].body);
  const m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(na);
  const notAfter = m ? '20' + m[1] + '-' + m[2] + '-' + m[3] + 'T' + m[4] + ':' + m[5] + ':' + m[6] + 'Z' : '';
  await storeCert(app, new Uint8Array(await crypto.subtle.exportKey('pkcs8', keys.privateKey)), chain, notAfter);
  return { notAfter };
}

/* от cron: издава при липса и подновява 30 дни преди изтичане; след неуспех опитва отново след 6 часа */
export async function ensureCert(app, force = false) {
  const domain = new URL(app.cfg.appUrl).hostname;
  if (!/\./.test(domain) || /^(localhost|127\.)/.test(domain)) return { skipped: 'локален адрес' };
  const st = await certStatus(app);
  const due = !st.has || !st.notAfter || Date.parse(st.notAfter) - Date.now() < 30 * 864e5;
  if (!due && !force) return { ok: true, notAfter: st.notAfter };
  if (!force && st.last && st.last.error && Date.now() - Date.parse(st.last.at) < 6 * 36e5) return { skipped: 'изчакване след грешка' };
  try {
    const r = await issue(app, domain);
    await app.kv.put('kep:last', JSON.stringify({ at: new Date().toISOString(), ok: true, notAfter: r.notAfter }));
    return { ok: true, issued: true, notAfter: r.notAfter };
  } catch (e) {
    await app.kv.put('kep:last', JSON.stringify({ at: new Date().toISOString(), error: String(e.message || e).slice(0, 400) }));
    return { error: String(e.message || e).slice(0, 400) };
  }
}

/* GET /.well-known/acme-challenge/<token> */
export async function challenge(app, token) {
  if (!/^[A-Za-z0-9_-]{10,200}$/.test(token)) return new Response('Not found', { status: 404 });
  const v = await app.kv.get('acme:ch:' + token);
  return v ? new Response(v, { headers: { 'Content-Type': 'text/plain' } }) : new Response('Not found', { status: 404 });
}
