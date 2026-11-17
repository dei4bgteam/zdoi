/* Синтетичен доставчик на КЕП за тестовете: CA, удостоверения с OCSP/CRL адреси, OCSP отговори и CRL. Не са истински. */

import { generateKeyPairSync, sign as nodeSign, createHash } from 'node:crypto';
import * as D from '../site/js/der.js';

const te = s => new TextEncoder().encode(s);
export const utc = d => D.tlv(0x17, te(d.toISOString().replace(/[-:T]/g, '').slice(2, 14) + 'Z'));
export const gen = d => D.tlv(0x18, te(d.toISOString().replace(/[-:T]/g, '').slice(0, 14) + 'Z'));
const attr = (o, v, tag = 0x0c) => D.set(D.seq(D.oid(o), D.tlv(tag, te(v))));
const uri = u => D.tlv(0x86, te(u));
const sigAlgOf = key => key.asymmetricKeyType === 'ec' ? D.algo(D.OID.ecdsaSha256, false) : D.algo(D.OID.sha256Rsa);
const signWith = (key, data) => new Uint8Array(nodeSign('sha256', data, key));

let serialSeq = 1000;

/* { kind: 'rsa'|'ec', cn, id (serialNumber), issuer?: { cert, key }, qualified, ocsp, crl, caIssuers, ca } */
export function makeCert(o = {}) {
  const { privateKey, publicKey } = o.kind === 'ec' ? generateKeyPairSync('ec', { namedCurve: 'P-256' }) : generateKeyPairSync('rsa', { modulusLength: 2048 });
  const name = D.seq(attr(D.OID.country, 'BG', 0x13), attr(D.OID.cn, o.cn || 'Тест'), ...(o.id ? [attr(D.OID.serialNumber, o.id, 0x13)] : []));
  const issuerName = o.issuer ? D.read(D.read(o.issuer.der).children[0].raw).children[5].raw : name;
  const exts = [];
  if (o.ca) exts.push(D.seq(D.oid('2.5.29.19'), D.tlv(0x01, Uint8Array.of(0xff)), D.octets(D.seq(D.tlv(0x01, Uint8Array.of(0xff))))));
  else exts.push(D.seq(D.oid(D.OID.keyUsage), D.tlv(0x01, Uint8Array.of(0xff)), D.octets(D.tlv(0x03, Uint8Array.of(6, 0xc0)))));
  if (o.qualified) exts.push(D.seq(D.oid(D.OID.qcStatements), D.octets(D.seq(D.seq(D.oid(D.OID.qcCompliance)), D.seq(D.oid(D.OID.qcSscd))))));
  if (o.crl) exts.push(D.seq(D.oid(D.OID.crlDp), D.octets(D.seq(D.seq(D.ctx(0, D.ctx(0, uri(o.crl))))))));
  const aia = [];
  if (o.ocsp) aia.push(D.seq(D.oid(D.OID.ocsp), uri(o.ocsp)));
  if (o.caIssuers) aia.push(D.seq(D.oid(D.OID.caIssuers), uri(o.caIssuers)));
  if (aia.length) exts.push(D.seq(D.oid(D.OID.aia), D.octets(D.seq(...aia))));
  const signer = o.issuer ? o.issuer.key : privateKey;
  const serial = o.serial || ++serialSeq;
  const tbs = D.seq(D.ctx(0, D.int(2)), D.int(serial), sigAlgOf(signer), issuerName,
    D.seq(utc(new Date(Date.now() - 864e5)), utc(new Date(Date.now() + 365 * 864e5))), name,
    new Uint8Array(publicKey.export({ format: 'der', type: 'spki' })), D.ctx(3, D.seq(...exts)));
  const der = D.seq(tbs, sigAlgOf(signer), D.bits(signWith(signer, tbs)));
  return { der, key: privateKey, serial, cert: D.parseCert(der) };
}

/* OCSP отговор: status 'good' | 'revoked' | 'unknown'; signer – ключът, с който се подписва (по подразбиране – на CA) */
export function ocspResponse(ca, leaf, status, signerKey) {
  const sha1 = b => createHash('sha1').update(b).digest();
  const caCert = D.parseCert(ca.der);
  const keyBits = D.read(caCert.spki).children[1].body.subarray(1);
  const certId = D.seq(D.algo(D.OID.sha1), D.octets(sha1(leaf.cert.issuerRaw)), D.octets(sha1(keyBits)), leaf.cert.serialRaw);
  const st = status === 'good' ? Uint8Array.of(0x80, 0) : status === 'revoked' ? D.ctx(1, D.concat([gen(new Date(Date.now() - 3600e3)), D.ctx(0, D.tlv(0x0a, Uint8Array.of(1)))])) : Uint8Array.of(0x82, 0);
  const single = D.seq(certId, st, gen(new Date(Date.now() - 60e3)), D.ctx(0, gen(new Date(Date.now() + 864e5))));
  const tbs = D.seq(D.ctx(2, D.octets(sha1(keyBits))), gen(new Date()), D.seq(single));
  const key = signerKey || ca.key;
  const basic = D.seq(tbs, sigAlgOf(key), D.bits(signWith(key, tbs)));
  return D.seq(D.tlv(0x0a, Uint8Array.of(0)), D.ctx(0, D.seq(D.oid(D.OID.ocspBasic), D.octets(basic))));
}

/* CRL с прекратените серийни номера */
export function crl(ca, revokedSerials = []) {
  const caCert = D.parseCert(ca.der);
  const list = revokedSerials.length ? D.seq(...revokedSerials.map(s => D.seq(D.int(s), utc(new Date(Date.now() - 3600e3))))) : null;
  const tbs = D.seq(D.int(1), sigAlgOf(ca.key), caCert.subjectRaw, utc(new Date(Date.now() - 3600e3)), utc(new Date(Date.now() + 864e5)), list);
  return D.seq(tbs, sigAlgOf(ca.key), D.bits(signWith(ca.key, tbs)));
}

/* fetch към доставчика: routes { url: () => { status, body } } */
export function fakeProvider(routes, realFetch) {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    const u = String(url);
    if (routes[u]) { calls.push(u); const r = routes[u](init); return new Response(r.body, { status: r.status || 200 }); }
    return realFetch(url, init);
  };
  return calls;
}
