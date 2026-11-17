/*
 * Минимален ASN.1 DER: кодиране, разчитане, X.509 сертификати и CMS SignedData (за PAdES подпис с КЕП).
 * Общ за браузъра (site/js) и Worker-а (worker/src/der.js го внася).
 */

export const OID = {
  data: '1.2.840.113549.1.7.1', signedData: '1.2.840.113549.1.7.2',
  contentType: '1.2.840.113549.1.9.3', messageDigest: '1.2.840.113549.1.9.4', signingCertV2: '1.2.840.113549.1.9.16.2.47',
  extensionRequest: '1.2.840.113549.1.9.14',
  sha256: '2.16.840.1.101.3.4.2.1', rsa: '1.2.840.113549.1.1.1', sha256Rsa: '1.2.840.113549.1.1.11',
  ec: '1.2.840.10045.2.1', ecdsaSha256: '1.2.840.10045.4.3.2', ecdsaSha384: '1.2.840.10045.4.3.3',
  crlDp: '2.5.29.31', aia: '1.3.6.1.5.5.7.1.1', ocsp: '1.3.6.1.5.5.7.48.1', caIssuers: '1.3.6.1.5.5.7.48.2', ocspBasic: '1.3.6.1.5.5.7.48.1.1', sha1: '1.3.14.3.2.26',
  sha1Rsa: '1.2.840.113549.1.1.5', sha384Rsa: '1.2.840.113549.1.1.12', sha512Rsa: '1.2.840.113549.1.1.13', email: '1.2.840.113549.1.9.1',
  cn: '2.5.4.3', serialNumber: '2.5.4.5', givenName: '2.5.4.42', surname: '2.5.4.4', org: '2.5.4.10', orgId: '2.5.4.97', country: '2.5.4.6',
  san: '2.5.29.17', keyUsage: '2.5.29.15', qcStatements: '1.3.6.1.5.5.7.1.3', qcCompliance: '0.4.0.1862.1.1', qcSscd: '0.4.0.1862.1.4',
  p256: '1.2.840.10045.3.1.7', p384: '1.3.132.0.34'
};

/* ---------- кодиране ---------- */

const cat = parts => {
  const n = parts.reduce((s, p) => s + p.length, 0), out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
export const concat = cat;

function len(n) {
  if (n < 128) return Uint8Array.of(n);
  const b = [];
  while (n > 0) { b.unshift(n & 255); n = Math.floor(n / 256); }
  return Uint8Array.of(0x80 | b.length, ...b);
}
export const tlv = (tag, body) => cat([Uint8Array.of(tag), len(body.length), body]);
export const seq = (...x) => tlv(0x30, cat(x.filter(Boolean)));
export const set = (...x) => tlv(0x31, cat(x.filter(Boolean)));
/* SET OF в DER: елементите се подреждат по байтове */
export const setOf = (...x) => {
  const items = x.filter(Boolean).slice().sort((a, b) => { for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i]; return a.length - b.length; });
  return tlv(0x31, cat(items));
};
export const nul = () => Uint8Array.of(5, 0);
export const octets = b => tlv(0x04, b);
export const bits = b => tlv(0x03, cat([Uint8Array.of(0), b]));
export const utf8 = s => tlv(0x0c, new TextEncoder().encode(s));
export const ctx = (n, body, constructed = true) => tlv((constructed ? 0xa0 : 0x80) | n, body);
export const int = v => {
  let b;
  if (v instanceof Uint8Array) b = v;
  else { const a = []; let n = v; do { a.unshift(n & 255); n = Math.floor(n / 256); } while (n > 0); b = Uint8Array.from(a); }
  let i = 0;
  while (i < b.length - 1 && b[i] === 0 && !(b[i + 1] & 0x80)) i++;
  b = b.subarray(i);
  return tlv(0x02, b[0] & 0x80 ? cat([Uint8Array.of(0), b]) : b);
};
export function oid(s) {
  const p = s.split('.').map(Number), out = [40 * p[0] + p[1]];
  for (const v of p.slice(2)) {
    const b = [v & 127];
    let n = Math.floor(v / 128);
    while (n > 0) { b.unshift((n & 127) | 128); n = Math.floor(n / 128); }
    out.push(...b);
  }
  return tlv(0x06, Uint8Array.from(out));
}
export const algo = (o, withNull = true) => seq(oid(o), withNull ? nul() : null);

/* ---------- разчитане ---------- */

/* връща { tag, len, start (тяло), end, hdr, raw, children? } */
export function read(buf, pos = 0, depth = Infinity) {
  const tag = buf[pos];
  let p = pos + 1, l = buf[p++];
  if (l & 0x80) { const n = l & 127; l = 0; for (let i = 0; i < n; i++) l = l * 256 + buf[p++]; }
  const node = { tag, start: p, end: p + l, hdr: pos, raw: buf.subarray(pos, p + l), body: buf.subarray(p, p + l) };
  if ((tag & 0x20) && depth > 0) {
    node.children = [];
    for (let q = p; q < p + l;) { const c = read(buf, q, depth - 1); node.children.push(c); q = c.end; }
  }
  return node;
}
export function oidStr(b) {
  const out = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) { v = v * 128 + (b[i] & 127); if (!(b[i] & 128)) { out.push(v); v = 0; } }
  return out.join('.');
}
const text = n => new TextDecoder(n.tag === 0x1e ? 'utf-16be' : 'utf-8').decode(n.body);
function timeOf(n) {
  const s = new TextDecoder().decode(n.body);
  const m = n.tag === 0x17 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(s) : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(s);
  if (!m) return null;
  const y = n.tag === 0x17 ? (Number(m[1]) < 50 ? 2000 : 1900) + Number(m[1]) : Number(m[1]);
  return new Date(Date.UTC(y, m[2] - 1, m[3], m[4], m[5], m[6] || 0));
}
function nameOf(n) {
  const o = {};
  for (const rdn of n.children) for (const atv of rdn.children) o[oidStr(atv.children[0].body)] = text(atv.children[1]);
  return o;
}

export const b64 = u8 => { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };
export const unb64 = s => Uint8Array.from(atob(String(s).replace(/\s+/g, '')), c => c.charCodeAt(0));
export const hex = u8 => [...u8].map(b => b.toString(16).padStart(2, '0')).join('');

/* X.509: полетата, нужни за подписа и проверката */
export function parseCert(der) {
  const c = read(der), tbs = c.children[0], f = tbs.children;
  let i = f[0].tag === 0xa0 ? 1 : 0;
  const serial = f[i], issuer = f[i + 2], validity = f[i + 3], subject = f[i + 4], spki = f[i + 5];
  const extNode = f.find(x => x.tag === 0xa3);
  const ext = {};
  if (extNode) for (const e of extNode.children[0].children) {
    const id = oidStr(e.children[0].body);
    ext[id] = e.children[e.children.length - 1].body;
  }
  const subj = nameOf(subject), iss = nameOf(issuer);
  const keyAlg = oidStr(spki.children[0].children[0].body);
  const curve = spki.children[0].children[1] && spki.children[0].children[1].tag === 0x06 ? oidStr(spki.children[0].children[1].body) : '';
  let qualified = false, sscd = false;
  if (ext[OID.qcStatements]) {
    const qs = read(ext[OID.qcStatements]);
    for (const st of qs.children) { const id = oidStr(st.children[0].body); if (id === OID.qcCompliance) qualified = true; if (id === OID.qcSscd) sscd = true; }
  }
  const uris = node => { const out = []; const walk = n => { if (n.tag === 0x86) out.push(new TextDecoder().decode(n.body)); (n.children || []).forEach(walk); }; walk(node); return out; };
  const crl = ext[OID.crlDp] ? uris(read(ext[OID.crlDp])).filter(u => /^https?:/i.test(u)) : [];
  const ocsp = [], caIssuers = [];
  if (ext[OID.aia]) for (const ad of read(ext[OID.aia]).children) {
    const m = oidStr(ad.children[0].body), g = ad.children[1];
    if (g.tag === 0x86) (m === OID.ocsp ? ocsp : m === OID.caIssuers ? caIssuers : []).push(new TextDecoder().decode(g.body));
  }
  let keyUsage = 0;
  if (ext[OID.keyUsage]) { const ku = read(ext[OID.keyUsage]).body; keyUsage = (ku[1] || 0) << 8 | (ku[2] || 0); }
  return {
    der, tbs: tbs.raw, serial: serial.body, serialRaw: serial.raw, issuerRaw: issuer.raw, subjectRaw: subject.raw, spki: spki.raw,
    notBefore: timeOf(validity.children[0]), notAfter: timeOf(validity.children[1]),
    subject: subj, issuer: iss, keyAlg, curve, qualified, sscd,
    nonRepudiation: !!(keyUsage & 0x4000), digitalSignature: !!(keyUsage & 0x8000),
    sigAlg: oidStr(c.children[1].children[0].body), signature: c.children[2].body.subarray(1),
    crl, ocsp, caIssuers, email: subj[OID.email] || '',
    name: subj[OID.cn] || [subj[OID.givenName], subj[OID.surname]].filter(Boolean).join(' '),
    org: subj[OID.org] || '', id: subj[OID.serialNumber] || '', issuerName: iss[OID.cn] || iss[OID.org] || ''
  };
}

/* ---------- CMS за PAdES (ETSI EN 319 142-1, ниво B-B) ---------- */

/* подписаните атрибути: contentType, messageDigest, signingCertificateV2; без signingTime (времето е в /M на PDF) */
export function signedAttrs(digest, cert, certHash) {
  const essCertIdV2 = seq(octets(certHash), seq(seq(ctx(4, cert.issuerRaw)), cert.serialRaw)); // hashAlgorithm по подразбиране е SHA-256
  return [
    seq(oid(OID.contentType), set(oid(OID.data))),
    seq(oid(OID.messageDigest), set(octets(digest))),
    seq(oid(OID.signingCertV2), set(seq(seq(essCertIdV2))))
  ];
}
/* това подписва картата: DER на SET OF атрибутите */
export const attrsToSign = attrs => setOf(...attrs);

export function signedData(attrs, signature, chain, cert) {
  const ec = cert.keyAlg === OID.ec;
  const signerInfo = seq(int(1), seq(cert.issuerRaw, cert.serialRaw), algo(OID.sha256),
    tlv(0xa0, read(setOf(...attrs)).body), ec ? algo(OID.ecdsaSha256, false) : algo(OID.rsa), octets(signature));
  const sd = seq(int(1), set(algo(OID.sha256)), seq(oid(OID.data)), ctx(0, cat(chain)), set(signerInfo));
  return seq(oid(OID.signedData), ctx(0, sd));
}

/* разчита CMS SignedData от PDF подпис */
export function parseSignedData(der) {
  const ci = read(der), sd = ci.children[1].children[0];
  const parts = sd.children;
  const certsNode = parts.find(x => x.tag === 0xa0);
  const certs = certsNode ? certsNode.children.map(x => x.raw) : [];
  const si = parts[parts.length - 1].children[0].children;
  const sid = si[1];
  const attrsNode = si.find(x => x.tag === 0xa0);
  const sigAlgIdx = si.indexOf(attrsNode) + 1;
  const attrs = {};
  for (const a of attrsNode.children) attrs[oidStr(a.children[0].body)] = a.children[1].children[0];
  return {
    certs, sidIssuer: sid.children[0].raw, sidSerial: sid.children[1].body,
    attrsDer: cat([Uint8Array.of(0x31), attrsNode.raw.subarray(1)]), // [0] IMPLICIT → SET за проверката
    digest: attrs[OID.messageDigest] ? attrs[OID.messageDigest].body : null,
    sigAlg: oidStr(si[sigAlgIdx].children[0].body), signature: si[sigAlgIdx + 1].body
  };
}

/* ECDSA: DER (r, s) ↔ r||s за WebCrypto */
export function ecdsaRaw(der, size) {
  const s = read(der);
  const fix = b => { let x = b; while (x.length > size && x[0] === 0) x = x.subarray(1); const o = new Uint8Array(size); o.set(x, size - x.length); return o; };
  return cat([fix(s.children[0].body), fix(s.children[1].body)]);
}
export function ecdsaDer(raw) {
  const h = raw.length / 2;
  return seq(int(raw.subarray(0, h)), int(raw.subarray(h)));
}
