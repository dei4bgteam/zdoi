/* Хешове, случайни ключове и подписване (WebCrypto – работи в Cloudflare Workers и в Node 20+). */

const enc = new TextEncoder();
const subtle = globalThis.crypto.subtle;

export const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
export const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
export const b64url = buf => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const bytes = s => (typeof s === 'string' ? enc.encode(s) : s);

export async function sha256(s) {
  return hex(await subtle.digest('SHA-256', bytes(s)));
}

export function randomToken() {
  const a = new Uint8Array(32);
  crypto.getRandomValues(a);
  return hex(a);
}

/* код от 8 цифри без отместване към малките числа */
export function randomCode() {
  const a = new Uint32Array(1);
  let n;
  do { crypto.getRandomValues(a); n = a[0]; } while (n >= 4294000000);
  return String(n % 1e8).padStart(8, '0');
}

export async function hmac(key, text) {
  const k = await subtle.importKey('raw', bytes(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64(await subtle.sign('HMAC', k, bytes(text)));
}

export function sameText(a, b) {
  a = String(a); b = String(b);
  if (!a || a.length !== b.length) return false;
  let x = 0;
  for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return x === 0;
}

/* ---------- RS256 за вход със сертификат в Microsoft Entra ---------- */

function pemBody(pem) {
  const body = String(pem).replace(/-----[A-Z ]+-----/g, '').replace(/\\n/g, '').replace(/\s+/g, '');
  const raw = atob(body), out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

const hexToBytes = h => new Uint8Array((String(h).replace(/[^0-9a-fA-F]/g, '').match(/../g) || []).map(x => parseInt(x, 16)));

export async function signRs256(pem, text) {
  if (/BEGIN RSA PRIVATE KEY/.test(pem)) throw new Error('Ключът трябва да е във формат PKCS#8 (BEGIN PRIVATE KEY).');
  const key = await subtle.importKey('pkcs8', pemBody(pem), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  return b64url(await subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(text)));
}

/* подписано твърдение за client_credentials; важи 5 минути */
export async function clientAssertion({ clientId, key, sha1, sha256: sha256Hex }, tokenUrl) {
  const now = Math.floor(Date.now() / 1000);
  const part = o => b64url(enc.encode(JSON.stringify(o)));
  const head = { alg: 'RS256', typ: 'JWT', x5t: b64url(hexToBytes(sha1)) };
  if (sha256Hex) head['x5t#S256'] = b64url(hexToBytes(sha256Hex));
  const claims = { aud: tokenUrl, iss: clientId, sub: clientId, jti: randomToken(), nbf: now, iat: now, exp: now + 300 };
  const unsigned = part(head) + '.' + part(claims);
  return unsigned + '.' + (await signRs256(key, unsigned));
}
