/*
 * Microsoft Graph с вход със сертификат (client_credentials + client_assertion).
 * Нужни права на приложението: Sites.Selected (с роля write/manage за сайта) и Mail.Send,
 * ограничено с RBAC for Applications само до пощенската кутия на изпращача.
 */

import { clientAssertion } from './crypto.js';

const GRAPH = 'https://graph.microsoft.com/v1.0';
let memToken = null;

export function msConfig(env) {
  const c = {
    tenant: env.MS_TENANT, clientId: env.MS_CLIENT_ID, key: env.MS_PRIVATE_KEY,
    sha1: env.MS_CERT_SHA1, sha256: env.MS_CERT_SHA256
  };
  return c.tenant && c.clientId && c.key && c.sha1 ? c : null;
}

/* само кодът на грешката, без целия отговор */
async function errorOf(r) {
  try {
    const e = await r.json();
    const aad = /AADSTS\d+/.exec(e.error_description || '');
    return (String((e.error && e.error.code) || e.error || '').slice(0, 80) + ' ' + String((e.error && e.error.message) || '').slice(0, 200) + (aad ? ' ' + aad[0] : '')).trim();
  } catch (_) { return ''; }
}

export class GraphError extends Error {
  constructor(status, detail) {
    super('graph ' + status + (detail ? ': ' + detail : ''));
    this.status = status;
  }
}

export async function graphToken(env) {
  if (env.GRAPH_TOKEN) return env.GRAPH_TOKEN; // делегиран токен от tools/sp-provision.js
  if (memToken && memToken.exp > Date.now() + 60000) return memToken.value;
  const c = msConfig(env);
  if (!c) throw new Error('Липсват MS_TENANT, MS_CLIENT_ID, MS_PRIVATE_KEY или MS_CERT_SHA1.');
  const url = 'https://login.microsoftonline.com/' + encodeURIComponent(c.tenant.trim()) + '/oauth2/v2.0/token';
  const body = new URLSearchParams({
    client_id: c.clientId.trim(), scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials',
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: await clientAssertion(c, url)
  });
  const r = await fetch(url, { method: 'POST', body });
  if (r.status !== 200) throw new GraphError(r.status, 'токен ' + (await errorOf(r)));
  const t = await r.json();
  memToken = { value: t.access_token, exp: Date.now() + (Number(t.expires_in) || 3600) * 1000 };
  return memToken.value;
}

/* заявка към Graph; повтаря при 429/503 и при изтекъл токен */
export async function graph(env, method, path, body, headers = {}) {
  const url = path.startsWith('https://') ? path : GRAPH + path;
  for (let attempt = 0; attempt < 4; attempt++) {
    const r = await fetch(url, {
      method,
      headers: Object.assign({ Authorization: 'Bearer ' + (await graphToken(env)), Accept: 'application/json' },
        body !== undefined ? { 'Content-Type': 'application/json' } : {}, headers),
      body: body !== undefined ? JSON.stringify(body) : undefined
    });
    if (r.status === 401 && attempt === 0) { memToken = null; continue; }
    if ((r.status === 429 || r.status === 503 || r.status === 504) && attempt < 3) {
      const wait = Math.min(5, Number(r.headers.get('Retry-After')) || attempt + 1);
      await new Promise(res => setTimeout(res, wait * 1000));
      continue;
    }
    if (r.status === 204 || r.status === 202) return {};
    if (!r.ok) throw new GraphError(r.status, await errorOf(r));
    return r.json();
  }
  throw new GraphError(429, 'твърде много заявки');
}

/* писмата не се пазят в „Изпратени“, защото съдържат еднократни връзки и кодове */
export async function sendMail(env, to, subject, text, replyTo) {
  const sender = env.MAIL_SENDER;
  if (!sender) throw new Error('Липсва MAIL_SENDER.');
  await graph(env, 'POST', '/users/' + encodeURIComponent(sender) + '/sendMail', {
    message: {
      subject, body: { contentType: 'Text', content: text },
      toRecipients: [{ emailAddress: { address: to } }],
      replyTo: replyTo ? [{ emailAddress: { address: replyTo } }] : []
    },
    saveToSentItems: false
  });
}
