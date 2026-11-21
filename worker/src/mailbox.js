/*
 * Пощенската кутия на приемната (priemna@zdoi.eu) през Microsoft Graph:
 *   – изпраща писма от priemna с адрес за отговор priemna+<етикет на преписката>@zdoi.eu;
 *   – чете входящите писма след определен момент, с прикачените файлове.
 * Правата на приложението са ограничени с RBAC for Applications в Exchange само до тази кутия и no-reply.
 * В тестовете се подменя с env.__mailbox.
 */

import { graph } from './graph.js';

export const mailboxAddress = env => String(env.MAILBOX || 'priemna@zdoi.eu').toLowerCase();

/* priemna@zdoi.eu + p2026-0001 → priemna+p2026-0001@zdoi.eu */
export function plusOf(address, tag) {
  const [local, domain] = String(address).toLowerCase().split('@');
  return local + '+' + tag + '@' + domain;
}
export const plusAddress = (env, tag) => plusOf(mailboxAddress(env), tag);

const rcpt = list => (list || []).filter(Boolean).map(a => ({ emailAddress: { address: a } }));
const fileAtt = a => ({ '@odata.type': '#microsoft.graph.fileAttachment', name: a.name, contentType: a.contentType || 'application/octet-stream', contentBytes: toB64(a.bytes) });

function toB64(bytes) {
  let s = '';
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
  return btoa(s);
}
export function fromB64(text) {
  const raw = atob(String(text || '')), out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

/* address: кутията на лицето (по подразбиране – приемната); приложението трябва да има достъп до нея в Exchange */
export function graphMailbox(env, address) {
  const addr = String(address || mailboxAddress(env)).toLowerCase();
  const box = '/users/' + encodeURIComponent(addr);
  return {
    address: addr,

    /* m: { to[], cc[], subject, text, replyTo, attachments[{name, contentType, bytes}], replyToGraphId } */
    async send(m) {
      const replyTo = m.replyTo ? [{ emailAddress: { address: m.replyTo } }] : [];
      if (m.replyToGraphId) {
        // отговор в същата нишка: черновата пази Message-ID на оригинала (In-Reply-To/References)
        const draft = await graph(env, 'POST', box + '/messages/' + encodeURIComponent(m.replyToGraphId) + '/createReply', {});
        await graph(env, 'PATCH', box + '/messages/' + draft.id, {
          subject: m.subject, body: { contentType: 'Text', content: m.text }, toRecipients: rcpt(m.to), ccRecipients: rcpt(m.cc), replyTo
        });
        for (const a of m.attachments || []) await graph(env, 'POST', box + '/messages/' + draft.id + '/attachments', fileAtt(a));
        await graph(env, 'POST', box + '/messages/' + draft.id + '/send');
        return {};
      }
      await graph(env, 'POST', box + '/sendMail', {
        message: {
          subject: m.subject, body: { contentType: 'Text', content: m.text }, toRecipients: rcpt(m.to), ccRecipients: rcpt(m.cc), replyTo,
          attachments: (m.attachments || []).map(fileAtt)
        },
        saveToSentItems: true
      });
      return {};
    },

    /* входящите писма след момента sinceIso (по реда на получаване) */
    async fetchSince(sinceIso, limit = 50) {
      const sel = 'id,internetMessageId,receivedDateTime,from,toRecipients,ccRecipients,subject,body,hasAttachments';
      const url = box + '/mailFolders/inbox/messages?$filter=' + encodeURIComponent('receivedDateTime ge ' + sinceIso) +
        '&$orderby=receivedDateTime asc&$top=' + limit + '&$select=' + sel;
      const r = await graph(env, 'GET', url, undefined, { Prefer: 'outlook.body-content-type="text"' });
      const out = [];
      for (const m of r.value || []) {
        const atts = [];
        if (m.hasAttachments) {
          const a = await graph(env, 'GET', box + '/messages/' + encodeURIComponent(m.id) + '/attachments');
          for (const x of a.value || []) {
            if (x['@odata.type'] !== '#microsoft.graph.fileAttachment' || x.isInline) continue;
            atts.push({ name: x.name, contentType: x.contentType, size: x.size, bytes: fromB64(x.contentBytes) });
          }
        }
        out.push({
          graphId: m.id, messageId: m.internetMessageId || m.id, at: m.receivedDateTime,
          from: (m.from && m.from.emailAddress && m.from.emailAddress.address) || '',
          fromName: (m.from && m.from.emailAddress && m.from.emailAddress.name) || '',
          to: (m.toRecipients || []).map(x => x.emailAddress.address), cc: (m.ccRecipients || []).map(x => x.emailAddress.address),
          subject: m.subject || '', body: (m.body && m.body.content) || '', attachments: atts
        });
      }
      return out;
    }
  };
}

export const getMailbox = (env, address) =>
  (env.__mailboxes && address && env.__mailboxes[String(address).toLowerCase()]) || env.__mailbox || graphMailbox(env, address);
