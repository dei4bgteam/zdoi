/* Публичните регистри на доставчика (OCSP, CRL) и вход/свързване с КЕП */

import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { sign as nodeSign } from 'node:crypto';
import * as D from '../site/js/der.js';
import { makeCert, ocspResponse, crl, fakeProvider } from './pki.js';
import { checkRevocation } from '../worker/src/revocation.js';
import { ready } from './helpers.js';
import { makeApp } from '../worker/src/core.js';
import { storeCert } from '../worker/src/acme.js';

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

const OCSP = 'http://ocsp.test-qtsp.bg', CRL = 'http://crl.test-qtsp.bg/ca.crl', CA_URL = 'http://repo.test-qtsp.bg/ca.crt';

function provider() {
  const ca = makeCert({ cn: 'Test QTSP Qualified CA', ca: true });
  const person = (o = {}) => makeCert(Object.assign({ cn: 'Мария Тестова', id: 'PNOBG-9001010000', issuer: ca, qualified: true, ocsp: OCSP, crl: CRL, caIssuers: CA_URL }, o));
  return { ca, person };
}

test('OCSP: валидно, прекратено, неизвестно; издателят – от веригата или от адреса в сертификата', async () => {
  const { ca, person } = provider();
  const p = person();
  let status = 'good';
  const calls = fakeProvider({ [OCSP]: () => ({ body: ocspResponse(ca, p, status) }), [CA_URL]: () => ({ body: ca.der }), [CRL]: () => ({ body: crl(ca, []) }) }, realFetch);

  let r = await checkRevocation(p.cert, [ca.der]);
  assert.equal(r.status, 'good');
  assert.equal(r.method, 'OCSP');
  assert.ok(!calls.includes(CA_URL));

  r = await checkRevocation(p.cert, []); // без верига: издателят се сваля
  assert.equal(r.status, 'good');
  assert.ok(calls.includes(CA_URL));

  status = 'revoked';
  r = await checkRevocation(p.cert, [ca.der]);
  assert.equal(r.status, 'revoked');
  assert.equal(r.reason, 'компрометиран ключ');

  // OCSP „не знае“ → CRL
  status = 'unknown';
  r = await checkRevocation(p.cert, [ca.der]);
  assert.equal(r.method, 'CRL');
  assert.equal(r.status, 'good');
});

test('OCSP с чужд подпис се отхвърля и се ползва CRL; прекратено по CRL; недостъпни регистри – неизвестно', async () => {
  const { ca, person } = provider();
  const p = person(), other = makeCert({ cn: 'Измамник' });
  let crlList = [];
  let ocspOk = true;
  fakeProvider({
    [OCSP]: () => (ocspOk ? { body: ocspResponse(ca, p, 'good', other.key) } : { status: 503, body: '' }),
    [CRL]: () => ({ body: crl(ca, crlList) }), [CA_URL]: () => ({ body: ca.der })
  }, realFetch);
  let r = await checkRevocation(p.cert, [ca.der]);
  assert.equal(r.method, 'CRL');
  assert.equal(r.status, 'good');

  crlList = [5, p.serial, 99999];
  r = await checkRevocation(p.cert, [ca.der]);
  assert.equal(r.status, 'revoked');
  assert.equal(r.method, 'CRL');

  // подправен CRL (подписан от друг) – не се приема
  globalThis.fetch = async url => String(url) === CRL ? new Response(crl(other, [])) : new Response('', { status: 503 });
  r = await checkRevocation(p.cert, [ca.der]);
  assert.equal(r.status, 'unknown');
  assert.match(r.note, /CRL: (невалиден подпис|друг издател)/);

  // фалшив „издател“ във веригата не се приема
  ocspOk = false;
  fakeProvider({ [OCSP]: () => ({ status: 503, body: '' }), [CRL]: () => ({ status: 503, body: '' }), [CA_URL]: () => ({ status: 404, body: '' }) }, realFetch);
  r = await checkRevocation(p.cert, [other.der]);
  assert.equal(r.status, 'unknown');
  assert.match(r.note, /издателят/);
});

/* вход и свързване с КЕП – подписът на картата се симулира с ключа на удостоверението */
async function kepSetup() {
  const r = await ready();
  const app = makeApp(r.env, r.env.__store, r.env.__kv, null);
  const server = makeCert({ cn: 'adm.test' });
  await storeCert(app, new Uint8Array(server.key.export({ format: 'der', type: 'pkcs8' })), [D.b64(server.der)], '2036-01-01T00:00:00Z');
  return r;
}
const cardSign = (person, ch) => ({ id: ch.id, signature: D.b64(new Uint8Array(nodeSign('sha256', D.unb64(ch.content), person.key))), chain: [D.b64(person.der)] });

test('вход с КЕП: свързване от профила, вход, прекратено удостоверение, чужд КЕП', async () => {
  const { env, admin } = await kepSetup();
  const { client } = await import('./helpers.js');
  const { ca, person } = provider();
  const maria = person();
  let status = 'good';
  fakeProvider({ [OCSP]: () => ({ body: ocspResponse(ca, maria, status) }), [CRL]: () => ({ body: crl(ca, []) }), [CA_URL]: () => ({ body: ca.der }) }, realFetch);

  const anon = client(env);
  assert.deepEqual((await anon.call('oauth.providers')).providers.map(p => p.id), ['kep']);

  // несвързан КЕП
  let ch = await anon.call('kep.challenge');
  let r = await anon.call('kep.login', cardSign(maria, ch));
  assert.equal(r.error, 'kep');
  assert.match(r.message, /не е свързан/);

  // свързване (влязъл администратор)
  ch = await admin.call('kep.linkChallenge');
  r = await admin.call('kep.link', cardSign(maria, ch));
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal((await admin.call('me')).me.linked.kep.name, 'Мария Тестова');
  // challenge не се ползва повторно
  assert.equal((await admin.call('kep.link', cardSign(maria, ch))).error, 'kep');

  // вход
  ch = await anon.call('kep.challenge');
  r = await anon.call('kep.login', cardSign(maria, ch));
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.me.username, 'admin');
  assert.ok(anon.cookie);

  // подновен КЕП (нов ключ, същото лице) – влиза
  const renewed = person();
  fakeProvider({ [OCSP]: () => ({ body: ocspResponse(ca, renewed, 'good') }), [CRL]: () => ({ body: crl(ca, []) }), [CA_URL]: () => ({ body: ca.der }) }, realFetch);
  ch = await client(env).call('kep.challenge');
  assert.equal((await client(env).call('kep.login', cardSign(renewed, ch))).ok, true);

  // подпис с друг ключ – отказ
  const ivan = person({ cn: 'Иван', id: 'PNOBG-7001010000' });
  ch = await client(env).call('kep.challenge');
  r = await client(env).call('kep.login', Object.assign(cardSign(ivan, ch), { chain: [D.b64(maria.der)] }));
  assert.match(r.message, /невалиден/);

  // прекратено удостоверение
  status = 'revoked';
  fakeProvider({ [OCSP]: () => ({ body: ocspResponse(ca, maria, status) }), [CRL]: () => ({ body: crl(ca, []) }), [CA_URL]: () => ({ body: ca.der }) }, realFetch);
  ch = await client(env).call('kep.challenge');
  r = await client(env).call('kep.login', cardSign(maria, ch));
  assert.match(r.message, /прекратено или спряно/);

  // неквалифициран
  const plain = person({ qualified: false, id: 'PNOBG-6001010000' });
  ch = await client(env).call('kep.challenge');
  r = await client(env).call('kep.login', cardSign(plain, ch));
  assert.match(r.message, /квалифициран/);

  // изключен от администратора
  await admin.call('oauth.save', { kep: false });
  assert.equal((await client(env).call('kep.challenge')).error, 'value');
});
