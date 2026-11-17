/* Подпис с КЕП от край до край: PDF → BISS (симулиран, със същата проверка на заявката) → PAdES → проверка в системата */

import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify, createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ready } from './helpers.js';
import { makeApp } from '../worker/src/core.js';
import { storeCert } from '../worker/src/acme.js';
import { signPdf, chooseSigner } from '../site/js/kep.js';
import { verifyPdf } from '../worker/src/kep.js';

/* pdf-lib (UMD) както в браузъра: задава глобалния PDFLib */
globalThis.window = globalThis.window || {};
new Function(readFileSync(new URL('../site/vendor/pdf-lib.min.js', import.meta.url), 'utf8')).call(globalThis);
window.PDFLib = globalThis.PDFLib;

const fx = n => readFileSync(new URL('./fixtures/' + n, import.meta.url), 'utf8');
const derOf = pem => Buffer.from(pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''), 'base64');
const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

/* BISS: /version, /getsigner, /sign; проверява signedContents като истинския (SHA256withRSA върху SHA-256 на данните) */
function fakeBiss(card, serverCertB64) {
  const cardKey = createPrivateKey(fx(card + '.key')), cardDer = derOf(fx(card + '.crt'));
  const serverPub = createPublicKey({ key: Buffer.from(serverCertB64, 'base64'), format: 'der', type: 'spki' }) ;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    const u = new URL(String(url));
    if (u.hostname !== 'localhost') return realFetch(url, init);
    if (u.port !== '53953') throw new Error('ECONNREFUSED');
    const body = init && init.body ? JSON.parse(init.body) : null;
    calls.push(u.pathname);
    const json = o => new Response(JSON.stringify(o), { status: 200 });
    if (u.pathname === '/version') return json({ version: '3.46' });
    if (u.pathname === '/getsigner') return json({ status: 'ok', reasonCode: 200, chain: [cardDer.toString('base64')] });
    if (u.pathname === '/sign') {
      const data = Buffer.from(body.contents[0], 'base64');
      const okReq = nodeVerify('sha256', createHash('sha256').update(data).digest(), serverPub, Buffer.from(body.signedContents[0], 'base64'));
      if (!okReq) return json({ status: 'failed', reasonCode: 500, reasonText: 'Подписът на заявката е невалиден' });
      const isEc = card.includes('ec');
      const sig = nodeSign('sha256', data, isEc ? { key: cardKey, dsaEncoding: 'der' } : cardKey);
      return json({ status: 'ok', reasonCode: 200, signatures: [sig.toString('base64')], signatureType: 'signature' });
    }
    return new Response('{}', { status: 404 });
  };
  return calls;
}

async function samplePdf() {
  const { PDFDocument, StandardFonts } = window.PDFLib;
  const d = await PDFDocument.create();
  const p = d.addPage([595, 842]);
  p.drawText('ZDOI test application', { x: 50, y: 780, size: 14, font: await d.embedFont(StandardFonts.Helvetica) });
  return d.save();
}

/* сървърният сертификат от фикстурите вместо Let's Encrypt */
async function withServerCert(env) {
  const app = makeApp(env, env.__store, env.__kv, null);
  const pkcs8 = createPrivateKey(fx('server.key')).export({ format: 'der', type: 'pkcs8' });
  await storeCert(app, new Uint8Array(pkcs8), [derOf(fx('server.crt')).toString('base64')], '2036-01-01T00:00:00Z');
  return createPublicKey(fx('server.crt')).export({ format: 'der', type: 'spki' }).toString('base64');
}

async function docWithPdf(admin) {
  const { regNo } = await admin.call('req.create', { mode: 'Сдружението', title: 'Тест', entity: { name: 'Община Тест', email: 'a@example.org' }, points: ['Точка 1'] });
  const d = await admin.call('doc.reserve', { regNo, kind: 'Заявление', payload: { points: ['Точка 1'] } });
  const pdf = await samplePdf();
  assert.equal((await admin.call('doc.file', { outNo: d.outNo, pdf: Buffer.from(pdf).toString('base64') })).ok, true);
  return { regNo, outNo: d.outNo, pdf };
}

for (const card of ['card-rsa', 'card-ec']) {
  test('КЕП (' + card + '): подпис през BISS, проверка, запис; повторно и подправено – отказ', async () => {
    const { env, admin } = await ready();
    const serverSpki = await withServerCert(env);
    const calls = fakeBiss(card, serverSpki);
    const { regNo, outNo, pdf } = await docWithPdf(admin);

    const { findBiss } = await import('../site/js/kep.js');
    const biss = await findBiss();
    assert.equal(biss.port, 53953);
    const signer = await chooseSigner(biss.port);
    assert.equal(signer.cert.name, 'Иван Тестов Иванов');
    assert.equal(signer.cert.qualified, true);

    const steps = [];
    const signed = await signPdf({
      port: biss.port, signer, pdfBytes: pdf, outNo, onStep: s => steps.push(s),
      authorize: async content => { const r = await admin.call('kep.authorize', { outNo, content }); if (!r.ok) throw new Error(r.message); return r; }
    });
    assert.deepEqual(calls, ['/version', '/getsigner', '/sign']);

    // независима проверка на CMS с openssl (ако е наличен)
    try {
      const dir = mkdtempSync(join(tmpdir(), 'kep-'));
      const latin = Buffer.from(signed).toString('latin1');
      const [, a, b, c, l] = /\/ByteRange \[(\d+) (\d+) (\d+) (\d+)\s*\]/.exec(latin).map(Number);
      writeFileSync(join(dir, 'content.bin'), Buffer.concat([Buffer.from(signed.subarray(a, b)), Buffer.from(signed.subarray(c, c + l))]));
      const hex = latin.slice(b + 1, c - 1).replace(/(00)+$/, '');
      writeFileSync(join(dir, 'sig.der'), Buffer.from(hex, 'hex'));
      const out = execFileSync('openssl', ['cms', '-verify', '-inform', 'DER', '-in', join(dir, 'sig.der'), '-content', join(dir, 'content.bin'), '-binary', '-noverify', '-out', join(dir, 'o.bin')], { stdio: ['ignore', 'pipe', 'pipe'] });
      assert.ok(out !== undefined);
    } catch (e) {
      if (!/ENOENT/.test(String(e.code || e.message))) throw new Error('openssl cms -verify: ' + String(e.stderr || e.message));
    }

    if (process.env.KEP_DUMP) writeFileSync(process.env.KEP_DUMP + '-' + card + '.pdf', signed);
    const v = await verifyPdf(signed);
    assert.equal(v.cert.name, 'Иван Тестов Иванов');

    const done = await admin.call('kep.complete', { outNo, pdf: Buffer.from(signed).toString('base64') });
    assert.equal(done.ok, true, JSON.stringify(done));
    assert.equal(done.signature.name, 'Иван Тестов Иванов');
    assert.equal(done.signature.id, 'PNOBG-80******00');
    assert.equal(done.signature.qualified, true);
    const g = await admin.call('req.get', { regNo });
    const doc = g.docs.find(x => x.outNo === outNo);
    assert.equal(doc.payload._sig.name, 'Иван Тестов Иванов');
    assert.ok(g.events.some(e => e.kind === 'Подпис с КЕП'));
    // подписаният се сваля и е същият
    const dl = await admin.call('doc.download', { outNo });
    assert.equal(dl.data, Buffer.from(signed).toString('base64'));
    // повторно подписване и редакция – отказ
    assert.equal((await admin.call('kep.authorize', { outNo, content: 'MQ==' })).error, 'value');
    assert.equal((await admin.call('doc.reserve', { regNo, kind: 'Заявление', outNo, payload: {} })).error, 'value');

    // подправен файл
    const bad = Uint8Array.from(signed);
    bad[200] = bad[200] ^ 1;
    await assert.rejects(() => verifyPdf(bad), /не съвпада|невалиден/);
  });
}

test('КЕП: заявка без разрешение от сървъра се отказва от BISS; PDF без подпис – отказ', async () => {
  const { env, admin } = await ready();
  const serverSpki = await withServerCert(env);
  fakeBiss('card-rsa', serverSpki);
  const { outNo, pdf } = await docWithPdf(admin);
  const signer = await chooseSigner(53953);
  await assert.rejects(() => signPdf({ port: 53953, signer, pdfBytes: pdf, outNo, authorize: async () => ({ signedContents: Buffer.alloc(256).toString('base64'), signedContentsCert: 'x' }) }), /BISS: Подписът на заявката е невалиден/);
  const r = await admin.call('kep.complete', { outNo, pdf: Buffer.from(pdf).toString('base64') });
  assert.equal(r.error, 'value');
});
