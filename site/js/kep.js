/*
 * Подписване на PDF с КЕП на смарт карта чрез B-Trust BISS (локална услуга на компютъра; работи и с карти на други
 * доставчици, ако веригите им са инсталирани). Резултатът е PAdES подпис (ETSI.CAdES.detached), ниво B-B.
 *
 *   1. BISS: избор на сертификат от картата (/getsigner);
 *   2. PDF с печат „Подписано с КЕП…“ и поле за подпис (pdf-lib);
 *   3. хеш на файла → подписани атрибути (CMS) → сървърът разрешава заявката (BISS изисква signedContents);
 *   4. BISS подписва атрибутите с картата (ПИН) → CMS SignedData се вгражда в PDF-а.
 */

import * as D from './der.js';

const PORTS = [53952, 53953, 53954, 53955];
const SIG_SIZE = 16384; // байтове за CMS в /Contents
const sha256 = async u8 => new Uint8Array(await crypto.subtle.digest('SHA-256', u8));

function script(src) {
  return new Promise((ok, bad) => {
    const s = document.createElement('script');
    s.src = src; s.onload = ok; s.onerror = () => bad(new Error('Неуспешно зареждане на ' + src));
    document.head.append(s);
  });
}
let pdfLib = null;
const loadPdfLib = () => (pdfLib = pdfLib || (window.PDFLib ? Promise.resolve() : script('vendor/pdf-lib.min.js')));

/* ---------- BISS ---------- */

async function call(port, path, body, ms) {
  const ac = new AbortController(), t = setTimeout(() => ac.abort(), ms);
  try {
    const r = await fetch('https://localhost:' + port + path, body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: ac.signal } : { signal: ac.signal });
    return await r.json();
  } finally { clearTimeout(t); }
}

/*
 * Всички портове наведнъж: затворените отказват веднага, а отговорът от BISS може да закъснее, докато
 * браузърът (Firefox) пита за достъп до локалната мрежа – затова изчакването е дълго, а не по 1,5 с на порт.
 */
export async function findBiss() {
  const probe = p => call(p, '/version', null, 60000).then(v => {
    if (v && v.version) return { port: p, version: v.version };
    throw new Error('не е BISS');
  });
  try { return await Promise.any(PORTS.map(probe)); } catch (_) { return null; }
}

const bissError = r => {
  const code = String(r && r.reasonCode || '');
  const text = (r && r.reasonText) || 'неизвестна грешка';
  if (code === '401') return 'Подписването е отказано: не е избран сертификат, грешен или блокиран ПИН (' + text + ').';
  if (code === '441') return 'BISS не намира удостоверителната верига на доставчика на КЕП. Инсталирайте веригите на вашия доставчик и на B-Trust.';
  if (code === '403') return 'BISS отказа: в момента се обработва друга заявка (' + text + ').';
  return 'BISS: ' + text + (code ? ' (' + code + ')' : '');
};

/* сертификатът от картата: { chain: [DER], cert (разчетен) } */
export async function chooseSigner(port) {
  const r = await call(port, '/getsigner', { selector: {}, showValidCerts: true }, 15 * 60000);
  if (!r || r.status !== 'ok' || !r.chain || !r.chain.length) throw new Error(bissError(r));
  const chain = r.chain.map(D.unb64);
  const cert = D.parseCert(chain[0]);
  if (cert.notAfter && cert.notAfter < new Date()) throw new Error('Удостоверението на ' + cert.name + ' е изтекло на ' + cert.notAfter.toLocaleDateString('bg-BG') + '.');
  return { chain, cert, b64: r.chain[0] };
}

/* ---------- PDF ---------- */

async function preparePdf(bytes, info) {
  await loadPdfLib();
  const { PDFDocument, PDFName, PDFNumber, PDFHexString, PDFString, PDFArray } = window.PDFLib;
  const doc = await PDFDocument.load(bytes);
  const pages = doc.getPages(), page = pages[pages.length - 1];
  const ctx = doc.context;
  const byteRange = PDFArray.withContext(ctx);
  byteRange.push(PDFNumber.of(0));
  ['**********', '**********', '**********'].forEach(x => byteRange.push(PDFName.of(x)));
  const sig = ctx.obj({
    Type: 'Sig', Filter: 'Adobe.PPKLite', SubFilter: 'ETSI.CAdES.detached', ByteRange: byteRange,
    Contents: PDFHexString.of('0'.repeat(SIG_SIZE * 2)), M: PDFString.fromDate(new Date()),
    Name: PDFString.of(ascii(info.name)), Reason: PDFString.of(ascii(info.reason || 'Signed')), Location: PDFString.of(ascii(info.location || 'Bulgaria'))
  });
  const sigRef = ctx.register(sig);
  const widget = ctx.obj({ Type: 'Annot', Subtype: 'Widget', FT: 'Sig', Rect: [0, 0, 0, 0], V: sigRef, T: PDFString.of('KEP ' + Date.now()), F: 132, P: page.ref });
  const widgetRef = ctx.register(widget);
  const annots = page.node.lookup(PDFName.of('Annots'));
  if (annots) annots.push(widgetRef); else page.node.set(PDFName.of('Annots'), ctx.obj([widgetRef]));
  doc.catalog.set(PDFName.of('AcroForm'), ctx.obj({ Fields: [widgetRef], SigFlags: 3 }));
  const out = await doc.save({ useObjectStreams: false });

  // точните граници: всичко без /Contents <…>
  const latin = new TextDecoder('latin1').decode(out);
  const ph = '<' + '0'.repeat(SIG_SIZE * 2) + '>';
  const start = latin.lastIndexOf(ph);
  if (start < 0) throw new Error('Полето за подпис не е намерено.');
  const end = start + ph.length;
  const brText = '/ByteRange [ 0 /********** /********** /********** ]';
  let brAt = latin.lastIndexOf(brText);
  const brAlt = '/ByteRange [0 /********** /********** /**********]';
  let brLen = brText.length;
  if (brAt < 0) { brAt = latin.lastIndexOf(brAlt); brLen = brAlt.length; }
  if (brAt < 0) throw new Error('ByteRange не е намерен.');
  const range = [0, start, end, out.length - end];
  const brNew = ('/ByteRange [' + range.join(' ') + ']').padEnd(brLen, ' ');
  if (brNew.length > brLen) throw new Error('ByteRange е твърде дълъг.');
  out.set(new TextEncoder().encode(brNew), brAt);
  return { bytes: out, range, start, end };
}

/* PDF низовете (без шрифт) – само латиница; кирилицата е в печата на страницата */
const TR = { а: 'a', б: 'b', в: 'v', г: 'g', д: 'd', е: 'e', ж: 'zh', з: 'z', и: 'i', й: 'y', к: 'k', л: 'l', м: 'm', н: 'n', о: 'o', п: 'p', р: 'r', с: 's', т: 't', у: 'u', ф: 'f', х: 'h', ц: 'ts', ч: 'ch', ш: 'sh', щ: 'sht', ъ: 'a', ь: 'y', ю: 'yu', я: 'ya' };
const ascii = s => String(s || '').split('').map(ch => { const l = ch.toLowerCase(), t = TR[l]; return t === undefined ? ch : ch === l ? t : t.charAt(0).toUpperCase() + t.slice(1); }).join('').replace(/[^\x20-\x7e]/g, '');

/* ---------- целият процес ---------- */

/*
 * opts: { port, signer, pdfBytes (вече с печата), outNo, authorize(contentB64) → { signedContents, signedContentsCert }, onStep(text) }
 * връща подписания PDF (Uint8Array)
 */
export async function signPdf(opts) {
  const step = opts.onStep || (() => {});
  const { signer } = opts;
  step('Подготовка на PDF…');
  const prep = await preparePdf(opts.pdfBytes, { name: signer.cert.name, reason: 'Izh. No ' + opts.outNo });
  const signedPart = D.concat([prep.bytes.subarray(0, prep.start), prep.bytes.subarray(prep.end)]);
  const attrs = D.signedAttrs(await sha256(signedPart), signer.cert, await sha256(signer.chain[0]));
  const toSign = D.attrsToSign(attrs), toSignB64 = D.b64(toSign);
  step('Разрешение от сървъра…');
  const auth = await opts.authorize(toSignB64);
  step('Въведете ПИН кода в прозореца на BISS…');
  const r = await call(opts.port, '/sign', {
    version: '1.0', contents: [toSignB64], contentType: 'data', hashAlgorithm: 'SHA256', signatureType: 'signature',
    signedContents: [auth.signedContents], signedContentsCert: [auth.signedContentsCert], signerCertificateB64: signer.b64,
    confirmText: ['Подписване на ' + opts.outNo]
  }, 15 * 60000);
  if (!r || r.status !== 'ok' || !r.signatures || !r.signatures[0]) throw new Error(bissError(r));
  let sig = D.unb64(r.signatures[0]);
  if (signer.cert.keyAlg === D.OID.ec && sig[0] !== 0x30) sig = D.ecdsaDer(sig);
  step('Сглобяване на подписа…');
  const cms = D.signedData(attrs, sig, signer.chain, signer.cert);
  if (cms.length > SIG_SIZE) throw new Error('Подписът е по-голям от запазеното място.');
  const hexSig = D.hex(cms).padEnd(SIG_SIZE * 2, '0');
  prep.bytes.set(new TextEncoder().encode(hexSig), prep.start + 1);
  return prep.bytes;
}

/* ---------- вход и свързване с КЕП ----------
 * challenge: { id, content, signedContents, signedContentsCert } от сървъра; картата подписва текста (ПИН в BISS)
 */
export async function signChallenge(port, signer, ch) {
  const r = await call(port, '/sign', {
    version: '1.0', contents: [ch.content], contentType: 'data', hashAlgorithm: 'SHA256', signatureType: 'signature',
    signedContents: [ch.signedContents], signedContentsCert: [ch.signedContentsCert], signerCertificateB64: signer.b64,
    confirmText: ['Вход в ADM ЗДОИ4You']
  }, 15 * 60000);
  if (!r || r.status !== 'ok' || !r.signatures || !r.signatures[0]) throw new Error(bissError(r));
  return { id: ch.id, signature: r.signatures[0], chain: signer.chain.map(D.b64) };
}
