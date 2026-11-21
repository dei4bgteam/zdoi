/*
 * Подготвя сайта за публикуване с Worker-а: копие на site/ в worker/public/ с версия в адресите на js и css
 * (?v=<commit>), за да не се зареждат стари файлове от кеша на браузъра или Cloudflare.
 *
 *   node tools/build-site.mjs
 */

import { cpSync, rmSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SRC = join(ROOT, 'site'), OUT = join(ROOT, 'worker', 'public');

let v;
try { v = execSync('git rev-parse --short=8 HEAD', { cwd: ROOT }).toString().trim(); } catch (_) { v = 'local'; }
try { if (execSync('git status --porcelain site', { cwd: ROOT }).toString().trim()) v += '-' + Date.now().toString(36); } catch (_) { /* без git */ }

rmSync(OUT, { recursive: true, force: true });
cpSync(SRC, OUT, { recursive: true, filter: p => !/[\\/](CNAME)$/.test(p) });

for (const f of readdirSync(OUT).filter(x => x.endsWith('.html'))) {
  const p = join(OUT, f);
  writeFileSync(p, readFileSync(p, 'utf8').replace(/\?v=dev/g, '?v=' + v));
}
const js = join(OUT, 'js');
for (const f of readdirSync(js).filter(x => x.endsWith('.js'))) {
  const p = join(js, f);
  writeFileSync(p, readFileSync(p, 'utf8').replace(/(from '\.\/[a-z0-9-]+\.js)'/g, "$1?v=" + v + "'"));
}
console.log('Сайтът е подготвен в worker/public (версия ' + v + ').');
