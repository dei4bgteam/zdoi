/* ADM ЗДОИ4You – интерфейс. Всички данни се вмъкват с textContent, без innerHTML. */

import { term, termMonths, daysBetween } from './calendar.js';

const API = '/api';
const SESSION_MIN = 30;
const PERM_LABELS = {
  casesAll: 'Вижда всички преписки', casesEdit: 'Въвежда и променя преписки', courts: 'Води съдебни дела',
  addressees: 'Променя адресати', departments: 'Управлява отдели', log: 'Вижда дневника'
};
const ROLE_HINT = {
  'Администратор': 'всички права и управление на потребителите',
  'Служител': 'преписки, дела и адресати',
  'Наблюдател': 'само преглед'
};

/* ---------- помощни ---------- */

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  Object.entries(attrs || {}).forEach(([k, v]) => {
    if (v === null || v === undefined || v === false) return;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked') el.checked = !!v;
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, v);
  });
  kids.flat(Infinity).forEach(c => { if (c !== null && c !== undefined && c !== false) el.append(c.nodeType ? c : String(c)); });
  return el;
}
const $ = id => document.getElementById(id);
const setView = (...nodes) => { const v = $('view') || $('app'); v.replaceChildren(...nodes.flat(Infinity).filter(n => n !== null && n !== undefined && n !== false)); window.scrollTo(0, 0); };
let toastTimer;
function toast(msg) {
  const t = $('toast');
  t.textContent = msg; t.classList.add('on');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('on'), 3500);
}
const fmtDate = iso => { const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso || ''); return m ? `${m[3]}.${m[2]}.${m[1]}` : '—'; };
const fmtTime = iso => { const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}:\d{2})/.exec(iso || ''); return m ? `${m[3]}.${m[2]}.${m[1]} ${m[4]}` : (iso || '—'); };
const todayIso = () => new Date().toLocaleDateString('en-CA', { timeZone: 'Europe/Sofia' });
const pair = o => (Array.isArray(o) ? o : [o, o || '—']);
const userName = u => { const x = (boot && boot.users || []).find(y => y.username === u); return x ? x.name : (u || '—'); };

function dueText(days) {
  if (days === null || days === undefined) return '';
  if (days < 0) return 'изтекъл преди ' + -days + (days === -1 ? ' ден' : ' дни');
  if (days === 0) return 'изтича днес';
  return 'остават ' + days + (days === 1 ? ' ден' : ' дни');
}
const dueClass = days => (days === null || days === undefined ? '' : days < 0 ? 'due-bad' : days <= 3 ? 'due-warn' : 'due-ok');
function statusPill(s) {
  const cls = { 'Нова': 'info', 'В обработка': 'info', 'Чака уточняване': 'warn', 'Чака трето лице': 'warn', 'Решение издадено': 'ok', 'Приключена': '' }[s] || '';
  return h('span', { class: 'pill ' + cls }, s || '—');
}

/* ---------- сървър ---------- */

let me = null, boot = null, expAt = 0, timerId = null;

async function api(action, data) {
  let res;
  try {
    const r = await fetch(API, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action, data: data || {} }) });
    res = await r.json();
  } catch (e) { throw new Error('Няма връзка със сървъра. Проверете интернет връзката и опитайте отново.'); }
  if (res.ok) {
    if (me) expAt = Date.now() + SESSION_MIN * 6e4;
    return res;
  }
  if (res.error === 'session' && me) { endSession(res.message); }
  throw Object.assign(new Error(res.message || 'Възникна грешка.'), { code: res.error });
}

/* PBKDF2 в браузъра: паролата не напуска устройството */
async function preHash(username, password) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', iterations: 600000, salt: enc.encode(`zdoi-adm:v1:${username}`) }, key, 256);
  return btoa(String.fromCharCode(...new Uint8Array(bits)));
}

function strongEnough(pw) {
  if (pw.length < 12) return 'Паролата трябва да е поне 12 знака.';
  if (!/[A-Za-zА-Яа-я]/.test(pw) || !/\d/.test(pw)) return 'Паролата трябва да съдържа букви и цифри.';
  return '';
}

function endSession(msg) {
  me = null; boot = null; clearInterval(timerId);
  location.hash = '#/login';
  route();
  if (msg) toast(msg);
}

async function startSession(m) {
  me = m;
  expAt = Date.now() + SESSION_MIN * 6e4;
  boot = await api('bootstrap');
  clearInterval(timerId);
  timerId = setInterval(tick, 1000);
}

function tick() {
  const el = $('timer');
  const left = Math.max(0, Math.round((expAt - Date.now()) / 1000));
  if (el) {
    el.textContent = Math.floor(left / 60) + ':' + String(left % 60).padStart(2, '0');
    el.classList.toggle('warn', left < 120);
  }
  if (left === 0 && me) endSession('Сесията изтече поради бездействие.');
}

/* ---------- форми ---------- */

/* def: { k, label, type, options, req, full, hint, max, min, placeholder } */
function field(def, value) {
  let input;
  const v = value === undefined || value === null ? '' : value;
  if (def.type === 'select') {
    input = h('select', { name: def.k, required: !!def.req, disabled: !!def.disabled }, (def.options || []).map(o => { const [val, text] = pair(o); return h('option', { value: val }, text); }));
    input.value = v;
    if (input.selectedIndex < 0 && input.options.length) input.selectedIndex = 0;
  } else if (def.type === 'textarea') {
    input = h('textarea', { name: def.k, required: !!def.req, maxlength: def.max || 8000, rows: def.rows || 4, disabled: !!def.disabled });
    input.value = v;
  } else if (def.type === 'checkbox') {
    return h('label', { class: 'check' + (def.full ? ' full' : '') }, h('input', { type: 'checkbox', name: def.k, checked: v === true || v === 'Да', disabled: !!def.disabled }), h('span', null, def.label));
  } else {
    input = h('input', {
      name: def.k, type: def.type || 'text', required: !!def.req, maxlength: def.max || null, min: def.min, max: def.maxValue,
      placeholder: def.placeholder || null, autocomplete: def.autocomplete || 'off', pattern: def.pattern || null, list: def.list || null, disabled: !!def.disabled
    });
    input.value = v;
  }
  return h('label', { class: 'field' + (def.full ? ' full' : '') },
    h('span', null, def.label, def.req ? h('span', { class: 'req', 'aria-hidden': 'true' }, ' *') : null), input, def.hint ? h('small', null, def.hint) : null);
}

function formValues(form) {
  const out = {};
  [...form.elements].forEach(el => {
    if (!el.name || el.disabled) return;
    out[el.name] = el.type === 'checkbox' ? el.checked : el.value.trim();
  });
  return out;
}

/* изпраща формата и показва грешката в нея */
function onSubmit(form, fn) {
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const btn = form.querySelector('button[type=submit]'), err = form.querySelector('.err');
    if (err) err.remove();
    if (btn) btn.disabled = true;
    try { await fn(formValues(form)); }
    catch (ex) { form.append(h('p', { class: 'err', role: 'alert' }, ex.message)); }
    finally { if (btn) btn.disabled = false; }
  });
}

function dialog(title, body, { wide } = {}) {
  const d = h('dialog', { class: wide ? 'wide' : '' }, h('h2', null, title), body);
  d.addEventListener('close', () => d.remove());
  document.body.append(d);
  d.showModal();
  return d;
}

function formDialog(title, fields, values, submitText, fn, opts = {}) {
  const form = h('form', null,
    h('div', { class: 'form-grid' }, fields.map(f => field(f, values[f.k]))),
    opts.extra || null,
    h('div', { class: 'actions' }, h('button', { type: 'button', class: 'btn', onclick: () => d.close() }, 'Отказ'), h('button', { type: 'submit', class: 'btn primary' }, submitText)));
  const d = dialog(title, form, opts);
  onSubmit(form, async v => { await fn(v, form); d.close(); });
  return d;
}

const table = (head, rows, empty) => rows.length
  ? h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null, head.map(x => h('th', null, x)))), h('tbody', null, rows)))
  : h('p', { class: 'empty' }, empty || 'Няма записи.');

const kv = pairs => h('dl', { class: 'kv' }, pairs.filter(Boolean).map(([k, v]) => [h('dt', null, k), h('dd', null, v === '' || v === null || v === undefined ? '—' : v)]));

/* ---------- оформление ---------- */

const NAV = () => [
  ['#/dashboard', 'Табло', true],
  ['#/cases', 'Преписки', true],
  ['#/courts', 'Дела', true],
  ['#/addressees', 'Адресати', true],
  ['#/calc', 'Срокове', true],
  ['#/departments', 'Отдели', true],
  ['#/users', 'Потребители', me.role === 'Администратор'],
  ['#/log', 'Дневник', !!me.perms.log],
  ['#/profile', 'Моят профил', true]
];

function themeSelect() {
  const cur = document.documentElement.getAttribute('data-theme');
  const s = h('select', { class: 'theme', 'aria-label': 'Тема', onchange: e => {
    document.documentElement.setAttribute('data-theme', e.target.value);
    try { localStorage.setItem('theme', e.target.value); } catch (_) { /* без памет */ }
  } }, [['light', 'Светла'], ['dark', 'Тъмна'], ['blue', 'Синя']].map(([v, t]) => h('option', { value: v }, t)));
  s.value = cur;
  return s;
}

function shell() {
  if ($('view')) { markNav(); return; }
  const header = h('header', { class: 'top' }, h('div', { class: 'bar' },
    h('a', { class: 'brand', href: '#/dashboard' }, h('span', { class: 'logo-plate mini' }, h('img', { src: 'assets/logo-site.png', alt: 'ЗДОИ4You' }))),
    h('strong', null, 'ADM'),
    h('div', { class: 'user' },
      h('div', { class: 'who' }, h('div', null, me.name), h('div', { class: 'muted' }, me.role)),
      h('span', { class: 'timer muted', id: 'timer', title: 'Оставащо време на сесията' }, ''),
      themeSelect(),
      h('button', { class: 'btn sm', onclick: async () => { try { await api('logout'); } catch (_) { /* изтекла */ } endSession('Излязохте от системата.'); } }, 'Изход')),
    h('nav', { class: 'tabs', id: 'nav' }, NAV().filter(x => x[2]).map(([href, t]) => h('a', { href }, t)))));
  $('app').replaceChildren(header, h('main', { id: 'view' }), h('footer', { class: 'app-foot small muted' }, 'ADM ЗДОИ4You – вътрешна система. Данните се пазят в SharePoint.'));
  markNav();
  tick();
}

function markNav() {
  const cur = location.hash.split('/').slice(0, 2).join('/');
  document.querySelectorAll('#nav a').forEach(a => {
    const on = a.getAttribute('href') === cur || (cur === '#/case' && a.getAttribute('href') === '#/cases');
    a.classList.toggle('on', on);
  });
}

const head = (title, ...actions) => h('div', { class: 'head' }, h('h1', null, title), h('div', { class: 'actions' }, actions));
const loading = () => setView(h('p', { class: 'loading' }, 'Зареждане…'));
const failView = e => setView(h('p', { class: 'err' }, e.message));

/* ---------- публични страници ---------- */

function gate(title, sub, ...body) {
  $('app').replaceChildren(h('div', { class: 'gate' },
    h('span', { class: 'logo-plate' }, h('img', { src: 'assets/logo-site.png', alt: 'ЗДОИ4You' })),
    h('div', { class: 'card gate-card' }, h('h1', null, title), sub ? h('p', { class: 'muted' }, sub) : null, body),
    h('p', { class: 'gate-foot' }, 'ADM ЗДОИ4You – вътрешна система. Достъпът е само за упълномощени служители.')));
}

function loginView() {
  const form = h('form', { autocomplete: 'on' },
    h('div', { class: 'stack' },
      field({ k: 'username', label: 'Потребител', req: true, autocomplete: 'username', max: 40 }),
      field({ k: 'password', label: 'Парола', type: 'password', req: true, autocomplete: 'current-password', max: 200 })),
    h('button', { type: 'submit', class: 'btn primary block' }, 'Вход'),
    h('div', { class: 'gate-links' }, h('a', { href: '#/forgot' }, 'Забравена парола'), h('a', { href: '#/calc' }, 'Калкулатор на срокове')));
  gate('Вход', 'Влезте с потребителското име и паролата си.', form);
  form.username.focus();
  onSubmit(form, async v => {
    const username = v.username.toLowerCase();
    const r = await api('login', { username, hash: await preHash(username, form.password.value) });
    if (r.twofa) return codeView(r.ticket);
    await startSession(r.me);
    location.hash = '#/dashboard';
    route();
  });
}

function codeView(ticket) {
  const form = h('form', null,
    field({ k: 'code', label: 'Код от 8 цифри', req: true, pattern: '\\d{8}', max: 8, autocomplete: 'one-time-code' }),
    h('button', { type: 'submit', class: 'btn primary block' }, 'Потвърди'),
    h('div', { class: 'gate-links' }, h('a', { href: '#/login', onclick: () => setTimeout(route) }, 'Назад')));
  gate('Код за вход', 'Изпратихме код на имейла ви. Той важи 5 минути.', form);
  form.code.focus();
  onSubmit(form, async v => {
    const r = await api('login.code', { ticket, code: v.code });
    await startSession(r.me);
    location.hash = '#/dashboard';
    route();
  });
}

function forgotView() {
  const form = h('form', null, field({ k: 'username', label: 'Потребител', req: true, autocomplete: 'username' }),
    h('button', { type: 'submit', class: 'btn primary block' }, 'Изпрати връзка'),
    h('div', { class: 'gate-links' }, h('a', { href: '#/login' }, 'Към входа')));
  gate('Забравена парола', 'Ще изпратим еднократна връзка на имейла, записан за потребителя.', form);
  onSubmit(form, async v => {
    await api('forgot', { username: v.username.toLowerCase() });
    gate('Проверете пощата', null, h('p', null, 'Ако потребителят съществува и има имейл, ще получите връзка за нова парола. Тя важи 2 часа.'), h('div', { class: 'gate-links' }, h('a', { href: '#/login' }, 'Към входа')));
  });
}

async function activateView(username, token) {
  gate('Нова парола', null, h('p', { class: 'loading' }, 'Проверка на връзката…'));
  let valid = false;
  try { valid = (await api('link.check', { username, token })).valid; } catch (_) { valid = false; }
  if (!valid) return gate('Връзката е невалидна', 'Връзката е използвана, изтекла или грешна. Поискайте нова от администратора или от „Забравена парола“.', h('div', { class: 'gate-links' }, h('a', { href: '#/login' }, 'Към входа'), h('a', { href: '#/forgot' }, 'Забравена парола')));
  const form = h('form', null,
    h('div', { class: 'stack' },
      field({ k: 'u', label: 'Потребител', value: username, disabled: true }, username),
      field({ k: 'password', label: 'Нова парола', type: 'password', req: true, autocomplete: 'new-password', hint: 'Поне 12 знака, с букви и цифри.' }),
      field({ k: 'again', label: 'Повторете паролата', type: 'password', req: true, autocomplete: 'new-password' })),
    h('button', { type: 'submit', class: 'btn primary block' }, 'Запази паролата'));
  gate('Нова парола', 'Изберете парола. Тя не се изпраща към сървъра – там се пази само производна стойност.', form);
  onSubmit(form, async v => {
    const weak = strongEnough(v.password);
    if (weak) throw new Error(weak);
    if (v.password !== v.again) throw new Error('Паролите не съвпадат.');
    await api('activate', { username, token, hash: await preHash(username, v.password) });
    toast('Паролата е зададена. Влезте.');
    location.hash = '#/login';
  });
}

/* ---------- табло ---------- */

async function dashboardView() {
  loading();
  try {
    const d = await api('dashboard');
    const tile = (n, label, href, cls) => h('a', { class: 'card tile ' + (cls || ''), href }, h('b', null, n), h('span', { class: 'muted' }, label));
    const caseRows = (list, empty, withDue = true) => list.length ? h('ul', { class: 'list-plain' }, list.map(c => h('li', null,
      h('a', { href: '#/case/' + encodeURIComponent(c.regNo) }, c.regNo + ' – ' + c.applicantName),
      withDue ? h('span', { class: dueClass(c.daysLeft) }, c.due ? fmtDate(c.due) + ' · ' + dueText(c.daysLeft) : '—')
        : h('span', { class: dueClass(c.appealDays) }, fmtDate(c.appealBy) + ' · ' + dueText(c.appealDays))))) : h('p', { class: 'empty' }, empty);
    setView(
      head('Табло', me.perms.casesEdit ? h('a', { class: 'btn primary', href: '#/case/new' }, 'Нова преписка') : null),
      h('div', { class: 'tiles' },
        tile(d.open, 'Отворени преписки', '#/cases'),
        tile(d.overdue.length, 'С изтекъл срок', '#/cases?f=overdue', d.overdue.length ? 'bad' : ''),
        tile(d.soon.length, 'Изтичат до 3 дни', '#/cases?f=soon', d.soon.length ? 'warn' : ''),
        tile(d.mine.length, 'Възложени на мен', '#/cases?f=mine'),
        tile(d.unassigned.length, 'Без отговорник', '#/cases?f=none'),
        tile(d.total, 'Всички преписки', '#/cases')),
      h('div', { class: 'grid2' },
        h('section', { class: 'card stack' }, h('h2', null, 'Изтекли срокове'), caseRows(d.overdue, 'Няма преписки с изтекъл срок.')),
        h('section', { class: 'card stack' }, h('h2', null, 'Изтичат скоро'), caseRows(d.soon, 'Няма срокове в следващите 3 дни.')),
        h('section', { class: 'card stack' }, h('h2', null, 'Моите преписки'), caseRows(d.mine, 'Нямате възложени преписки.')),
        h('section', { class: 'card stack' }, h('h2', null, 'Срок за обжалване (до 7 дни)'), caseRows(d.appeals, 'Няма решения с изтичащ срок за обжалване.', false)),
        h('section', { class: 'card stack' }, h('h2', null, 'Заседания (30 дни)'), d.hearings.length ? h('ul', { class: 'list-plain' }, d.hearings.map(x => h('li', null,
          h('a', { href: x.regNo ? '#/case/' + encodeURIComponent(x.regNo) : '#/courts' }, x.court.replace('Административен съд – ', 'АС ') + ' № ' + x.caseNo + '/' + x.year),
          h('span', null, fmtDate(x.nextHearing))))) : h('p', { class: 'empty' }, 'Няма насрочени заседания.')),
        h('section', { class: 'card stack' }, h('h2', null, 'По статус'), h('ul', { class: 'list-plain' }, Object.entries(d.byStatus).map(([s, n]) => h('li', null, statusPill(s), h('b', null, n)))))));
  } catch (e) { failView(e); }
}

/* ---------- преписки ---------- */

async function casesView(query) {
  loading();
  try {
    const { cases } = await api('case.list');
    const preset = new URLSearchParams(query || '').get('f') || '';
    const q = h('input', { type: 'search', placeholder: 'Търсене: номер, заявител, описание…', 'aria-label': 'Търсене' });
    const st = h('select', { 'aria-label': 'Статус' }, h('option', { value: '' }, 'Всички статуси'), h('option', { value: 'open' }, 'Отворени'), boot.lists.statuses.map(s => h('option', { value: s }, s)));
    const own = h('select', { 'aria-label': 'Отговорник' }, h('option', { value: '' }, 'Всички отговорници'), h('option', { value: 'mine' }, 'Моите'), h('option', { value: 'none' }, 'Без отговорник'), boot.users.map(u => h('option', { value: 'u:' + u.username }, u.name)));
    const due = h('select', { 'aria-label': 'Срок' }, h('option', { value: '' }, 'Всички срокове'), h('option', { value: 'overdue' }, 'Изтекъл срок'), h('option', { value: 'soon' }, 'До 3 дни'));
    if (preset === 'mine' || preset === 'none') own.value = preset;
    if (preset === 'overdue' || preset === 'soon') due.value = preset;
    const body = h('div');
    const draw = () => {
      const text = q.value.trim().toLowerCase();
      const rows = cases.filter(c => {
        if (text && ![c.regNo, c.applicantName, c.subject, c.decisionNo].join(' ').toLowerCase().includes(text)) return false;
        if (st.value === 'open' && c.due === '' && !['Нова', 'В обработка', 'Чака уточняване', 'Чака трето лице'].includes(c.status)) return false;
        if (st.value && st.value !== 'open' && c.status !== st.value) return false;
        if (own.value === 'mine' && c.owner !== me.username) return false;
        if (own.value === 'none' && c.owner) return false;
        if (own.value.startsWith('u:') && c.owner !== own.value.slice(2)) return false;
        if (due.value === 'overdue' && !(c.daysLeft !== null && c.daysLeft < 0)) return false;
        if (due.value === 'soon' && !(c.daysLeft !== null && c.daysLeft >= 0 && c.daysLeft <= 3)) return false;
        return true;
      });
      body.replaceChildren(h('p', { class: 'small muted' }, 'Показани: ' + rows.length + ' от ' + cases.length),
        table(['Рег. №', 'Регистрирана', 'Заявител', 'Описание', 'Статус', 'Отговорник', 'Срок'], rows.map(c => h('tr', { class: 'link', onclick: () => { location.hash = '#/case/' + encodeURIComponent(c.regNo); } },
          h('td', { class: 'mono' }, c.regNo, c.locked === 'Да' ? ' 🔒' : ''), h('td', null, fmtDate(c.regDate)), h('td', null, c.applicantName),
          h('td', { class: 'subject' }, c.subject), h('td', null, statusPill(c.status)), h('td', null, c.owner ? userName(c.owner) : h('span', { class: 'muted' }, '—')),
          h('td', null, c.due ? h('span', { class: dueClass(c.daysLeft) }, fmtDate(c.due), h('br'), h('span', { class: 'small' }, dueText(c.daysLeft))) : (c.appealBy ? h('span', { class: 'small muted' }, 'обжалване до ' + fmtDate(c.appealBy)) : '—')))),
        'Няма преписки по тези условия.'));
    };
    [q, st, own, due].forEach(x => x.addEventListener('input', draw));
    setView(head('Преписки', me.perms.casesEdit ? h('a', { class: 'btn primary', href: '#/case/new' }, 'Нова преписка') : null),
      h('div', { class: 'card' }, h('div', { class: 'filters' }, q, st, own, due), body));
    draw();
  } catch (e) { failView(e); }
}

const APPLICANT_FIELDS = () => [
  { k: 'kind', label: 'Вид заявление', type: 'select', options: boot.lists.kinds, req: true },
  { k: 'regDate', label: 'Дата на регистриране', type: 'date', req: true },
  { k: 'channel', label: 'Начин на подаване', type: 'select', options: boot.lists.channels, req: true },
  { k: 'applicantType', label: 'Вид заявител', type: 'select', options: boot.lists.applicantTypes, req: true },
  { k: 'applicantName', label: 'Заявител (име или наименование)', req: true, max: 200 },
  { k: 'applicantEik', label: 'ЕИК/БУЛСТАТ', max: 13, pattern: '\\d{9}|\\d{13}', hint: 'Само за юридически лица.' },
  { k: 'applicantSeat', label: 'Седалище', max: 120 },
  { k: 'applicantOblast', label: 'Област', max: 80 },
  { k: 'applicantAddress', label: 'Адрес за кореспонденция', max: 400, full: true },
  { k: 'applicantEmail', label: 'Имейл', type: 'email', max: 200 },
  { k: 'applicantPhone', label: 'Телефон', type: 'tel', max: 40 },
  { k: 'subject', label: 'Описание на исканата информация', type: 'textarea', req: true, full: true },
  { k: 'form', label: 'Предпочитана форма на достъп', max: 250 },
  { k: 'department', label: 'Отдел', type: 'select', options: [['', '—']].concat(boot.departments) },
  { k: 'noPublish', label: 'Заявителят не е съгласен информацията да се публикува (чл. 25, ал. 1, т. 5)', type: 'checkbox', full: true }
];

async function newCaseView() {
  if (!me.perms.casesEdit) return setView(h('p', { class: 'err' }, 'Нямате право да въвеждате преписки.'));
  let addressees = [];
  try { addressees = (await api('addressee.list')).addressees; } catch (_) { addressees = []; }
  const fields = [{ k: 'regNo', label: 'Рег. № (по желание)', max: 60, hint: 'Празно – номерът се дава автоматично (ЗДОИ-ГГГГ-0001).' }]
    .concat(APPLICANT_FIELDS(), [
      { k: 'owner', label: 'Отговорник', type: 'select', options: [['', '— без отговорник —']].concat(boot.users.filter(u => u.role !== 'Наблюдател').map(u => [u.username, u.name])) },
      { k: 'saveAddressee', label: 'Запази заявителя в „Адресати“', type: 'checkbox' }
    ]);
  const form = h('form', null, h('div', { class: 'form-grid' }, fields.map(f => field(f, f.k === 'regDate' ? todayIso() : f.k === 'owner' ? me.username : ''))),
    h('div', { class: 'actions mt-16' }, h('a', { class: 'btn', href: '#/cases' }, 'Отказ'), h('button', { type: 'submit', class: 'btn primary' }, 'Въведи преписката')));
  const pick = addressees.length ? h('label', { class: 'field' }, h('span', null, 'Попълни от адресат'),
    h('select', { onchange: e => {
      const a = addressees.find(x => x._id === e.target.value);
      if (!a) return;
      const set = (k, v) => { if (form.elements[k] && v) form.elements[k].value = v; };
      if (boot.lists.applicantTypes.includes(a.type)) set('applicantType', a.type);
      set('applicantName', a.name); set('applicantEik', a.eik); set('applicantSeat', a.seat); set('applicantOblast', a.oblast);
      set('applicantAddress', a.address); set('applicantEmail', a.email); set('applicantPhone', a.phone);
    } }, h('option', { value: '' }, '— изберете —'), addressees.map(a => h('option', { value: a._id }, a.name + (a.email ? ' · ' + a.email : ''))))) : null;
  setView(head('Нова преписка'), h('div', { class: 'card' }, pick ? h('div', { class: 'mb-14 w-420', }, pick) : null, form));
  onSubmit(form, async v => {
    const r = await api('case.create', v);
    toast('Преписката е въведена: ' + r.regNo);
    location.hash = '#/case/' + encodeURIComponent(r.regNo);
  });
}

const PROGRESS_FIELDS = () => [
  { k: 'status', label: 'Статус', type: 'select', options: boot.lists.statuses, req: true },
  { k: 'outcome', label: 'Резултат', type: 'select', options: boot.lists.outcomes.map(o => [o, o || '—']) },
  { k: 'clarifyAsked', label: 'Поискано уточняване (чл. 29)', type: 'date' },
  { k: 'clarifyGot', label: 'Получено уточняване', type: 'date' },
  { k: 'ext30', label: 'Удължаване по чл. 30 (дни, до 10)', type: 'number', min: 0, maxValue: 10 },
  { k: 'ext31', label: 'Удължаване по чл. 31 (дни, до 14)', type: 'number', min: 0, maxValue: 14 },
  { k: 'thirdAsked', label: 'Поискано съгласие от трето лице', type: 'date' },
  { k: 'thirdGot', label: 'Отговор от трето лице', type: 'date' },
  { k: 'decisionNo', label: 'Решение №', max: 60 },
  { k: 'decisionDate', label: 'Дата на решението', type: 'date' },
  { k: 'grounds', label: 'Правни основания (при отказ или частичен достъп)', type: 'textarea', full: true, max: 4000, rows: 3 },
  { k: 'served', label: 'Връчено на', type: 'date' },
  { k: 'servedHow', label: 'Начин на връчване', type: 'select', options: boot.lists.servedHow.map(o => [o, o || '—']) },
  { k: 'published15c', label: 'Публикувано на платформата (чл. 15в)', type: 'date' },
  { k: 'appealed', label: 'Решението е обжалвано', type: 'checkbox' },
  { k: 'appealNote', label: 'Бележка за обжалването', type: 'textarea', full: true, max: 2000, rows: 2 }
];

async function caseView(regNo) {
  loading();
  let d;
  try { d = await api('case.get', { regNo }); } catch (e) { return failView(e); }
  const c = d.case, locked = c.locked === 'Да', edit = me.perms.casesEdit && !locked;
  const reload = () => caseView(regNo);

  const editData = () => formDialog('Данни на преписката', APPLICANT_FIELDS(), c, 'Запази', async v => {
    await api('case.update', Object.assign({}, c, v, { regNo: c.regNo }));
    toast('Запазено.'); reload();
  }, { wide: true });
  const editProgress = () => formDialog('Ход и решение', PROGRESS_FIELDS(), c, 'Запази', async v => {
    await api('case.update', Object.assign({}, c, v, { regNo: c.regNo }));
    toast('Запазено.'); reload();
  }, { wide: true, extra: h('p', { class: 'note mt-12' }, 'Документите (писма и решения) не се създават в системата – тук се отбелязват само номерът, датата и резултатът.') });

  const dueCard = h('section', { class: 'card stack' }, h('h2', null, 'Срокове'),
    c.due ? [h('div', null, h('div', { class: 'small muted' }, c.dueLabel), h('div', { class: 'bigdue ' + dueClass(c.daysLeft) }, fmtDate(c.due)), h('div', { class: dueClass(c.daysLeft) }, dueText(c.daysLeft))),
      c.silentBy ? h('p', { class: 'small muted' }, 'При липса на решение заявителят може да обжалва мълчаливия отказ до ' + fmtDate(c.silentBy) + ' (чл. 149, ал. 2 АПК).') : null]
      : h('p', { class: 'muted' }, 'Няма текущ срок за произнасяне.'),
    c.thirdInvolved ? h('div', { class: 'small' }, 'Трето лице: съгласие се иска до ', h('b', null, fmtDate(c.thirdBy)), c.thirdAsked ? ' (поискано ' + fmtDate(c.thirdAsked) + ')' : '', '; отговор до ', h('b', null, fmtDate(c.thirdReplyBy)), c.thirdGot ? ' (получен ' + fmtDate(c.thirdGot) + ')' : '') : null,
    c.appealBy ? h('div', null, h('div', { class: 'small muted' }, 'Срок за обжалване на решението (чл. 149, ал. 1 АПК)'), h('b', { class: dueClass(c.appealDays) }, fmtDate(c.appealBy) + ' · ' + dueText(c.appealDays)))
      : (c.decisionDate ? h('p', { class: 'small muted' }, 'Въведете датата на връчване, за да се изчисли срокът за обжалване.') : null));

  const ownerSel = h('select', { disabled: !edit, 'aria-label': 'Отговорник' }, h('option', { value: '' }, '— без отговорник —'), boot.users.filter(u => u.role !== 'Наблюдател').map(u => h('option', { value: u.username }, u.name)));
  ownerSel.value = c.owner || '';
  const ownerCard = h('section', { class: 'card stack' }, h('h2', null, 'Отговорник'), ownerSel,
    edit ? h('div', { class: 'actions' },
      h('button', { class: 'btn primary sm', onclick: async () => { try { await api('case.assign', { regNo: c.regNo, owner: ownerSel.value }); toast('Отговорникът е записан.'); reload(); } catch (e) { toast(e.message); } } }, 'Запази'),
      c.owner !== me.username ? h('button', { class: 'btn sm', onclick: async () => { try { await api('case.assign', { regNo: c.regNo, owner: me.username }); toast('Поехте преписката.'); reload(); } catch (e) { toast(e.message); } } }, 'Поеми') : null) : null);

  const canLock = me.perms.casesEdit && (me.role === 'Администратор' || (!locked && c.owner === me.username) || (locked && c.lockedBy === me.username));
  const lockCard = h('section', { class: 'card stack' }, h('h2', null, 'Заключване'),
    h('p', { class: 'small muted' }, locked ? 'Заключена от ' + userName(c.lockedBy) + ' на ' + fmtTime(c.lockedAt) + '. Промени, коментари и смяна на отговорника не се приемат, докато не бъде отключена. Делата се водят и при заключена преписка.' : 'Заключената преписка се чете, но не се променя. Заключва отговорникът или администратор.'),
    canLock ? h('button', { class: 'btn sm', onclick: () => formDialog(locked ? 'Отключване' : 'Заключване', [{ k: 'reason', label: 'Причина (по желание)', max: 300, full: true }], {}, locked ? 'Отключи' : 'Заключи', async v => {
      await api('case.lock', { regNo: c.regNo, locked: !locked, reason: v.reason }); toast(locked ? 'Отключена.' : 'Заключена.'); reload();
    }) }, locked ? 'Отключи' : 'Заключи') : null);

  const courtCard = h('section', { class: 'card stack' }, h('div', { class: 'head m-0' }, h('h2', null, 'Съдебни дела'), me.perms.courts ? h('button', { class: 'btn sm', onclick: () => courtDialog({ regNo: c.regNo }, reload) }, 'Добави дело') : null),
    d.courts.length ? h('ul', { class: 'list-plain' }, d.courts.map(x => h('li', null,
      h('span', null, x.court.replace('Административен съд – ', 'АС '), ' № ', x.caseNo, '/', x.year, h('br'), h('span', { class: 'small muted' }, x.status + (x.nextHearing ? ' · заседание ' + fmtDate(x.nextHearing) : ''))),
      me.perms.courts ? h('button', { class: 'btn sm', onclick: () => courtDialog(x, reload) }, 'Промени') : null))) : h('p', { class: 'empty' }, 'Няма дела.'));

  const comment = h('form', null, field({ k: 'text', label: 'Вътрешен коментар', type: 'textarea', rows: 3, max: 4000, req: true, full: true }), h('div', { class: 'actions mt-8' }, h('button', { type: 'submit', class: 'btn sm primary' }, 'Добави')));
  onSubmit(comment, async v => { await api('case.comment', { regNo: c.regNo, text: v.text }); toast('Коментарът е добавен.'); reload(); });
  const history = h('section', { class: 'card stack' }, h('h2', null, 'Коментари и история'), edit ? comment : null,
    h('ul', { class: 'timeline' }, d.events.map(e => h('li', null, h('div', { class: 'small muted' }, fmtTime(e.at) + ' · ' + userName(e.user) + ' · ' + e.kind), h('div', { class: 'pre' }, e.text)))));

  setView(
    head(c.regNo + (locked ? ' 🔒' : ''), statusPill(c.status), edit ? h('button', { class: 'btn', onclick: editData }, 'Данни') : null, edit ? h('button', { class: 'btn primary', onclick: editProgress }, 'Ход и решение') : null),
    locked ? h('p', { class: 'warnbox mb-16' }, 'Преписката е заключена.') : null,
    h('div', { class: 'split' },
      h('div', { class: 'stack' },
        h('section', { class: 'card stack' }, h('h2', null, 'Заявление'), kv([
          ['Вид', c.kind], ['Регистрирано', fmtDate(c.regDate)], ['Начин на подаване', c.channel], ['Заявител', c.applicantName + ' (' + c.applicantType + ')'],
          c.applicantEik ? ['ЕИК/БУЛСТАТ', c.applicantEik] : null, ['Седалище', [c.applicantSeat, c.applicantOblast].filter(Boolean).join(', ')],
          ['Адрес', c.applicantAddress], ['Имейл', c.applicantEmail], ['Телефон', c.applicantPhone], ['Отдел', c.department],
          ['Предпочитана форма', c.form], ['Съгласие за публикуване', c.noPublish === 'Да' ? 'Не' : 'Да'],
          ['Въведена', fmtTime(c.createdAt) + ' от ' + userName(c.createdBy)]
        ]), h('div', null, h('div', { class: 'small muted' }, 'Искана информация'), h('p', { class: 'pre' }, c.subject))),
        h('section', { class: 'card stack' }, h('h2', null, 'Ход и решение'), kv([
          ['Статус', c.status], ['Резултат', c.outcome], ['Уточняване', c.clarifyAsked ? 'поискано ' + fmtDate(c.clarifyAsked) + (c.clarifyGot ? ', получено ' + fmtDate(c.clarifyGot) : '') : ''],
          ['Удължаване', [c.ext30 ? 'чл. 30: ' + c.ext30 + ' дни' : '', c.ext31 ? 'чл. 31: ' + c.ext31 + ' дни' : ''].filter(Boolean).join('; ')],
          ['Решение', c.decisionNo ? '№ ' + c.decisionNo + ' от ' + fmtDate(c.decisionDate) : ''], ['Основания', c.grounds],
          ['Връчено', c.served ? fmtDate(c.served) + (c.servedHow ? ' – ' + c.servedHow : '') : ''], ['Публикувано (чл. 15в)', c.published15c ? fmtDate(c.published15c) : ''],
          ['Обжалвано', c.appealed === 'Да' ? 'Да' + (c.appealNote ? ' – ' + c.appealNote : '') : 'Не']
        ])),
        history),
      h('div', { class: 'stack' }, dueCard, ownerCard, lockCard, courtCard)));
}

/* ---------- дела ---------- */

function courtDialog(x, done) {
  const fields = [
    { k: 'regNo', label: 'Преписка (рег. №)', max: 60, list: 'case-nos' },
    { k: 'court', label: 'Съд', type: 'select', options: boot.lists.courts, req: true },
    { k: 'instance', label: 'Инстанция', type: 'select', options: boot.lists.courtInstances, req: true },
    { k: 'caseNo', label: '№ на дело', req: true, max: 40 },
    { k: 'year', label: 'Година', type: 'number', req: true, min: 2000, maxValue: 2100 },
    { k: 'kind', label: 'Вид', type: 'select', options: boot.lists.courtKinds, req: true },
    { k: 'status', label: 'Статус', type: 'select', options: boot.lists.courtStatuses, req: true },
    { k: 'nextHearing', label: 'Следващо заседание', type: 'date' },
    { k: 'result', label: 'Резултат', max: 250, full: true },
    { k: 'note', label: 'Бележки', type: 'textarea', full: true, max: 4000, rows: 3 }
  ];
  const values = Object.assign({ year: new Date().getFullYear(), court: 'Административен съд – София-град' }, x);
  const del = x.id || x._id ? h('button', { type: 'button', class: 'btn danger mr-auto', onclick: async () => {
    if (!confirm('Да се изтрие ли делото?')) return;
    try { await api('court.delete', { id: x._id }); d.close(); toast('Делото е изтрито.'); done(); } catch (e) { toast(e.message); }
  } }, 'Изтрий') : null;
  const d = formDialog(x._id ? 'Дело' : 'Ново дело', fields, values, 'Запази', async v => {
    await api('court.save', Object.assign(v, { id: x._id || '' }));
    toast('Делото е записано.'); done();
  }, { wide: true });
  if (del) d.querySelector('.actions').prepend(del);
}

async function courtsView() {
  loading();
  try {
    const { courts, cases } = await api('court.list');
    const list = h('datalist', { id: 'case-nos' }, cases.map(n => h('option', { value: n })));
    setView(head('Съдебни дела', me.perms.courts ? h('button', { class: 'btn primary', onclick: () => courtDialog({}, courtsView) }, 'Ново дело') : null), list,
      h('div', { class: 'card' }, table(['Съд', 'Дело', 'Вид', 'Статус', 'Заседание', 'Преписка', ''], courts.map(x => h('tr', null,
        h('td', null, x.court, h('br'), h('span', { class: 'small muted' }, x.instance)), h('td', { class: 'mono' }, x.caseNo + '/' + x.year), h('td', null, x.kind),
        h('td', null, h('span', { class: 'pill' }, x.status), x.result ? h('div', { class: 'small muted' }, x.result) : null), h('td', null, x.nextHearing ? fmtDate(x.nextHearing) : '—'),
        h('td', null, x.regNo ? h('a', { href: '#/case/' + encodeURIComponent(x.regNo) }, x.regNo) : '—'),
        h('td', null, me.perms.courts ? h('button', { class: 'btn sm', onclick: () => courtDialog(x, courtsView) }, 'Промени') : null))), 'Няма въведени дела.')));
  } catch (e) { failView(e); }
}

/* ---------- адресати ---------- */

const ADDRESSEE_FIELDS = () => [
  { k: 'type', label: 'Вид', type: 'select', options: boot.lists.addresseeTypes, req: true },
  { k: 'name', label: 'Име или наименование', req: true, max: 200 },
  { k: 'eik', label: 'ЕИК/БУЛСТАТ', max: 13, pattern: '\\d{9}|\\d{13}' },
  { k: 'seat', label: 'Седалище', max: 120 },
  { k: 'oblast', label: 'Област', max: 80 },
  { k: 'address', label: 'Адрес', max: 400, full: true },
  { k: 'email', label: 'Имейл', type: 'email', max: 200 },
  { k: 'phone', label: 'Телефон', type: 'tel', max: 40 }
];

async function addresseesView() {
  loading();
  try {
    const { addressees } = await api('addressee.list');
    const edit = a => formDialog(a._id ? 'Адресат' : 'Нов адресат', ADDRESSEE_FIELDS(), a, 'Запази', async v => {
      await api('addressee.save', Object.assign(v, { id: a._id || '' })); toast('Запазено.'); addresseesView();
    }, { wide: true });
    const q = h('input', { type: 'search', placeholder: 'Търсене…', 'aria-label': 'Търсене' });
    const body = h('div');
    const draw = () => {
      const t = q.value.trim().toLowerCase();
      const rows = addressees.filter(a => !t || [a.name, a.eik, a.email, a.address].join(' ').toLowerCase().includes(t));
      body.replaceChildren(table(['Име', 'Вид', 'ЕИК/БУЛСТАТ', 'Имейл', 'Адрес', ''], rows.map(a => h('tr', null,
        h('td', null, a.name), h('td', null, a.type), h('td', { class: 'mono' }, a.eik || '—'), h('td', null, a.email || '—'), h('td', null, a.address || '—'),
        h('td', null, me.perms.addressees ? h('div', { class: 'actions' },
          h('button', { class: 'btn sm', onclick: () => edit(a) }, 'Промени'),
          h('button', { class: 'btn sm danger', onclick: async () => { if (!confirm('Да се изтрие ли ' + a.name + '?')) return; try { await api('addressee.delete', { id: a._id }); toast('Изтрит.'); addresseesView(); } catch (e) { toast(e.message); } } }, 'Изтрий')) : null))), 'Няма адресати.'));
    };
    q.addEventListener('input', draw);
    setView(head('Адресати', me.perms.addressees ? h('button', { class: 'btn primary', onclick: () => edit({ type: 'Гражданин' }) }, 'Нов адресат') : null),
      h('p', { class: 'small muted mb-12' }, 'Заявители, трети лица и органи. Избират се при нова преписка.'),
      h('div', { class: 'card' }, h('div', { class: 'filters' }, q), body));
    draw();
  } catch (e) { failView(e); }
}

/* ---------- отдели ---------- */

async function departmentsView() {
  loading();
  try {
    const { departments } = await api('department.list');
    const fields = [
      { k: 'name', label: 'Наименование', req: true, max: 160, full: true }, { k: 'head', label: 'Ръководител', max: 120 },
      { k: 'position', label: 'Длъжност', max: 120 }, { k: 'email', label: 'Имейл', type: 'email', max: 200 }, { k: 'active', label: 'Активен', type: 'checkbox' }
    ];
    const edit = x => formDialog(x._id ? 'Отдел' : 'Нов отдел', fields, x, 'Запази', async v => {
      await api('department.save', Object.assign(v, { id: x._id || '' })); toast('Запазено.'); boot = await api('bootstrap'); departmentsView();
    });
    setView(head('Отдели', me.perms.departments ? h('button', { class: 'btn primary', onclick: () => edit({ active: 'Да' }) }, 'Нов отдел') : null),
      h('div', { class: 'card' }, table(['Наименование', 'Ръководител', 'Имейл', 'Състояние', ''], departments.map(x => h('tr', null,
        h('td', null, x.name), h('td', null, [x.head, x.position].filter(Boolean).join(', ') || '—'), h('td', null, x.email || '—'),
        h('td', null, h('span', { class: 'pill ' + (x.active === 'Да' ? 'ok' : '') }, x.active === 'Да' ? 'Активен' : 'Неактивен')),
        h('td', null, me.perms.departments ? h('button', { class: 'btn sm', onclick: () => edit(x) }, 'Промени') : null))), 'Няма въведени отдели.')));
  } catch (e) { failView(e); }
}

/* ---------- потребители ---------- */

async function usersView() {
  loading();
  try {
    const d = await api('users.list');
    const edit = u => {
      const isNew = !u.username;
      const fields = [
        { k: 'username', label: 'Потребителско име', req: true, max: 40, pattern: '[a-z0-9._\\-]{3,40}', disabled: !isNew, hint: 'Малки латински букви, цифри и . _ -' },
        { k: 'name', label: 'Имена', req: true, max: 120 }, { k: 'position', label: 'Длъжност', max: 120 },
        { k: 'email', label: 'Имейл', type: 'email', req: true, max: 200, hint: 'На него идват връзките за парола.' }, { k: 'phone', label: 'Телефон', type: 'tel', max: 40 },
        { k: 'role', label: 'Роля', type: 'select', options: d.roles.map(r => [r, r + ' – ' + ROLE_HINT[r]]), req: true },
        { k: 'department', label: 'Отдел', type: 'select', options: [['', '—']].concat(d.departments.map(x => x.name)) },
        { k: 'active', label: 'Активен', type: 'checkbox' }
      ];
      const rolePerms = h('input', { type: 'checkbox', name: '_rolePerms', checked: !u.customPerms });
      const permBoxes = h('div', { class: 'perm-grid' }, d.perms.map(p => h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'p_' + p, checked: !!(u.perms && u.perms[p]) }), h('span', null, PERM_LABELS[p]))));
      const syncPerms = () => { permBoxes.hidden = rolePerms.checked; };
      rolePerms.addEventListener('change', syncPerms);
      syncPerms();
      const extra = h('fieldset', { class: 'mt-16', }, h('legend', null, 'Права'),
        h('p', { class: 'small muted mb-8' }, 'Наблюдателят винаги само преглежда. Управлението на потребители е само за администратор.'),
        h('label', { class: 'check mb-8' }, rolePerms, h('span', null, 'Права според ролята')), permBoxes);
      formDialog(isNew ? 'Нов потребител' : 'Потребител ' + u.username, fields, Object.assign({ active: 'Да', role: 'Служител' }, u), isNew ? 'Създай и изпрати връзка' : 'Запази', async (v, form) => {
        const data = Object.assign({}, v, { isNew, username: isNew ? v.username.toLowerCase() : u.username });
        data.perms = form.elements._rolePerms.checked ? null : d.perms.filter(p => form.elements['p_' + p].checked);
        Object.keys(data).filter(k => k.startsWith('p_') || k === '_rolePerms').forEach(k => delete data[k]);
        const r = await api('users.save', data);
        toast(isNew ? (r.mailed ? 'Потребителят е създаден. Връзката за парола е изпратена.' : 'Потребителят е създаден, но писмото не е изпратено – проверете пощата.') : 'Запазено.');
        boot = await api('bootstrap');
        usersView();
      }, { wide: true, extra });
    };
    setView(head('Потребители', h('button', { class: 'btn primary', onclick: () => edit({}) }, 'Нов потребител')),
      h('div', { class: 'card' }, table(['Потребител', 'Име', 'Роля', 'Отдел', 'Състояние', 'Последен вход', ''], d.users.map(u => h('tr', null,
        h('td', { class: 'mono' }, u.username), h('td', null, u.name, u.position ? h('div', { class: 'small muted' }, u.position) : null), h('td', null, u.role),
        h('td', null, u.department || '—'),
        h('td', null, u.active !== 'Да' ? h('span', { class: 'pill' }, 'Спрян') : u.pending ? h('span', { class: 'pill warn' }, 'Без парола') : h('span', { class: 'pill ok' }, 'Активен'), u.twofa ? h('span', { class: 'pill info ml-4' }, '2FA') : null),
        h('td', null, fmtTime(u.lastLogin)),
        h('td', null, h('div', { class: 'actions' }, h('button', { class: 'btn sm', onclick: () => edit(u) }, 'Промени'),
          u.active === 'Да' ? h('button', { class: 'btn sm', onclick: async () => { if (!confirm('Да се изпрати ли нова връзка за парола на ' + u.email + '?')) return; try { await api('users.invite', { username: u.username }); toast('Връзката е изпратена.'); } catch (e) { toast(e.message); } } }, 'Връзка за парола') : null,
          h('a', { class: 'btn sm', href: '#/logins/' + encodeURIComponent(u.username) }, 'Входове')))))),
        h('p', { class: 'small muted mt-12' }, 'Паролите не се изпращат. Потребителят задава паролата си сам чрез еднократна връзка, която важи 7 дни.')));
  } catch (e) { failView(e); }
}

/* ---------- дневник и входове ---------- */

async function logView() {
  loading();
  try {
    const { log } = await api('log.list');
    const q = h('input', { type: 'search', placeholder: 'Търсене: потребител, действие, обект…', 'aria-label': 'Търсене' });
    const body = h('div');
    const draw = () => {
      const t = q.value.trim().toLowerCase();
      body.replaceChildren(table(['Време', 'Потребител', 'Действие', 'Обект', 'Подробности', 'IP'], log.filter(r => !t || [r.actor, r.action, r.ref, r.details].join(' ').toLowerCase().includes(t)).slice(0, 500).map(r => h('tr', null,
        h('td', null, fmtTime(r.at)), h('td', null, r.actor), h('td', null, r.action), h('td', null, r.ref || '—'), h('td', { class: 'pre small' }, r.details || ''), h('td', { class: 'mono small' }, r.ip || '')))));
    };
    q.addEventListener('input', draw);
    setView(head('Дневник'), h('div', { class: 'card' }, h('div', { class: 'filters' }, q), body));
    draw();
  } catch (e) { failView(e); }
}

async function loginsView(username) {
  loading();
  try {
    const { logins } = await api('logins.list', { username: username || '' });
    setView(head('Входове' + (username ? ' – ' + username : '')),
      h('div', { class: 'card' }, table(['Време', 'Потребител', 'Резултат', 'IP адрес', 'Браузър'], logins.map(r => h('tr', null,
        h('td', null, fmtTime(r.at)), h('td', null, r.username), h('td', null, h('span', { class: 'pill ' + (r.result === 'Успешен' ? 'ok' : 'bad') }, r.result)),
        h('td', { class: 'mono' }, r.ip || '—'), h('td', { class: 'small login-agent' }, r.agent || '—'))))));
  } catch (e) { failView(e); }
}

/* ---------- профил ---------- */

async function profileView() {
  loading();
  let m;
  try { m = (await api('me')).me; } catch (e) { return failView(e); }
  const pw = h('form', null, h('div', { class: 'stack' },
    field({ k: 'current', label: 'Текуща парола', type: 'password', req: true, autocomplete: 'current-password' }),
    field({ k: 'next', label: 'Нова парола', type: 'password', req: true, autocomplete: 'new-password', hint: 'Поне 12 знака, с букви и цифри.' }),
    field({ k: 'again', label: 'Повторете новата парола', type: 'password', req: true, autocomplete: 'new-password' })),
  h('button', { type: 'submit', class: 'btn primary block' }, 'Смени паролата'));
  onSubmit(pw, async v => {
    const weak = strongEnough(v.next);
    if (weak) throw new Error(weak);
    if (v.next !== v.again) throw new Error('Новите пароли не съвпадат.');
    await api('password', { current: await preHash(m.username, v.current), next: await preHash(m.username, v.next) });
    pw.reset(); toast('Паролата е сменена.');
  });

  const twofa = h('form', null, h('p', { class: 'small muted mb-10' }, m.twofa
    ? 'Включен: при вход след паролата въвеждате код от 8 цифри, изпратен на ' + (m.email || 'имейла ви') + '.'
    : 'При включване след паролата ще въвеждате код, изпратен на ' + (m.email || 'имейла ви') + '.'),
  field({ k: 'password', label: 'Парола за потвърждение', type: 'password', req: true, autocomplete: 'current-password' }),
  h('button', { type: 'submit', class: 'btn block' + (m.twofa ? ' danger' : ' primary') }, m.twofa ? 'Изключи двуфакторния вход' : 'Включи двуфакторния вход'));
  onSubmit(twofa, async v => {
    const hash = await preHash(m.username, v.password);
    if (m.twofa) { await api('twofa.start', { hash, enable: false }); toast('Двуфакторният вход е изключен.'); return profileView(); }
    const st = await api('twofa.start', { hash });
    formDialog('Потвърдете кода', [{ k: 'code', label: 'Код от имейла', req: true, pattern: '\\d{8}', max: 8, full: true }], {}, 'Потвърди', async c => {
      await api('twofa.confirm', { ticket: st.ticket, code: c.code }); toast('Двуфакторният вход е включен.'); profileView();
    });
  });

  const n = m.notify;
  const notify = h('form', null, h('div', { class: 'stack' },
    field({ k: 'assign', label: 'Когато ме определят за отговорник', type: 'checkbox' }, n.assign),
    field({ k: 'deadline', label: 'Напомняния за срокове (3 дни, 1 ден, в деня и ден след)', type: 'checkbox' }, n.deadline),
    field({ k: 'status', label: 'Промяна на статуса', type: 'checkbox' }, n.status),
    field({ k: 'comments', label: 'Нов коментар', type: 'checkbox' }, n.comments),
    me.perms.casesAll ? field({ k: 'all', label: 'Статус и коментари за всички преписки, не само моите', type: 'checkbox' }, n.all) : null),
  h('button', { type: 'submit', class: 'btn block' }, 'Запази известията'));
  onSubmit(notify, async v => { await api('notify.save', v); toast('Известията са запазени.'); });

  setView(head('Моят профил'), h('div', { class: 'grid2' },
    h('section', { class: 'card stack' }, h('h2', null, 'Данни'), kv([['Потребител', m.username], ['Име', m.name], ['Роля', m.role], ['Длъжност', m.position], ['Отдел', m.department], ['Имейл', m.email], ['Телефон', m.phone],
      ['Права', Object.keys(m.perms).map(k => PERM_LABELS[k]).join('; ')]]), h('p', { class: 'small muted' }, 'Данните се променят от администратор.'), h('a', { href: '#/logins' }, 'Моите входове')),
    h('section', { class: 'card stack' }, h('h2', null, 'Парола'), pw),
    h('section', { class: 'card stack' }, h('h2', null, 'Двуфакторен вход'), twofa),
    h('section', { class: 'card stack' }, h('h2', null, 'Известия по имейл'), notify)));
}

/* ---------- калкулатор на срокове (работи и без вход) ---------- */

function calcView() {
  const form = h('form', null, h('div', { class: 'form-grid' },
    field({ k: 'regDate', label: 'Дата на регистриране', type: 'date', req: true }, todayIso()),
    field({ k: 'ext30', label: 'Удължаване по чл. 30 (дни)', type: 'number', min: 0, maxValue: 10 }, ''),
    field({ k: 'ext31', label: 'Удължаване по чл. 31 (дни)', type: 'number', min: 0, maxValue: 14 }, ''),
    field({ k: 'clarifyAsked', label: 'Поискано уточняване', type: 'date' }, ''),
    field({ k: 'clarifyGot', label: 'Получено уточняване', type: 'date' }, ''),
    field({ k: 'served', label: 'Връчено решение', type: 'date' }, '')));
  const out = h('div', { class: 'calc-out' });
  const row = (label, iso, extra) => h('div', null, h('div', { class: 'small muted' }, label), h('b', { class: dueClass(daysBetween(todayIso(), iso)) }, fmtDate(iso) + ' · ' + dueText(daysBetween(todayIso(), iso))), extra ? h('div', { class: 'small muted' }, extra) : null);
  const draw = () => {
    const v = formValues(form), items = [];
    if (/^\d{4}-\d{2}-\d{2}$/.test(v.regDate)) {
      const e30 = Math.min(10, Math.max(0, Number(v.ext30) || 0)), e31 = Math.min(14, Math.max(0, Number(v.ext31) || 0));
      if (v.clarifyAsked && !v.clarifyGot) items.push(row('Срок за уточняване от заявителя (чл. 29, ал. 2) – 30 дни', term(v.clarifyAsked, 30)));
      const base = v.clarifyGot || v.regDate, due = term(base, 14 + e30 + e31);
      items.push(row('Срок за решение (чл. 28, ал. 1' + (e30 ? '; чл. 30' : '') + (e31 ? '; чл. 31' : '') + ')', due, 'Броят се от ' + (v.clarifyGot ? 'получаване на уточнението' : 'регистрирането') + '; ако изтича в неработен ден, се мести на следващия работен.'));
      items.push(row('Съгласие от трето лице се иска до (чл. 31, ал. 2)', term(v.regDate, 7)));
      items.push(row('Мълчалив отказ може да се обжалва до (чл. 149, ал. 2 АПК)', termMonths(due, 2)));
    }
    if (/^\d{4}-\d{2}-\d{2}$/.test(v.served)) items.push(row('Срок за обжалване на решението (14 дни, чл. 149, ал. 1 АПК)', term(v.served, 14)));
    out.replaceChildren(...items);
  };
  form.addEventListener('input', draw);
  const card = h('div', { class: 'card' }, form, out,
    h('p', { class: 'small muted mt-14' }, 'Отчитат се официалните празници и почивните дни по чл. 154 КТ. Изчислението е помощно и не е правна консултация.'));
  if (me) setView(head('Калкулатор на срокове'), card);
  else gate('Калкулатор на срокове', 'Срокове по ЗДОИ и АПК.', card, h('div', { class: 'gate-links' }, h('a', { href: '#/login' }, 'Към входа')));
  if (!me) document.querySelector('.gate-card').classList.add('wide');
  draw();
}

/* ---------- маршрути ---------- */

async function route() {
  const raw = location.hash.slice(1) || '/dashboard';
  const [path, query] = raw.split('?');
  const parts = path.split('/').filter(Boolean).map(decodeURIComponent);
  const page = parts[0] || 'dashboard';
  if (!me) {
    if (page === 'activate') return activateView(parts[1] || '', parts[2] || '');
    if (page === 'forgot') return forgotView();
    if (page === 'calc') return calcView();
    if (page !== 'login') { history.replaceState(null, '', '#/login'); }
    return loginView();
  }
  if (['login', 'activate', 'forgot'].includes(page)) { location.hash = '#/dashboard'; return; }
  shell();
  switch (page) {
    case 'dashboard': return dashboardView();
    case 'cases': return casesView(query);
    case 'case': return parts[1] === 'new' ? newCaseView() : caseView(parts[1]);
    case 'courts': return courtsView();
    case 'addressees': return addresseesView();
    case 'departments': return departmentsView();
    case 'users': return me.role === 'Администратор' ? usersView() : failView(new Error('Само за администратор.'));
    case 'log': return logView();
    case 'logins': return loginsView(parts[1]);
    case 'profile': return profileView();
    case 'calc': return calcView();
    default: return setView(h('p', { class: 'err' }, 'Страницата не е намерена.'));
  }
}

window.addEventListener('hashchange', route);

/* при отваряне: ако бисквитката е валидна, сесията продължава */
(async () => {
  if (!/^#\/(activate|forgot|calc)/.test(location.hash)) {
    try {
      const r = await api('me');
      await startSession(r.me);
    } catch (_) { me = null; }
  }
  route();
})();
