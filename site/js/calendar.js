/* Календар: празниците по чл. 154 КТ; срок, който изтича в неработен ден, се мести на следващия работен (чл. 60, ал. 6 ГПК). */

export const DAY_MS = 864e5;
const mk = (y, m, d) => new Date(Date.UTC(y, m, d));
export const dateKey = d => d.toISOString().slice(0, 10);
export const addDays = (d, n) => new Date(d.getTime() + n * DAY_MS);
export const parseIso = s => { const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(s || ''); return m ? mk(+m[1], m[2] - 1, +m[3]) : null; };

/* юлиански Великден + 13 дни (1900–2099) */
export function orthodoxEaster(y) {
  const a = y % 4, b = y % 7, c = y % 19, d = (19 * c + 15) % 30, e = (2 * a + 4 * b - d + 34) % 7;
  const month = Math.floor((d + e + 114) / 31), day = ((d + e + 114) % 31) + 1;
  return addDays(mk(y, month - 1, day), 13);
}

const cache = {};
export function holidays(y) {
  if (cache[y]) return cache[y];
  const set = {}, e = orthodoxEaster(y);
  [-2, -1, 0, 1].forEach(o => { set[dateKey(addDays(e, o))] = 1; });
  const fixed = [[0, 1], [2, 3], [4, 1], [4, 6], [4, 24], [8, 6], [8, 22], [11, 24], [11, 25], [11, 26]].map(p => mk(y, p[0], p[1]));
  fixed.forEach(f => { set[dateKey(f)] = 1; });
  // празник в събота или неделя се отработва в първия следващ работен ден
  fixed.forEach(f => {
    const w = f.getUTCDay();
    if (w === 0 || w === 6) {
      let x = addDays(f, 1);
      while (x.getUTCDay() === 0 || x.getUTCDay() === 6 || set[dateKey(x)]) x = addDays(x, 1);
      set[dateKey(x)] = 1;
    }
  });
  return (cache[y] = set);
}

export const isWorkday = d => d.getUTCDay() !== 0 && d.getUTCDay() !== 6 && !holidays(d.getUTCFullYear())[dateKey(d)];

/* срок в дни от дата, преместен до работен ден */
export function term(startIso, days) {
  let end = addDays(parseIso(startIso), days);
  while (!isWorkday(end)) end = addDays(end, 1);
  return dateKey(end);
}

/* срок в месеци (мълчалив отказ: 2 месеца, чл. 149, ал. 2 АПК); при липса на ден – последният ден на месеца */
export function termMonths(startIso, months) {
  const s = parseIso(startIso);
  const y = s.getUTCFullYear(), m = s.getUTCMonth() + months, d = s.getUTCDate();
  const last = new Date(Date.UTC(y, m + 1, 0)).getUTCDate();
  let end = mk(y, m, Math.min(d, last));
  while (!isWorkday(end)) end = addDays(end, 1);
  return dateKey(end);
}

export const daysBetween = (fromIso, toIso) => Math.round((parseIso(toIso) - parseIso(fromIso)) / DAY_MS);
