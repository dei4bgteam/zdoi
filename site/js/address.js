/*
 * Адрес от списък: област, община и населено място по ЕКАТТЕ на НСИ (архив 2025), пощенски код от GeoNames (CC BY 4.0)
 * и улици от OpenStreetMap (ODbL), където има данни. Резултатът се записва в обикновено текстово поле и може да се допълни ръчно.
 */

const memo = {};
const json = url => memo[url] || (memo[url] = fetch(url).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); }).catch(e => { delete memo[url]; throw e; }));
let seq = 0;

/* h – функцията за елементи от app.js; target – поле за адреса; oblastInput – по желание, поле за областта */
export function addressPicker(h, target, oblastInput) {
  const opt = (v, t) => h('option', { value: v }, t || v);
  const sel = label => h('select', { 'aria-label': label, disabled: true }, opt('', label));
  const oblast = sel('Област'), muni = sel('Община'), place = sel('Населено място');
  const sList = h('datalist', { id: 'adr-s-' + (++seq) });
  const street = h('input', { placeholder: 'ул., бул., ж.к. …', list: sList.id, autocomplete: 'off', 'aria-label': 'Улица' });
  const number = h('input', { placeholder: '№, бл., вх., ет., ап.', autocomplete: 'off', 'aria-label': 'Номер' });
  const postcode = h('input', { placeholder: 'п.к.', maxlength: 4, inputmode: 'numeric', pattern: '\\d{4}', autocomplete: 'off', 'aria-label': 'Пощенски код' });
  const note = h('small', { class: 'muted' }, 'Изберете от списъка – пощенският код се попълва сам. Полето с адреса остава редактируемо.');
  let data = null, codes = {}, streets = [];

  const compose = () => {
    const parts = [];
    if (postcode.value) parts.push('п.к. ' + postcode.value);
    if (place.value) parts.push(place.selectedOptions[0].textContent);
    if (oblast.value) parts.push('обл. ' + oblast.value);
    if (muni.value && muni.value !== (place.value ? place.selectedOptions[0].textContent.replace(/^(гр|с)\.\s/, '') : '')) parts.push('общ. ' + muni.value);
    if (street.value.trim()) parts.push(street.value.trim());
    if (number.value.trim()) parts.push(number.value.trim());
    target.value = parts.join(', ');
    target.dispatchEvent(new Event('input', { bubbles: true }));
    if (oblastInput) oblastInput.value = oblast.value;
  };

  const fill = (select, items, label) => {
    select.replaceChildren(opt('', label), ...items.map(([v, t]) => opt(v, t)));
    select.disabled = !items.length;
  };

  json('data/places.json').then(d => {
    data = d;
    fill(oblast, d.oblasts.map(o => [o.n, o.n]), 'Област');
  }).catch(() => { note.textContent = 'Списъкът с адреси не можа да се зареди – попълнете адреса ръчно.'; });
  json('data/postcodes.json').then(d => { codes = d.codes || {}; }).catch(() => {});

  oblast.addEventListener('change', () => {
    const o = data.oblasts.find(x => x.n === oblast.value);
    fill(muni, o ? o.m.map(m => [m.n, m.n]) : [], 'Община');
    fill(place, [], 'Населено място');
    compose();
  });
  muni.addEventListener('change', () => {
    const o = data.oblasts.find(x => x.n === oblast.value), m = o && o.m.find(x => x.n === muni.value);
    fill(place, m ? m.s.map(s => [s.e, s.n]) : [], 'Населено място');
    compose();
  });
  place.addEventListener('change', async () => {
    postcode.value = codes[place.value] || '';
    streets = [];
    sList.replaceChildren();
    try {
      const idx = await json('data/streets/index.json');
      if (idx.includes(place.value)) {
        const st = await json('data/streets/' + place.value + '.json');
        streets = (st.streets || []).concat(st.quarters || []);
        sList.replaceChildren(...streets.slice(0, 3000).map(s => h('option', { value: /^(ул|бул|ж\.к|кв|пл)/.test(s) ? s : 'ул. ' + s })));
      }
    } catch (_) { /* без улици */ }
    compose();
  });
  [street, number, postcode].forEach(x => x.addEventListener('input', compose));

  return h('details', { class: 'addr-pick full' }, h('summary', null, 'Попълни адреса от списък (област, населено място, п.к.)'),
    h('div', { class: 'form-grid mt-8' }, oblast, muni, place, postcode, street, number), sList, note);
}
