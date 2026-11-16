/*
 * SharePoint списъци. Заглавията на списъците и колоните са на български, за да се четат и ръчно.
 * Вътрешното име на колона е „z“ + ключа (zOrgNo, zName…), за да не съвпада със системните колони на SharePoint.
 * Всички стойности са текст. Колоните с „long“ са многоредови (до 63 999 знака), останалите са до 255 знака.
 * Колоните с „index“ са индексирани – по тях се търси.
 */

export const SCHEMA = {
  settings: ['ADM Настройки', { key: ['Ключ', 'index'], value: ['Стойност', 'long'] }, r => r.key],
  users: ['ADM Потребители', {
    username: ['Потребител', 'index'], name: ['Име'], position: ['Длъжност'],
    email: ['Имейл'], phone: ['Телефон'], role: ['Роля'], active: ['Активен'], department: ['Отдел'],
    perms: ['Права (JSON)'], notify: ['Известия (JSON)'], twofa: ['Двуфакторен вход'],
    salt: ['Сол'], hash: ['Хеш'], inviteHash: ['Покана (хеш)'], inviteExp: ['Покана до'], codeHash: ['Код (HMAC)'], codeExp: ['Код до'],
    lastLogin: ['Последен вход'], createdAt: ['Създаден'], createdBy: ['Създал']
  }, r => r.username],
  cases: ['ADM Преписки', {
    regNo: ['Рег. №', 'index'], createdAt: ['Въведена'], createdBy: ['Въвел'],
    kind: ['Вид заявление'], regDate: ['Дата на регистриране'], channel: ['Начин на подаване'],
    applicantType: ['Вид заявител'], applicantName: ['Заявител'], applicantEik: ['ЕИК/БУЛСТАТ на заявителя'], applicantSeat: ['Седалище'],
    applicantOblast: ['Област'], applicantAddress: ['Адрес за кореспонденция', 'long'], applicantEmail: ['Имейл'], applicantPhone: ['Телефон'],
    subject: ['Описание на исканата информация', 'long'], form: ['Предпочитана форма'], noPublish: ['Отказ от публикуване (чл. 25, ал. 1, т. 5)'],
    status: ['Статус'], outcome: ['Резултат'], owner: ['Отговорник'], department: ['Отдел'],
    clarifyAsked: ['Поискано уточняване'], clarifyGot: ['Получено уточняване'], ext30: ['Удължаване чл. 30 (дни)'], ext31: ['Удължаване чл. 31 (дни)'],
    thirdAsked: ['Поискано съгласие'], thirdGot: ['Отговор от трето лице'],
    decisionNo: ['Решение №'], decisionDate: ['Дата на решение'], grounds: ['Основания', 'long'],
    served: ['Връчено на'], servedHow: ['Начин на връчване'], published15c: ['Публикувано (чл. 15в)'],
    appealed: ['Обжалвано'], appealNote: ['Бележка за обжалването', 'long'],
    locked: ['Заключена'], lockedBy: ['Заключил'], lockedAt: ['Заключена на'], updatedAt: ['Променена']
  }, r => r.regNo],
  events: ['ADM Събития', {
    regNo: ['Рег. №', 'index'], at: ['Време'], user: ['Потребител'], kind: ['Вид'], text: ['Текст', 'long']
  }, r => r.regNo + ' ' + r.kind],
  courts: ['ADM Дела', {
    regNo: ['Преписка'], court: ['Съд'], caseNo: ['№ на дело'], year: ['Година'],
    kind: ['Вид'], instance: ['Инстанция'], status: ['Статус'], nextHearing: ['Следващо заседание'], result: ['Резултат'],
    note: ['Бележки', 'long'], by: ['Въвел'], at: ['Въведено'], updatedAt: ['Променено']
  }, r => r.court + ' ' + r.caseNo + '/' + r.year],
  requests: ['ADM Заявления', {
    regNo: ['№ на преписка', 'index'], tag: ['Пощенски етикет', 'index'], createdAt: ['Създадена'], createdBy: ['Създал'], updatedAt: ['Променена'],
    kind: ['Вид'], status: ['Статус'], owner: ['Отговорник'], title: ['Предмет'],
    mode: ['Заявител от името на'], applicant: ['Заявител (JSON)', 'long'], applicantName: ['Заявител'],
    entityId: ['Адресат (ID)'], entity: ['Задължен субект (JSON)', 'long'], entityName: ['Задължен субект'], entityEmail: ['Имейл на субекта'],
    points: ['Искана информация (JSON)', 'long'], motives: ['Мотиви', 'long'], access: ['Форма на достъп (JSON)'], noPublish: ['Несъгласие с публикуване'],
    sentAt: ['Изпратено на'], sentHow: ['Начин на изпращане'], outNo: ['Изх. № на заявлението'], entityRegNo: ['Вх. № при субекта'], entityRegDate: ['Вх. дата при субекта'],
    clarifyAskedAt: ['Поискано уточняване'], clarifySentAt: ['Изпратено уточнение'], ext30: ['Удължаване чл. 30 (дни)'], ext31: ['Удължаване чл. 31 (дни)'],
    decisionNo: ['Решение №'], decisionDate: ['Дата на решението'], outcome: ['Резултат'], servedAt: ['Получено решение на'],
    appealed: ['Обжалвано'], appealNote: ['Бележка за обжалването', 'long'], notes: ['Бележки', 'long'],
    locked: ['Заключена'], lockedBy: ['Заключил'], lockedAt: ['Заключена на']
  }, r => r.regNo + ' ' + (r.entityName || '')],
  docs: ['ADM Документи', {
    outNo: ['Изх. №', 'index'], regNo: ['Преписка', 'index'], kind: ['Вид'], date: ['Дата'], title: ['Заглавие'],
    payload: ['Съдържание (JSON)', 'long'], fileId: ['Файл (ID)'], fileUrl: ['Файл'], sentAt: ['Изпратен на'], sentTo: ['Изпратен до'], by: ['Създал'], at: ['Създаден']
  }, r => r.outNo + ' ' + r.kind],
  mail: ['ADM Кореспонденция', {
    regNo: ['Преписка', 'index'], messageId: ['Message-ID', 'index'], direction: ['Посока'], at: ['Време'], from: ['От'], to: ['До', 'long'], cc: ['Копие', 'long'],
    subject: ['Тема'], body: ['Текст', 'long'], graphId: ['ID в пощата', 'long'], attachments: ['Прикачени (JSON)', 'long'], docOutNo: ['Документ'], by: ['Изпратил'], matched: ['Разпределено по']
  }, r => (r.direction || '') + ' ' + (r.subject || '')],
  addressees: ['ADM Адресати', {
    type: ['Вид'], name: ['Име или наименование'], regBasis: ['Регистрация'], eik: ['ЕИК/БУЛСТАТ'],
    seat: ['Седалище'], address: ['Адрес', 'long'], oblast: ['Област'], email: ['Имейл'], phone: ['Телефон'], by: ['Въвел'], at: ['Въведен']
  }, r => r.name],
  departments: ['ADM Отдели', {
    name: ['Наименование'], head: ['Ръководител'], position: ['Длъжност'],
    email: ['Имейл'], active: ['Активен'], by: ['Въвел'], at: ['Въведен']
  }, r => r.name],
  log: ['ADM Дневник', {
    at: ['Време'], actor: ['Потребител'], action: ['Действие'], ref: ['Обект'], details: ['Подробности', 'long'], ip: ['IP адрес']
  }, r => r.action],
  logins: ['ADM Входове', {
    at: ['Време'], username: ['Потребител'], ip: ['IP адрес'], agent: ['Браузър'], result: ['Резултат']
  }, r => r.username + ' ' + r.result]
};

export const colName = key => 'z' + key[0].toUpperCase() + key.slice(1);
export const tableKeys = Object.keys(SCHEMA);

/* дължина на кратките колони в SharePoint */
export const SHORT_MAX = 255;

/* защита от изпълнение като формула при експорт в Excel */
export const safeCell = v => {
  if (v === null || v === undefined) return '';
  const t = String(v);
  return /^[=+\-@\t\r]/.test(t) ? "'" + t : t;
};
export const readCell = v => {
  const t = v === null || v === undefined ? '' : String(v);
  return /^'[=+\-@\t\r]/.test(t) ? t.slice(1) : t;
};

/* подготвя запис: само познатите полета, като текст, а кратките – отрязани до 255 знака */
export function toFields(table, obj) {
  const cols = SCHEMA[table][1], out = {};
  Object.keys(obj).forEach(k => {
    if (!cols[k]) return;
    let v = safeCell(obj[k]);
    if (cols[k][1] !== 'long' && cols[k][1] !== 'index' && v.length > SHORT_MAX) v = v.slice(0, SHORT_MAX);
    out[k] = v;
  });
  return out;
}
