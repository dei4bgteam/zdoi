/*
 * Създава приложението „ADM ZDOI4You“ в Microsoft Entra с вход със сертификат (вход с код за устройство, глобален администратор):
 *   1. регистрация на приложение + сертификат (без client secret);
 *   2. право Sites.Selected с одобрение от администратор;
 *   3. достъп за запис САМО до сайта на системата.
 * Пощата (Mail.Send) НЕ се дава в Entra, а с RBAC for Applications в Exchange само за no-reply@zdoi.eu.
 *
 *   node tools/entra-setup.js --cert ~/.adm-zdoi/adm-zdoi.crt [--site <site-id>] [--out entra.json]
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { graph } from '../worker/src/graph.js';

const arg = (name, def) => { const i = process.argv.indexOf('--' + name); return i > 0 ? process.argv[i + 1] : def; };
const TENANT = arg('tenant', 'bulmail.eu');
const CERT = arg('cert');
const SITE = arg('site', 'bulmaileu.sharepoint.com,c089c092-6209-4a58-a6f1-8a9ff9db54cb,cac3c2b2-5302-4544-a8c0-6ae13823279d');
const OUT = arg('out', 'entra.json');
const NAME = 'ADM ZDOI4You';
const CLIENT = '14d82eec-204b-4c2f-b7e8-296a70dab67e'; // Microsoft Graph Command Line Tools
const GRAPH_APP = '00000003-0000-0000-c000-000000000000';
const SCOPES = ['Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'Sites.FullControl.All', 'User.Read'].map(s => 'https://graph.microsoft.com/' + s).join(' ');
const sleep = ms => new Promise(r => setTimeout(r, ms));
if (!CERT) throw new Error('Посочете --cert <файл .crt>.');

async function deviceLogin() {
  const base = 'https://login.microsoftonline.com/' + TENANT + '/oauth2/v2.0/';
  const dc = await (await fetch(base + 'devicecode', { method: 'POST', body: new URLSearchParams({ client_id: CLIENT, scope: SCOPES }) })).json();
  if (!dc.device_code) throw new Error(JSON.stringify(dc));
  console.log('>>> ' + dc.message);
  const until = Date.now() + dc.expires_in * 1000;
  while (Date.now() < until) {
    await sleep((dc.interval || 5) * 1000);
    const t = await (await fetch(base + 'token', { method: 'POST', body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', client_id: CLIENT, device_code: dc.device_code }) })).json();
    if (t.access_token) return t.access_token;
    if (t.error !== 'authorization_pending' && t.error !== 'slow_down') throw new Error(t.error + ': ' + String(t.error_description).split('\n')[0]);
  }
  throw new Error('Кодът изтече.');
}

const pem = readFileSync(CERT, 'utf8');
const der = Buffer.from(pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''), 'base64');
const sha1 = createHash('sha1').update(der).digest('hex');
const sha256 = createHash('sha256').update(der).digest('hex');

const env = { GRAPH_TOKEN: await deviceLogin() };
const me = await graph(env, 'GET', '/me?$select=userPrincipalName');
console.log('Влязохте като ' + me.userPrincipalName);

// 1. приложение
let app = (await graph(env, 'GET', "/applications?$filter=displayName eq '" + NAME + "'&$select=id,appId,keyCredentials")).value[0];
const key = { type: 'AsymmetricX509Cert', usage: 'Verify', key: der.toString('base64'), displayName: 'CN=ADM ZDOI4You' };
if (!app) {
  app = await graph(env, 'POST', '/applications', { displayName: NAME, signInAudience: 'AzureADMyOrg', keyCredentials: [key], notes: 'Сървърът на adm.zdoi.eu (Cloudflare Worker). Достъп само до сайта adm-zdoi; поща само от no-reply@zdoi.eu (Exchange RBAC).' });
  console.log('Създадено приложение: ' + app.appId);
} else {
  const has = (app.keyCredentials || []).some(k => Buffer.from(k.customKeyIdentifier || '', 'base64').toString('hex').toLowerCase() === sha1);
  if (!has) {
    await graph(env, 'PATCH', '/applications/' + app.id, { keyCredentials: (app.keyCredentials || []).map(k => ({ type: k.type, usage: k.usage, key: k.key, keyId: k.keyId })).filter(k => k.key).concat(key) });
    console.log('Добавен сертификат към съществуващото приложение.');
  } else console.log('Приложението вече съществува със същия сертификат: ' + app.appId);
}

// 2. service principal и Sites.Selected
let sp = (await graph(env, 'GET', "/servicePrincipals?$filter=appId eq '" + app.appId + "'&$select=id")).value[0];
for (let i = 0; !sp && i < 10; i++) {
  try { sp = await graph(env, 'POST', '/servicePrincipals', { appId: app.appId }); } catch (e) { await sleep(3000); }
}
const graphSp = (await graph(env, 'GET', "/servicePrincipals?$filter=appId eq '" + GRAPH_APP + "'&$select=id,appRoles")).value[0];
const role = graphSp.appRoles.find(r => r.value === 'Sites.Selected');
await graph(env, 'PATCH', '/applications/' + app.id, { requiredResourceAccess: [{ resourceAppId: GRAPH_APP, resourceAccess: [{ id: role.id, type: 'Role' }] }] });
const assigned = (await graph(env, 'GET', '/servicePrincipals/' + sp.id + '/appRoleAssignments')).value.some(a => a.appRoleId === role.id);
if (!assigned) await graph(env, 'POST', '/servicePrincipals/' + graphSp.id + '/appRoleAssignedTo', { principalId: sp.id, resourceId: graphSp.id, appRoleId: role.id });
console.log('Sites.Selected: одобрено.');

// 3. запис само в сайта на системата
const perms = (await graph(env, 'GET', '/sites/' + SITE + '/permissions')).value || [];
const mine = perms.find(p => (p.grantedToIdentitiesV2 || p.grantedToIdentities || []).some(g => g.application && g.application.id === app.appId));
if (!mine) {
  await graph(env, 'POST', '/sites/' + SITE + '/permissions', { roles: ['write'], grantedToIdentities: [{ application: { id: app.appId, displayName: NAME } }] });
  console.log('Достъп за запис до сайта: даден.');
} else console.log('Достъп до сайта: вече има (' + (mine.roles || []).join(', ') + ').');

const result = { tenant: (await graph(env, 'GET', '/organization?$select=id')).value[0].id, clientId: app.appId, servicePrincipalId: sp.id, sha1, sha256 };
writeFileSync(OUT, JSON.stringify(result, null, 2));
console.log('\n' + JSON.stringify(result, null, 2));
