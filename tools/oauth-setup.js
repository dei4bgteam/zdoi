/*
 * Вход с Microsoft за adm.zdoi.eu (вход с код за устройство, глобален администратор):
 *   1. приложение „ADM ZDOI4You – вход“ само за акаунтите в организацията, със същия сертификат като сървърното
 *      (без client secret) и адрес за връщане https://adm.zdoi.eu/api/oauth/microsoft/callback;
 *   2. одобрение от администратор само за openid, profile и email (без достъп до данни);
 *   3. новите колони в SharePoint (външни профили на потребителите).
 *
 *   node tools/oauth-setup.js --cert ~/.adm-zdoi/adm-zdoi.crt
 */

import { readFileSync } from 'node:fs';
import { graph } from '../worker/src/graph.js';
import { SharePointStore } from '../worker/src/store/sharepoint.js';

const arg = (name, def) => { const i = process.argv.indexOf('--' + name); return i > 0 ? process.argv[i + 1] : def; };
const TENANT = arg('tenant', 'bulmail.eu');
const CERT = arg('cert');
const APP_URL = arg('app', 'https://adm.zdoi.eu/');
const SITE = arg('site', 'bulmaileu.sharepoint.com,c089c092-6209-4a58-a6f1-8a9ff9db54cb,cac3c2b2-5302-4544-a8c0-6ae13823279d');
const NAME = 'ADM ZDOI4You – вход';
const CLIENT = '14d82eec-204b-4c2f-b7e8-296a70dab67e'; // Microsoft Graph Command Line Tools
const GRAPH_APP = '00000003-0000-0000-c000-000000000000';
const SCOPES = ['Application.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All', 'Sites.Manage.All', 'User.Read'].map(s => 'https://graph.microsoft.com/' + s).join(' ');
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

const der = Buffer.from(readFileSync(CERT, 'utf8').replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''), 'base64');
const env = { GRAPH_TOKEN: await deviceLogin(), SP_SITE: SITE };
console.log('Влязохте като ' + (await graph(env, 'GET', '/me?$select=userPrincipalName')).userPrincipalName);

const graphSp = (await graph(env, 'GET', "/servicePrincipals?$filter=appId eq '" + GRAPH_APP + "'&$select=id,oauth2PermissionScopes")).value[0];
const scopes = ['openid', 'profile', 'email'];
const access = scopes.map(v => ({ id: graphSp.oauth2PermissionScopes.find(s => s.value === v).id, type: 'Scope' }));
const redirect = APP_URL.replace(/\/$/, '') + '/api/oauth/microsoft/callback';
const body = {
  signInAudience: 'AzureADMyOrg',
  web: { redirectUris: [redirect], implicitGrantSettings: { enableIdTokenIssuance: false, enableAccessTokenIssuance: false } },
  requiredResourceAccess: [{ resourceAppId: GRAPH_APP, resourceAccess: access }],
  optionalClaims: { idToken: [{ name: 'email', essential: false }] }
};

let app = (await graph(env, 'GET', "/applications?$filter=displayName eq '" + NAME + "'&$select=id,appId")).value[0];
if (!app) {
  app = await graph(env, 'POST', '/applications', Object.assign({ displayName: NAME, notes: 'Вход на служителите в adm.zdoi.eu. Само openid/profile/email, без достъп до данни.',
    keyCredentials: [{ type: 'AsymmetricX509Cert', usage: 'Verify', key: der.toString('base64'), displayName: 'CN=ADM ZDOI4You' }] }, body));
  console.log('Създадено приложение: ' + app.appId);
} else {
  await graph(env, 'PATCH', '/applications/' + app.id, body);
  console.log('Обновено приложение: ' + app.appId);
}

let sp = (await graph(env, 'GET', "/servicePrincipals?$filter=appId eq '" + app.appId + "'&$select=id")).value[0];
for (let i = 0; !sp && i < 10; i++) {
  try { sp = await graph(env, 'POST', '/servicePrincipals', { appId: app.appId, tags: ['WindowsAzureActiveDirectoryIntegratedApp'] }); } catch (e) { await sleep(3000); }
}
const grants = (await graph(env, 'GET', "/oauth2PermissionGrants?$filter=clientId eq '" + sp.id + "'")).value || [];
const g = grants.find(x => x.consentType === 'AllPrincipals' && x.resourceId === graphSp.id);
if (!g) await graph(env, 'POST', '/oauth2PermissionGrants', { clientId: sp.id, consentType: 'AllPrincipals', resourceId: graphSp.id, scope: scopes.join(' ') });
else if (g.scope.trim() !== scopes.join(' ')) await graph(env, 'PATCH', '/oauth2PermissionGrants/' + g.id, { scope: scopes.join(' ') });
console.log('Одобрение от администратор: ' + scopes.join(', '));

const { created } = await new SharePointStore(env).ensureSchema();
console.log(created.length ? 'Нови колони: ' + created.join(', ') : 'Колоните вече съществуват.');
console.log('\nMS_LOGIN_CLIENT_ID = "' + app.appId + '"');
