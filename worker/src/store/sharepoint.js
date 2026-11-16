/*
 * Склад в SharePoint списъци чрез Microsoft Graph.
 * SP_SITE е адресът на сайта във вида „tenant.sharepoint.com:/sites/adm“ или идентификаторът му.
 */

import { SCHEMA, colName, toFields, readCell } from '../schema.js';
import { graph, graphBytes, GraphError } from '../graph.js';

const PREFER = { Prefer: 'HonorNonIndexedQueriesWarningMayFailRandomly' };
const ids = { site: null, lists: null };
const q = v => "'" + String(v).replace(/'/g, "''") + "'";

export class SharePointStore {
  constructor(env) {
    this.env = env;
    if (!env.SP_SITE) throw new Error('Липсва SP_SITE.');
  }

  async siteId() {
    if (ids.site) return ids.site;
    const s = String(this.env.SP_SITE).trim();
    const r = await graph(this.env, 'GET', '/sites/' + encodeURI(s) + '?$select=id');
    return (ids.site = r.id);
  }

  async listMap(force) {
    if (ids.lists && !force) return ids.lists;
    const site = await this.siteId(), map = {};
    let url = '/sites/' + site + '/lists?$select=id,displayName&$top=200';
    while (url) {
      const r = await graph(this.env, 'GET', url);
      (r.value || []).forEach(l => { map[l.displayName] = l.id; });
      url = r['@odata.nextLink'] || null;
    }
    return (ids.lists = map);
  }

  async base(table) {
    const title = SCHEMA[table][0];
    let id = (await this.listMap())[title];
    if (!id) id = (await this.listMap(true))[title];
    if (!id) throw new Error('Няма списък „' + title + '“. Изпълнете настройката (/api/setup).');
    return '/sites/' + (await this.siteId()) + '/lists/' + id;
  }

  row(table, item) {
    const f = item.fields || {}, o = { _id: String(item.id), _etag: item.eTag || f['@odata.etag'] || '' };
    Object.keys(SCHEMA[table][1]).forEach(k => { o[k] = readCell(f[colName(k)]); });
    return o;
  }

  async list(table, where = {}) {
    const keys = Object.keys(where);
    const select = Object.keys(SCHEMA[table][1]).map(colName).join(',');
    let url = (await this.base(table)) + '/items?$top=999&$expand=fields($select=' + select + ')';
    if (keys.length) url += '&$filter=' + encodeURIComponent(keys.map(k => 'fields/' + colName(k) + ' eq ' + q(where[k])).join(' and '));
    const out = [];
    while (url) {
      const r = await graph(this.env, 'GET', url, undefined, PREFER);
      (r.value || []).forEach(it => out.push(this.row(table, it)));
      url = r['@odata.nextLink'] || null;
    }
    // подредба по реда на въвеждане, както в таблица
    return out.sort((a, b) => Number(a._id) - Number(b._id));
  }

  async get(table, id) {
    try {
      const it = await graph(this.env, 'GET', (await this.base(table)) + '/items/' + encodeURIComponent(id) + '?$expand=fields');
      return this.row(table, it);
    } catch (e) {
      if (e instanceof GraphError && e.status === 404) return null;
      throw e;
    }
  }

  spFields(table, obj) {
    const f = toFields(table, obj), out = {};
    Object.keys(f).forEach(k => { out[colName(k)] = f[k]; });
    out.Title = String(SCHEMA[table][2](Object.assign({}, obj)) || table).slice(0, 255);
    return out;
  }

  async insert(table, obj) {
    const it = await graph(this.env, 'POST', (await this.base(table)) + '/items', { fields: this.spFields(table, obj) });
    return this.row(table, it);
  }

  async patch(table, id, obj) {
    const f = toFields(table, obj), out = {};
    Object.keys(f).forEach(k => { out[colName(k)] = f[k]; });
    if (!Object.keys(out).length) return;
    await graph(this.env, 'PATCH', (await this.base(table)) + '/items/' + encodeURIComponent(id) + '/fields', out);
  }

  async remove(table, id) {
    await graph(this.env, 'DELETE', (await this.base(table)) + '/items/' + encodeURIComponent(id));
  }

  /* файлове в библиотеката „Документи“ на сайта, папка ADM/… */
  async uploadFile(path, bytes, contentType) {
    const clean = path.split('/').map(p => p.replace(/[\\:*?"<>|#%]/g, '_').trim()).filter(Boolean).map(encodeURIComponent).join('/');
    const r = await graphBytes(this.env, 'PUT', '/sites/' + (await this.siteId()) + '/drive/root:/ADM/' + clean + ':/content?@microsoft.graph.conflictBehavior=rename', bytes, contentType || 'application/octet-stream');
    return { id: r.id, webUrl: r.webUrl, name: r.name, size: r.size };
  }

  async downloadFile(id) {
    return graphBytes(this.env, 'GET', '/sites/' + (await this.siteId()) + '/drive/items/' + encodeURIComponent(id) + '/content');
  }

  /* създава липсващите списъци и колони; изпълнява се при настройката и е безопасно да се повтаря */
  async ensureSchema() {
    const site = await this.siteId(), created = [];
    const have = await this.listMap(true);
    for (const table of Object.keys(SCHEMA)) {
      const [title, cols] = SCHEMA[table];
      const defs = Object.keys(cols).map(k => {
        const kind = cols[k][1];
        return Object.assign({ name: colName(k), displayName: cols[k][0], text: kind === 'long' ? { allowMultipleLines: true, textType: 'plain' } : {} },
          kind === 'index' ? { indexed: true } : {});
      });
      if (!have[title]) {
        const r = await graph(this.env, 'POST', '/sites/' + site + '/lists', { displayName: title, columns: defs, list: { template: 'genericList' } });
        have[title] = r.id;
        created.push(title);
        continue;
      }
      // новите колони от по-късни версии се добавят към съществуващия списък
      const existing = await graph(this.env, 'GET', '/sites/' + site + '/lists/' + have[title] + '/columns?$select=name');
      const names = new Set((existing.value || []).map(c => c.name));
      for (const d of defs) {
        if (!names.has(d.name)) {
          await graph(this.env, 'POST', '/sites/' + site + '/lists/' + have[title] + '/columns', d);
          created.push(title + ' → ' + d.displayName);
        }
      }
    }
    ids.lists = have;
    return { created };
  }
}
