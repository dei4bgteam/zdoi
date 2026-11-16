/* Настройки на ADM ЗДОИ4You – вътрешна система. Стойностите според средата идват от wrangler.toml и тайните на Worker-а. */

export const CFG = {
  TZ: 'Europe/Sofia',
  SESSION_MIN: 30,
  INVITE_DAYS: 7,
  RESET_HOURS: 2,
  MAX_FAILS: 5,
  MAX_IP_FAILS: 20,
  FAIL_WINDOW_S: 900,
  CODE_MIN: 5,
  MAX_BODY: 300000,
  MAX_BIG_BODY: 12 * 1048576,
  MAINTAINER: 'Вътрешна система на ЗДОИ4You.'
};

export const ROLE_ADMIN = 'Администратор';
export const ROLE_STAFF = 'Служител';
export const ROLE_VIEW = 'Наблюдател';
export const ROLES = [ROLE_ADMIN, ROLE_STAFF, ROLE_VIEW];

/* права; управлението на потребители е само за роля Администратор и не се отнема */
export const PERMS = ['casesAll', 'casesEdit', 'courts', 'addressees', 'departments', 'log'];
export const ROLE_PERMS = {
  [ROLE_ADMIN]: PERMS,
  [ROLE_STAFF]: ['casesAll', 'casesEdit', 'courts', 'addressees'],
  [ROLE_VIEW]: ['casesAll']
};

export function envCfg(env) {
  const appUrl = String(env.APP_URL || 'https://adm.zdoi.eu/').replace(/\/?$/, '/');
  return {
    appUrl,
    origin: appUrl.replace(/\/$/, ''),
    support: env.SUPPORT || 'support@zdoi.eu',
    appName: env.APP_NAME || 'ADM ЗДОИ4You'
  };
}
