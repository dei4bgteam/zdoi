/* Настройки на ADM ЗДОИ4You – вътрешна система. Стойностите според средата идват от wrangler.toml и тайните на Worker-а. */

export const CFG = {
  TZ: 'Europe/Sofia',
  SESSION_MIN: 30, // по подразбиране; всеки избира в профила си от 30 минути до 3 часа
  SESSION_MAX: 180,
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

/* суперадминистраторът е администратор, който освен това управлява лицата и достъпа до тях */
export const ROLE_SUPER = 'Суперадминистратор';
export const ROLE_ADMIN = 'Администратор';
export const ROLE_STAFF = 'Служител';
export const ROLE_VIEW = 'Наблюдател';
export const ROLES = [ROLE_SUPER, ROLE_ADMIN, ROLE_STAFF, ROLE_VIEW];
export const ADMIN_ROLES = [ROLE_SUPER, ROLE_ADMIN];
export const isAdminRole = role => ADMIN_ROLES.includes(role);

/* продължителност на сесията без действие (минути), избира се в профила */
export const SESSION_CHOICES = [30, 45, 60, 90, 120, 150, 180];
export const sessionMinOf = u => { const n = Number(u && u.sessionMin); return SESSION_CHOICES.includes(n) ? n : CFG.SESSION_MIN; };

/* права; управлението на потребители е само за администраторите и не се отнема */
export const PERMS = ['casesAll', 'casesEdit', 'courts', 'addressees', 'departments', 'log'];
export const ROLE_PERMS = {
  [ROLE_SUPER]: PERMS,
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
