// One format for each kind of value in the whole product.
import { t } from './copy.js';

const MONTHS = [
  'january',
  'february',
  'march',
  'april',
  'may',
  'june',
  'july',
  'august',
  'september',
  'october',
  'november',
  'december',
];

/**
 * '16 November 2026'. A date with no time is a UTC day. A time (a read, a
 * share) shows the day of this computer, so that the day and the hour of
 * `fmtTime` agree, and a read late in the evening is not "tomorrow".
 */
export function fmtDate(iso) {
  if (!iso) return '';
  const day = iso.length === 10;
  const d = new Date(day ? `${iso}T00:00:00Z` : iso);
  if (Number.isNaN(d.getTime())) return iso;
  const [n, m, y] = day
    ? [d.getUTCDate(), d.getUTCMonth(), d.getUTCFullYear()]
    : [d.getDate(), d.getMonth(), d.getFullYear()];
  return `${n} ${t(`common.months.${MONTHS[m]}`)} ${y}`;
}

/** '16 November 2026, 11:08' in the time of this computer. Only when the hour matters. */
export function fmtTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n) => String(n).padStart(2, '0');
  return `${fmtDate(iso)}, ${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** '3 March 2026' or '3 March 2026 to 9 March 2026'. */
export function fmtRange(start, end) {
  if (!start) return '';
  return start === end || !end ? fmtDate(start) : t('common.range', { start: fmtDate(start), end: fmtDate(end) });
}

/**
 * Text that a converter or a model made, cleaned for the page: no HTML
 * comments, no tags, no markdown marks, no slide numbers.
 */
export function cleanText(text) {
  if (!text) return '';
  return String(text)
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<\/?[a-z][^>]*>/gi, ' ')
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/^\s{0,3}(#{1,6}|>|[-*+]|\d+\.)\s+/gm, '')
    .replace(/(\*\*|__|~~|`)/g, '')
    .replace(/(^|\s)[*_]([^*_\n]+)[*_](?=\s|[.,;:]|$)/g, '$1$2')
    .replace(/\|/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** A place on this computer with no absolute path: '~/labs/okafor'. */
export function homePath(path) {
  if (!path) return '';
  const clean = String(path).replace(/\\/g, '/').replace(/\/+$/, '');
  const home = clean.match(/^(?:\/Users|\/home)\/[^/]+(\/.*)?$/) || clean.match(/^[A-Za-z]:\/Users\/[^/]+(\/.*)?$/);
  if (home) return `~${home[1] || ''}`;
  const parts = clean.split('/').filter(Boolean);
  if (!clean.startsWith('/') && !/^[A-Za-z]:/.test(clean)) return clean;
  return parts.length > 2 ? `…/${parts.slice(-2).join('/')}` : `…/${parts.join('/')}`;
}

/**
 * The name of a source for a title. The label of today can be
 * 'folder /private/tmp/…/labs/okafor': the title is 'okafor' and the place
 * goes to Details. A later API gives `name` and `place`.
 */
export function sourceTitle(source) {
  if (source.name) return { title: source.name, place: source.place || '' };
  const label = String(source.label || '');
  const at = label.search(/(?:[A-Za-z]:)?[\\/]/);
  if (at < 0) return { title: label, place: '' };
  const path = label.slice(at).replace(/\\/g, '/').replace(/\/+$/, '');
  const name = path.split('/').filter(Boolean).pop() || label.slice(0, at).trim();
  return { title: name, place: homePath(path) };
}

/** A file name with no folder part. */
export function baseName(path) {
  return (
    String(path || '')
      .replace(/\\/g, '/')
      .split('/')
      .filter(Boolean)
      .pop() || ''
  );
}

// An email address that is safe in a mailto: link: one '@', a plain local
// part, and a domain of labels. No space, CR, LF, '?', '&', '%' or '#': each
// one could add a header (bcc=, cc=) or change the link. The address of a
// match comes from the app of another person, so it is untrusted.
const LOCAL = /^[A-Za-z0-9.!$'*+=^_`{|}~-]{1,64}$/;
const LABEL = '[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?';
const DOMAIN = new RegExp(`^(?=.{1,253}$)${LABEL}(?:\\.${LABEL})+$`);

/**
 * 'mailto:a@b.org?subject=…&body=…', or null for an address that fails the
 * check. The caller shows a refused address as text, with no link.
 */
export function mailtoHref(address, { subject, body } = {}) {
  if (typeof address !== 'string' || address.length > 254) return null;
  const parts = address.split('@');
  if (parts.length !== 2 || !LOCAL.test(parts[0]) || !DOMAIN.test(parts[1])) return null;
  const query = [
    subject ? `subject=${encodeURIComponent(subject)}` : null,
    body ? `body=${encodeURIComponent(body)}` : null,
  ].filter(Boolean);
  const to = `${encodeURIComponent(parts[0])}@${encodeURIComponent(parts[1])}`;
  return `mailto:${to}${query.length ? `?${query.join('&')}` : ''}`;
}
