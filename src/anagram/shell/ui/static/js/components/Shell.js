// The frame of the product: the rail with the stable destinations, the work
// area, and the one sheet. Rail items never move. The lime edge moves from
// the old item to the new item (motion recipe T2).
import { html, useLayoutEffect, useRef } from '../core/html.js';
import { t } from '../core/copy.js';
import { store } from '../core/store.js';
import { href, isCurrent, navItems, route, screenOf } from '../core/router.js';
import { retryNow } from '../core/events.js';
import { SheetHost, Sheet, openSheet } from './Sheet.js';

function Brand() {
  return html`
    <a class="ag-brand" href="#/" aria-label=${t('common.brand_home')}>
      <svg class="ag-mark" viewBox="0 0 1232 90" aria-hidden="true" focusable="false">
        <path d="M7 90V7H225V90 M263 0V83H481V0 M519 90V7H969V90 M1007 90V7H1225V90"
          fill="none" stroke="currentColor" stroke-width="14" stroke-linejoin="miter" />
      </svg>
      <span class="ag-brand-name">${t('common.product')}</span>
    </a>`;
}

function NavList({ group, onGo }) {
  const items = navItems(group);
  if (!items.length) return null;
  return html`
    <ul class=${`ag-nav-list ag-nav-list--${group}`}>
      ${items.map(
        (s) => html`
        <li key=${s.id}>
          <a href=${href(s.id)} aria-current=${isCurrent(s.id) ? 'page' : undefined} onClick=${onGo}>${t(`${s.id}.nav`)}</a>
        </li>`,
      )}
    </ul>`;
}

// Below 760 px the rail is one row: the mark, the product name, and "Menu".
// The bar does not name the place: the title of the screen does that, and
// the menu marks the current item. The menu is the one sheet, with the same
// destinations in the same order.
function MenuView({ close, open }) {
  return html`
    <${Sheet} title=${t('common.menu_title')}>
      <nav class="ag-menu" aria-label=${t('common.nav_main')}>
        ${open && html`<${NavList} group="main" onGo=${() => close()} />`}
        ${open && html`<${NavList} group="foot" onGo=${() => close()} />`}
        ${
          !open &&
          html`
          <ul class="ag-nav-list ag-nav-list--foot">
            <li><a href=${href('privacy')} onClick=${() => close()}>${t('privacy.nav')}</a></li>
          </ul>`
        }
      </nav>
      <div class="rf-ui-actions">
        <button type="button" class="rf-ui-button rf-ui-button--secondary" onClick=${() => close()}>${t('common.close')}</button>
      </div>
    <//>`;
}

function PhoneBar({ open }) {
  return html`
    <div class="ag-phonebar">
      <button type="button" class="rf-ui-button rf-ui-button--secondary ag-menu-button"
        onClick=${() => openSheet(MenuView, { open })}>${t('common.menu')}</button>
    </div>`;
}

// The lime edge: one element that moves to the current item. The mark moves
// only between two places of the same layout. After a change of the layout
// (a resize, or the narrow layout), the old place has no meaning, so the
// mark goes to the new place with no motion.
function useNavMark(navRef, markRef) {
  const placed = useRef(null); // the nav size of the last place: 'width x height'
  const current = route.value ? route.value.id : null;
  const place = (motion) => {
    const nav = navRef.current;
    const mark = markRef.current;
    if (!nav || !mark) return;
    const link = nav.querySelector('a[aria-current="page"]');
    if (!link) {
      mark.dataset.on = 'false';
      placed.current = null;
      return;
    }
    const box = nav.getBoundingClientRect();
    const at = link.getBoundingClientRect();
    const size = `${box.width}x${box.height}`;
    // The first place has no motion: the mark does not fly in.
    mark.dataset.move = motion && placed.current === size ? 'true' : 'false';
    mark.style.setProperty('--ag-mark-x', `${at.left - box.left}px`);
    mark.style.setProperty('--ag-mark-y', `${at.top - box.top}px`);
    mark.style.setProperty('--ag-mark-w', `${at.width}px`);
    mark.style.setProperty('--ag-mark-h', `${at.height}px`);
    mark.dataset.on = 'true';
    placed.current = size;
  };
  useLayoutEffect(() => {
    place(true);
  }, [current, store.overview.value]);
  // One observer for the life of the shell: a new observer on each route
  // change gives a first callback that stops the motion of the route change.
  useLayoutEffect(() => {
    const nav = navRef.current;
    if (!nav || typeof ResizeObserver !== 'function') return undefined;
    const watch = new ResizeObserver(() => place(false));
    watch.observe(nav);
    return () => watch.disconnect();
  }, []);
}

function Connection() {
  const notice = store.notice.value;
  if (!notice) return null;
  return html`
    <p class="ag-conn" role="status">
      <span>${t(notice === 'down' ? 'common.conn_down' : 'common.conn_retrying')}</span>
      ${
        notice === 'down' &&
        html`
        <button type="button" class="ag-link" onClick=${retryNow}>${t('common.try_again')}</button>`
      }
    </p>`;
}

export function Shell() {
  const ov = store.overview.value;
  const at = route.value;
  const screen = at ? screenOf(at.id) : null;
  const navRef = useRef(null);
  const markRef = useRef(null);
  useNavMark(navRef, markRef);
  const open = Boolean(ov?.joined && ov.setup_done);
  const View = screen ? screen.View : null;
  // The work area enters after a screen change (recipe T1), not at the first
  // paint. With a title that moves from its row (T3, 'in'), the title is not
  // part of the entrance. Back into a list (T3, 'back') has only the title move.
  const enter = at?.from && at.flight !== 'back' ? ' ag-m-enter' : '';
  const skip = (e) => {
    e.preventDefault();
    document.getElementById('main').focus();
  };
  return html`
    <a class="ag-skip" href="#main" onClick=${skip}>${t('common.skip')}</a>
    <div class="ag-shell">
      <header class="ag-rail">
        <div class="ag-rail-inner">
          <${Brand} />
          ${ov?.community && html`<p class="ag-community">${ov.community}</p>`}
          <nav class="ag-nav" aria-label=${t('common.nav_main')} ref=${navRef}>
            ${open && html`<${NavList} group="main" />`}
            ${open && html`<${NavList} group="foot" />`}
            ${
              !open &&
              html`
              <ul class="ag-nav-list ag-nav-list--foot">
                <li><a href=${href('privacy')} aria-current=${isCurrent('privacy') ? 'page' : undefined}>${t('privacy.nav')}</a></li>
              </ul>`
            }
            <span class="ag-nav-mark" aria-hidden="true" ref=${markRef}></span>
          </nav>
          <${PhoneBar} open=${open} />
          <${Connection} />
        </div>
      </header>
      <main id="main" tabindex="-1">
        ${
          View &&
          html`
          <div class=${`ag-view${enter}`} data-flight=${(at.from && at.flight) || undefined} key=${`${at.id} ${JSON.stringify(at.params)}`}>
            <${View} params=${at.params} query=${at.query} />
          </div>`
        }
      </main>
    </div>
    <${SheetHost} />`;
}
