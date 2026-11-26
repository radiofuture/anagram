/* Small shared helpers for widgets with host-owned asynchronous work. */
(function (global) {
  'use strict';
  function object(value, keys) {
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !keys.includes(key))) throw new Error('Invalid widget data.');
  }
  function text(value, max = 240) {
    if (typeof value !== 'string' || !value.trim() || value.length > max) throw new Error('Invalid widget text.');
    return value;
  }
  function identity(value, type, keys) {
    object(value, ['id', 'version', 'type', ...keys]);
    if (typeof value.id !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(value.id) || !Number.isSafeInteger(value.version) || value.version < 1 || value.type !== type) throw new Error('Invalid widget identity.');
  }
  function el(tag, className, value) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined) node.textContent = value;
    return node;
  }
  function scope() {
    const controller = new AbortController();
    return { listen: (node, type, callback) => node.addEventListener(type, callback, { signal: controller.signal }), destroy: () => controller.abort() };
  }
  let serial = 0;
  global.RadiofutureWidgetSupport = Object.freeze({ object, text, identity, el, scope, uid: () => `rf-host-${++serial}` });
})(window);
