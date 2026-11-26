/* Stable, version-pinned widget entry points. Registration is trusted host code. */
(function (global) {
  'use strict';
  const entries = new Map();
  const versionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
  function key(reference) {
    if (!reference || typeof reference !== 'object' || Array.isArray(reference) || Object.keys(reference).some(field => !['id', 'version'].includes(field)) || typeof reference.id !== 'string' || !/^rf\.[a-z]+(?:-[a-z]+)*$/.test(reference.id) || typeof reference.version !== 'string' || !versionPattern.test(reference.version)) throw new Error('Invalid widget reference.');
    return `${reference.id}@${reference.version}`;
  }
  function entry(reference) {
    const item = entries.get(key(reference));
    if (!item) throw new Error(`Unsupported widget: ${reference.id}@${reference.version}`);
    return item;
  }
  function register(descriptor, implementation) {
    const id = key({ id: descriptor.id, version: descriptor.version });
    if (entries.has(id)) throw new Error(`Duplicate widget: ${id}`);
    if (typeof implementation?.validate !== 'function' || typeof implementation?.mount !== 'function') throw new Error('Widget needs validation and mount.');
    for (const field of ['name', 'description', 'definitionSchema', 'entry', 'docs', 'example', 'status']) {
      if (typeof descriptor[field] !== 'string' || !descriptor[field].trim()) throw new Error(`Missing widget metadata: ${field}`);
    }
    if (!['reference', 'product', 'deprecated'].includes(descriptor.status)) throw new Error('Invalid widget status.');
    entries.set(id, Object.freeze({ descriptor: Object.freeze({ ...descriptor }), validate: implementation.validate, mount: implementation.mount }));
  }
  function mount(reference, parent, definition, onChange = () => {}, options = {}) {
    const item = entry(reference);
    if (!parent || typeof parent.append !== 'function' || typeof onChange !== 'function') throw new Error('Invalid widget host.');
    const validated = item.validate(definition);
    const instance = item.mount(parent, validated, onChange, options);
    return Object.freeze({ ...instance, widget: Object.freeze({ id: item.descriptor.id, version: item.descriptor.version }) });
  }
  global.RadiofutureWidgets = Object.freeze({
    register,
    list: () => Object.freeze(Array.from(entries.values(), item => item.descriptor)),
    get: reference => entry(reference).descriptor,
    validate: (reference, definition) => entry(reference).validate(definition),
    mount,
  });
})(window);
