// Slots: a track adds a view to a screen of another track with no edit of
// that screen. The provider calls `provide` at module load. The host screen
// renders `<Slot name="finding.actions" props=${{ finding }} />`.
//
// Slot names: finding.actions, finding.sections, item.actions, home.ask, home.sections,
// account.sections, lab.sections, lab.settings, lab.matching, lab.models, source.kinds.
import { signal } from './html.js';

const slots = signal({}); // name -> [{ order, View, ...more }]

/** Add a view to a slot. `more` holds other fields that the host screen reads (source.kinds: id, label, AddView). */
export function provide(slot, { order = 100, View, ...more }) {
  const list = [...(slots.value[slot] || []), { order, View, ...more }].sort((a, b) => a.order - b.order);
  slots.value = { ...slots.value, [slot]: list };
}

/** The entries of a slot, in their order. */
export function provided(slot) {
  return slots.value[slot] || [];
}
