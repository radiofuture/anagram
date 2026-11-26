// Ask (slot `home.ask`): the first thing on Home. One field over
// the library of the person and the labs whose space this computer can read.
// A question opens the Ask screen (`#/ask`), where the answer arrives; Back
// comes home. The parts are in parts/ask.js.
import { html, useState } from '../core/html.js';
import { optional } from '../core/resource.js';
import { href, navigate } from '../core/router.js';
import { provide } from '../core/slots.js';
import { ALL, AskForm, Examples, useAskSetup } from '../parts/ask.js';

function Ask() {
  const info = optional(useAskSetup());
  const [question, setQuestion] = useState('');
  const [space, setSpace] = useState(ALL);
  if (!info) return null;
  const go = (text, where) => {
    const q = (text || '').trim();
    if (!q) return;
    navigate(href('ask', {}, where && where !== ALL ? { q, space: where } : { q }));
  };
  return html`
    <div class="ag-ask">
      <${AskForm} info=${info} question=${question} setQuestion=${setQuestion} space=${space}
        setSpace=${setSpace} onSubmit=${go} hideLabel=${true} />
      <${Examples} info=${info} onPick=${(x) => go(x, space)} />
    </div>`;
}

provide(['home', 'ask'].join('.'), { order: 10, View: Ask });
