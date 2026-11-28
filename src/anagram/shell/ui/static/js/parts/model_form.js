// The form that sets up one model. Two places use it:
// the model section of Account (`slots/models.js`, for one person) and the
// lab model (`slots/lab_models.js`, for a PI or an admin).
//
// The three places where a model runs, in this order: this computer
// (Ollama), the university (an OpenAI-compatible address), a cloud provider
// (Anthropic, OpenAI, OpenRouter). Each choice shows one plain line about
// what leaves this computer. A key goes to the keychain only (`onSubmit`
// gets it; the lab form has no key: each member types their own).
import { html, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { ActionButton, Check, CheckList, ChoiceGroup, ErrorLine, Field, TextInput } from '../components/index.js';

export const WHERE = ['local', 'university', 'cloud'];
export const CLOUD = ['anthropic', 'openai', 'openrouter'];
// Neutral starting values for each cloud provider; placeholders give examples.
const START = {
  anthropic: { model: '' },
  openai: { model: '' },
  openrouter: { model: '', route: 'anthropic' },
};

/** The place of Profile JSON (or of no profile: a model on each computer). */
export function whereOf(p) {
  if (!p || p.provider === 'ollama') return 'local';
  return p.provider === 'openai_compatible' ? 'university' : 'cloud';
}

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

const inDays = (n) => new Date(Date.now() + n * 864e5).toISOString().slice(0, 10);

/** The plain line about what leaves this computer, for one choice. */
function leaves(where, provider, lab, labText) {
  if (where === 'local') return t(lab ? 'models.leaves_local_lab' : 'models.leaves_local');
  const name = where === 'university' ? t('models.university_name') : t(`models.cloud_${provider}`);
  if (lab) return t(labText ? 'models.leaves_lab_text' : 'models.leaves_lab_private', { name });
  return t(where === 'cloud' ? 'models.leaves_cloud' : 'models.leaves_university', { name });
}

/**
 * @param {{ollama?: {available: boolean, models: string[]}, start?: object, lab?: boolean,
 *   labText?: boolean, budget?: boolean, onSubmit: (out) => Promise<void>, submitLabel: string,
 *   busyLabel: string, onLook?: () => Promise<void>, taken?: string[]}} props
 *   `onSubmit` gets `{profile: Profile JSON | null, key, budget: {budget_usd, expires} | null,
 *   lab_text}`. `budget`: ask for a spend limit with a cloud model. `taken`: the local
 *   models that the person has already.
 */
export function ModelForm({
  ollama,
  start,
  lab = false,
  labText = false,
  budget = false,
  sources = [],
  onSubmit,
  submitLabel,
  busyLabel,
  onLook,
  taken = [],
}) {
  const first = start || null;
  const [where, setWhere] = useState(whereOf(first));
  const [provider, setProvider] = useState(first && CLOUD.includes(first.provider) ? first.provider : 'anthropic');
  const [model, setModel] = useState(first && first.provider !== 'ollama' ? first.model : START.anthropic.model);
  const [address, setAddress] = useState(first?.base_url || '');
  const [uniModel, setUniModel] = useState(first && first.provider === 'openai_compatible' ? first.model : '');
  const [route, setRoute] = useState(first?.route?.length ? first.route.join(', ') : START.openrouter.route);
  const [prices, setPrices] = useState(first?.prices ? first.prices : ['', '']);
  const [key, setKey] = useState('');
  const [limit, setLimit] = useState('10');
  const [until, setUntil] = useState(inDays(90));
  const [text, setText] = useState(labText);
  const [allowSources, setAllowSources] = useState([]);
  // An embedding model cannot read or answer: it is not a choice.
  const installed = (ollama?.models || []).filter(
    (m) => !/embed/i.test(m) && !taken.includes(m.replace(/:latest$/, '')),
  );
  const [picked, setLocal] = useState('');
  const local = installed.includes(picked) ? picked : installed[0] || '';
  const [error, setError] = useState('');

  const pickProvider = (p) => {
    setProvider(p);
    setModel(START[p].model);
  };

  const profile = () => {
    if (where === 'local') {
      if (lab) return null;
      const name = (local || '').replace(/:latest$/, '');
      if (!name) throw new Error(t('models.local_pick'));
      return { provider: 'ollama', model: name, label: name };
    }
    if (where === 'university') {
      const m = uniModel.trim();
      return { provider: 'openai_compatible', model: m, label: hostOf(address.trim()) || m, base_url: address.trim() };
    }
    const out = { provider, model: model.trim(), label: model.trim() };
    if (provider === 'openrouter')
      out.route = route
        .split(',')
        .map((r) => r.trim())
        .filter(Boolean);
    if (provider === 'openai') out.prices = prices.map((x) => String(x).trim());
    return out;
  };

  const submit = async () => {
    const paid = where === 'cloud' && !lab && budget;
    await onSubmit({
      profile: profile(),
      key: lab ? null : key.trim() || null,
      budget: paid ? { budget_usd: limit.trim(), expires: until } : null,
      lab_text: text,
      allow_sources: where !== 'local' && !lab ? allowSources : [],
    });
    setKey('');
  };

  let fields = null;
  let ready = true;
  if (where === 'local' && !lab) {
    if (!ollama?.available || !installed.length) {
      ready = false;
      const none = !ollama?.available;
      fields = html`
        <p class="ag-model-note">${t(none ? 'models.ollama_none' : ollama.models.length ? 'models.ollama_all' : 'models.ollama_empty')}</p>
        ${
          onLook &&
          html`
          <div class="rf-ui-actions">
            <${ActionButton} kind="secondary" label=${t('models.look')} busyLabel=${t('models.looking')} run=${onLook} errorTo=${setError} />
          </div>`
        }`;
    } else if (installed.length > 1) {
      fields = html`
        <${Field} id="model-local" label=${t('models.local_model')}>
          <select class="rf-ui-input" id="model-local" value=${local} onChange=${(e) => setLocal(e.currentTarget.value)}>
            ${installed.map((m) => html`<option key=${m} value=${m}>${m.replace(/:latest$/, '')}</option>`)}
          </select>
        <//>`;
    } else {
      fields = html`<p class="ag-model-note">${t('models.local_one', { model: installed[0].replace(/:latest$/, '') })}</p>`;
    }
  } else if (where === 'university') {
    fields = html`
      <${Field} id="model-address" label=${t('models.address')} help=${t('models.address_help')}>
        <${TextInput} value=${address} onInput=${setAddress} type="url" inputmode="url" spellcheck=${false} autocomplete="off" />
      <//>
      <${Field} id="model-name" label=${t('models.model_name')}>
        <${TextInput} value=${uniModel} onInput=${setUniModel} spellcheck=${false} autocomplete="off" />
      <//>
      ${
        !lab &&
        html`
        <${Field} id="model-key" label=${t('models.key_optional')} help=${t('models.key_help')}>
          <${TextInput} value=${key} onInput=${setKey} type="password" spellcheck=${false} autocomplete="off" />
        <//>`
      }`;
  } else if (where === 'cloud') {
    fields = html`
      <${Field} id="model-provider" label=${t('models.provider')}>
        <select class="rf-ui-input" id="model-provider" value=${provider} onChange=${(e) => pickProvider(e.currentTarget.value)}>
          ${CLOUD.map((p) => html`<option key=${p} value=${p}>${t(`models.cloud_${p}`)}</option>`)}
        </select>
      <//>
      <${Field} id="model-cloud-name" label=${t('models.model_name')}>
        <${TextInput} value=${model} onInput=${setModel} placeholder=${t(`models.model_placeholder_${provider}`)}
          spellcheck=${false} autocomplete="off" />
      <//>
      ${
        provider === 'openrouter' &&
        html`
        <${Field} id="model-route" label=${t('models.route')} help=${t('models.route_help')}>
          <${TextInput} value=${route} onInput=${setRoute} spellcheck=${false} autocomplete="off" />
        <//>`
      }
      ${
        provider === 'openai' &&
        html`
        <div class="ag-model-pair">
          <${Field} id="model-price-in" label=${t('models.price_in')}>
            <${TextInput} value=${prices[0]} onInput=${(v) => setPrices([v, prices[1]])} inputmode="decimal" autocomplete="off" />
          <//>
          <${Field} id="model-price-out" label=${t('models.price_out')}>
            <${TextInput} value=${prices[1]} onInput=${(v) => setPrices([prices[0], v])} inputmode="decimal" autocomplete="off" />
          <//>
        </div>
        <p class="rf-ui-help">${t('models.prices_help')}</p>`
      }
      ${
        !lab &&
        html`
        <${Field} id="model-key" label=${t('models.key')} help=${t('models.key_help')}>
          <${TextInput} value=${key} onInput=${setKey} type="password" spellcheck=${false} autocomplete="off" />
        <//>`
      }
      ${
        !lab &&
        budget &&
        html`
        <div class="ag-model-pair">
          <${Field} id="model-limit" label=${t('models.limit')}>
            <${TextInput} value=${limit} onInput=${setLimit} inputmode="decimal" autocomplete="off" />
          <//>
          <${Field} id="model-until" label=${t('models.until')}>
            <${TextInput} value=${until} onInput=${setUntil} type="date" />
          <//>
        </div>`
      }`;
  }

  const options = WHERE.map((w) => ({
    value: w,
    label: t(`models.where_${w}${lab ? '_lab' : ''}`),
    help: t(`models.where_${w}_help${lab ? '_lab' : ''}`),
  }));
  return html`
    <div class="ag-model-form">
      <${ChoiceGroup} legend=${t('models.where')} name=${lab ? 'lab-model-where' : 'model-where'} value=${where}
        options=${options} onChange=${setWhere} />
      ${fields}
      ${
        !lab &&
        where !== 'local' &&
        sources.length > 0 &&
        html`
        <${CheckList} legend=${t('models.sources_add_legend')} name="model-new-sources" value=${allowSources}
          items=${sources.map((s) => ({ value: s.id, label: s.label }))} onChange=${setAllowSources} />`
      }
      ${
        lab &&
        where !== 'local' &&
        html`
        <${Check} id="lab-model-text" label=${t('models.lab_text')} checked=${text} onChange=${setText} />`
      }
      ${ready && html`<p class="ag-model-leaves">${leaves(where, provider, lab, text)}</p>`}
      <${ErrorLine} text=${error} />
      ${
        ready &&
        html`
        <div class="rf-ui-actions">
          <${ActionButton} label=${submitLabel} busyLabel=${busyLabel} run=${submit} errorTo=${setError} />
        </div>`
      }
    </div>`;
}
