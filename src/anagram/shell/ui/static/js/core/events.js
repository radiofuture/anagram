// The one live stream: GET /api/events (Server-Sent Events). The page reads
// it with fetch, so that one reader gets each event type (EventSource has no
// listener for "all types"). After a break, the page connects again with
// Last-Event-ID and the server sends the events that the page did not get.
import { batch } from './html.js';
import { hooks } from './api.js';
import { store } from './store.js';

const listeners = new Set(); // { pattern, fn }
// Progress events for one key reach the page at most each 250 ms, always
// with the newest data (motion recipe P1: at most four changes each second).
const JOINED_MS = { 'source.progress': 250, 'job.progress': 250, 'understanding.progress': 250 };
const joined = new Map(); // type and key -> { timer, event, last }
const RETRY_MS = [500, 1000, 2000, 5000];

let controller = null;
let lastId = null;
let failures = 0;
let retryTimer = null;
let noticeTimer = null;
let started = false;
let onLive = null;
const live = new Promise((done) => {
  onLive = done;
});

/** Resolves at the first `hello`: from then on the page gets each event. */
export function ready(timeout = 2000) {
  return Promise.race([
    live,
    new Promise((done) => {
      setTimeout(done, timeout);
    }),
  ]);
}

function matches(pattern, event) {
  if (pattern === '*' || pattern === event.type) return true;
  return pattern.endsWith('.*') && event.topic === pattern.slice(0, -2);
}

/** Listen to events: 'source.progress', 'source.*', or '*'. Returns off(). */
export function on(pattern, fn) {
  const entry = { pattern, fn };
  listeners.add(entry);
  return () => listeners.delete(entry);
}

function deliver(event) {
  batch(() => {
    for (const { pattern, fn } of [...listeners]) {
      if (!matches(pattern, event)) continue;
      try {
        fn(event);
      } catch (err) {
        console.error(err);
      }
    }
  });
}

/** Give one event to the listeners. The stream calls this. */
export function dispatch(event) {
  const wait = JOINED_MS[event.type];
  if (!wait) {
    deliver(event);
    return;
  }
  const id = `${event.type} ${event.key}`;
  const slot = joined.get(id) || { timer: null, event: null, last: 0 };
  joined.set(id, slot);
  const now = Date.now();
  if (!slot.timer && now - slot.last >= wait) {
    slot.last = now;
    deliver(event);
    return;
  }
  slot.event = event;
  if (!slot.timer) {
    slot.timer = setTimeout(
      () => {
        slot.timer = null;
        slot.last = Date.now();
        deliver(slot.event);
      },
      Math.max(0, wait - (now - slot.last)),
    );
  }
}

function setConn(state) {
  store.conn.value = state;
  if (state === 'live' || state === 'connecting') {
    clearTimeout(noticeTimer);
    noticeTimer = null;
    store.notice.value = null;
  } else if (state === 'down') {
    clearTimeout(noticeTimer);
    noticeTimer = null;
    store.notice.value = 'down';
  } else if (store.notice.value === null && !noticeTimer) {
    // "Reconnecting" shows only after 3 s: a short break shows nothing.
    noticeTimer = setTimeout(() => {
      noticeTimer = null;
      if (store.conn.value === 'retrying') store.notice.value = 'retrying';
    }, 3000);
  }
}

function onFrame(type, text) {
  let event;
  try {
    event = JSON.parse(text);
  } catch {
    return;
  }
  if (!event || typeof event !== 'object') return;
  if (type === 'hello') {
    failures = 0;
    setConn('live');
    onLive();
    const id = event.data ? event.data.server_id : null;
    const before = store.serverId.value;
    store.serverId.value = id;
    // A different server: the page has no event of it. Load all data again.
    if (before !== null && before !== id) deliver({ type: 'resync', topic: 'resync', key: null, data: event.data });
    return;
  }
  dispatch(event);
}

async function read(body) {
  const reader = body.pipeThrough(new TextDecoderStream()).getReader();
  let buffer = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    buffer += value.replace(/\r\n?/g, '\n');
    let end = buffer.indexOf('\n\n');
    while (end >= 0) {
      const block = buffer.slice(0, end);
      buffer = buffer.slice(end + 2);
      let type = 'message';
      let id = null;
      const data = [];
      for (const line of block.split('\n')) {
        if (line.startsWith(':')) continue; // a keep-alive comment
        const at = line.indexOf(':');
        const name = at < 0 ? line : line.slice(0, at);
        const rest = at < 0 ? '' : line.slice(at + 1).replace(/^ /, '');
        if (name === 'event') type = rest;
        else if (name === 'id') id = rest;
        else if (name === 'data') data.push(rest);
      }
      if (id !== null && /^\d+$/.test(id)) lastId = id;
      if (data.length) onFrame(type, data.join('\n'));
      end = buffer.indexOf('\n\n');
    }
  }
}

async function open() {
  clearTimeout(retryTimer);
  const mine = new AbortController();
  controller = mine;
  try {
    const headers = { Accept: 'text/event-stream' };
    if (lastId !== null) headers['Last-Event-ID'] = lastId;
    const res = await fetch('/api/events', {
      headers,
      credentials: 'same-origin',
      cache: 'no-store',
      signal: mine.signal,
    });
    if (res.status === 401) {
      started = false;
      controller = null;
      if (hooks.launch) hooks.launch();
      return;
    }
    if (!res.ok || !res.body) throw new Error('no stream');
    await read(res.body);
  } catch {
    // The lines below handle each failure.
  }
  if (mine.signal.aborted || controller !== mine) return;
  controller = null;
  failures += 1;
  setConn(failures >= 3 ? 'down' : 'retrying');
  retryTimer = setTimeout(open, RETRY_MS[Math.min(failures, RETRY_MS.length) - 1]);
}

/** Open the stream. A second call does nothing. */
export function connect() {
  if (started) return;
  started = true;
  setConn('connecting');
  open();
}

/** "Try again" in the rail foot: connect now. */
export function retryNow() {
  if (controller) controller.abort();
  controller = null;
  started = true;
  open();
}

export function disconnect() {
  started = false;
  clearTimeout(retryTimer);
  if (controller) controller.abort();
  controller = null;
}

// Live values that more than one screen reads.
on('join.state', (e) => {
  store.live.join.value = e.data;
});
on('source.progress', (e) => {
  if (e.key) store.live.sources.value = { ...store.live.sources.value, [e.key]: e.data };
});
on('source.removed', (e) => {
  if (!e.key || !(e.key in store.live.sources.value)) return;
  const next = { ...store.live.sources.value };
  delete next[e.key];
  store.live.sources.value = next;
});
on('job.progress', (e) => {
  if (e.key) store.live.jobs.value = { ...store.live.jobs.value, [e.key]: e.data };
});
on('resync', () => {
  store.live.sources.value = {};
  store.live.jobs.value = {};
});
