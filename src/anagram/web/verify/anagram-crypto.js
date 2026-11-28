// The content digest of a file, in the browser (spec/formats.md, the
// `anagram-chunked-sha256-v1` content digest; Python: crypto/chunked.py):
//
//   SHA-256(len(tag) || tag || u64(size) || u32(chunk_size) || MTH(chunks))
//
// MTH is the RFC 6962 Merkle tree hash with each chunk as one leaf. The file
// is read one chunk at a time, so a large file does not load in full. The
// file never leaves the browser. WebCrypto needs a secure context (HTTPS or
// localhost).
//
// Only what the verify page needs is here. A future guest reader can extend
// this module.

export const CONTENT_ALG = 'anagram-chunked-sha256-v1';
export const TAG_CONTENT = 'anagram/v1/content';
const MAX_CHUNK_SIZE = 1 << 26;

async function sha256(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const all = new Uint8Array(n);
  let at = 0;
  for (const p of parts) {
    all.set(p, at);
    at += p.length;
  }
  return new Uint8Array(await crypto.subtle.digest('SHA-256', all));
}

const ZERO = Uint8Array.of(0);
const ONE = Uint8Array.of(1);

export function leafHash(data) {
  return sha256(ZERO, data);
}
export function nodeHash(left, right) {
  return sha256(ONE, left, right);
}

/** RFC 6962 root over leaf hashes that come one at a time (crypto/merkle.py StreamingRoot). */
export class StreamingRoot {
  constructor() {
    this.stack = [];
  }

  async add(leaf) {
    this.stack.push([0, leaf]);
    while (this.stack.length >= 2 && this.stack[this.stack.length - 1][0] === this.stack[this.stack.length - 2][0]) {
      const [height, right] = this.stack.pop();
      const [, left] = this.stack.pop();
      this.stack.push([height + 1, await nodeHash(left, right)]);
    }
  }

  async root() {
    if (!this.stack.length) return sha256(new Uint8Array(0));
    let r = this.stack[this.stack.length - 1][1];
    for (let i = this.stack.length - 2; i >= 0; i -= 1) r = await nodeHash(this.stack[i][1], r);
    return r;
  }
}

function tagPrefix(tag) {
  const raw = new TextEncoder().encode(tag);
  return Uint8Array.of(raw.length, ...raw);
}

function u64(n) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n));
  return out;
}

function u32(n) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n);
  return out;
}

export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * The content digest of a Blob or File with a given chunk size.
 * `progress(done, total)` is called after each chunk (optional).
 * @returns {Promise<{alg: string, chunk_size: number, digest: string, size: number}>}
 */
export async function contentDigest(blob, chunkSize, progress) {
  if (!Number.isInteger(chunkSize) || chunkSize <= 0 || chunkSize > MAX_CHUNK_SIZE) {
    throw new Error('bad chunk size');
  }
  const tree = new StreamingRoot();
  for (let at = 0; at < blob.size; at += chunkSize) {
    const chunk = new Uint8Array(await blob.slice(at, at + chunkSize).arrayBuffer());
    await tree.add(await leafHash(chunk));
    if (progress) progress(Math.min(at + chunkSize, blob.size), blob.size);
  }
  const digest = await sha256(tagPrefix(TAG_CONTENT), u64(blob.size), u32(chunkSize), await tree.root());
  return { alg: CONTENT_ALG, chunk_size: chunkSize, digest: toHex(digest), size: blob.size };
}
