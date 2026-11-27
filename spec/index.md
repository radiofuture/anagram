# Local index (`anagram.local.index`)

Status: v2 draft (2026-10-27). The committed formats are the version 1
formats of [formats.md](formats.md). This document adds no new
committed format. The index store, the documents, the facts, the vocabulary
files, and the drafts are local data. They can change without a new proof
format.

The local index runs on the user's device. It reads connected sources, makes
evidence records and stream checkpoints, converts files to documents, derives
meaning, and proposes draft findings and a draft matching profile. It never
sends index content to the node. The user confirms each commit and each
profile.

## 1. Pipeline

    Source --scan--> evidence (raw bytes) --> pending --> checkpoint (on a cadence)
                         |
                         +--> job: convert (Converter -> Document -> chunks, full-text)
                                 +--> job: enrich (Enricher -> facts)
                                 +--> job: embed  (Embedder -> vectors)

Rules:

1. The evidence is the raw bytes of the item. The scan commits the evidence
   opening and the pending root in one transaction, **before** any
   conversion. A checkpoint never waits for a conversion.
2. Each stage after the scan is a job (section 7). A job that fails waits and
   tries again. A failure in one item does not stop other items.
3. Meaning is keyed by **version**. A changed item gets a new version and new
   meaning. The meaning of the old version stays.
4. A file that no converter reads stays as evidence. It keeps its date proof.
   It goes into the **skipped report** with a reason and a fix.
5. Each stage has a plug-in registry (section 2). A plug-in that sends data
   off the device is a disclosure recipient (section 9).

## 2. Plug-in registries

`anagram.local.index.registry.Registry` holds the built-in plug-ins and loads more
from Python entry points:

| Stage | Entry point group | Built-ins | Contract |
| --- | --- | --- | --- |
| Source | `anagram.sources` | `folder`, `obsidian`, `git`, `zotero_file`, `zotero_web`, `orcid_works`, `github`, `gdrive`, `gmail`, `notion` | `connectors.base.Source` (v1), `connectors.sync.SyncSource` (v2) |
| Converter | `anagram.converters` | `markitdown`, `basic`, `obsidian`, `datalab` (stub) | `convert.base.Converter` |
| Enricher | `anagram.enrichers` | `chips`, `obsidian` | `enrich.Enricher` |

- The entry point name is the registry name. For a source, the name is its
  `kind`.
- A built-in name wins. An installed package cannot replace a built-in plug-in.
- A plug-in that does not load is logged and left out (`Registry.errors`). It
  does not stop the index.
- The registry order is the default order (built-ins first, then entry points
  by name).

### 2.1 Source contract

A source reads one place and yields evidence items. It does not commit,
convert, or change the source.

| Member | Meaning |
| --- | --- |
| `kind` (class) | the registry name; also `config()["kind"]` |
| `from_config(cfg, ctx)` (class method) | open the source from its stored config; `ctx` has `secret` (keystore) and `transport` (network) |
| `config()` | JSON with no secrets |
| `scan(known)` | yield each current `EvidenceItem`; `known` has the digest, size, mtime, and media type of the last scan |
| `describe()` | a short text for logs and the command line; it can hold the path |
| `discover(path)` (class method, optional) | `Suggestion`s of this kind in a local path |
| `own` (class, default true) | false: the items are the work of other people (the lab space source); briefs, drafts, and checkpoints leave them out |
| `after_scan(index, sid)` (optional) | work after a v1 scan, for example the links of a vault |

The **label** of a source is what the person sees. It is set when the source
is made (`local/sources/source_labels.py`): the last part of the path ("Lab notes"),
the kind and the account for a connected source ("Google Drive
(ana@lab.org)"), or the kind name. A label is never a path and never an
internal ID. `LocalIndex` gives a new label, when it opens the store, to each
source with an empty label or a label of the old form (`describe()`).

`connectors.discover(path)` asks each registered kind. For example a folder
gives "1 Folder, 2 Git repository, 1 Zotero library". The UI adds the folder
and its suggestions. The user can remove each one.

### 2.1b Source contract v2 (changes with a cursor)

A source with a `sync` method is a v2 source (`connectors/sync.py`,
`is_sync_source`). Contract v1 stays valid, and entry-point sources with only
`scan` still work. `sync_engine.SyncEngine` runs a v2 source; `LocalIndex`
keeps the v1 scan path for the others.

| Member | Meaning |
| --- | --- |
| `auth` (class) | `none`, `oauth`, or `api_key` |
| `refetchable` (class) | true: `fetch(key, extra)` can get the same bytes again, so the store can drop large bytes after conversion |
| `sync(ctx)` | yields `Upsert(item)`, `Delete(key, prefix=False)`, `Cursor(state)`, and `Note(phase, total, done, at, skipped)` |
| `choices(ctx, account, parent)` (class method) | what the person can include (Drive folders, Gmail labels, Notion pages) |
| `preview(ctx, cfg)` (class method) | `{"estimate", "of"}` for a choice |

`ctx` (`SyncContext`) has `state` (the stored cursor, `{}` on the first run),
`known(key)` (one indexed lookup), `known_keys(prefix)`, `deadline`, and
`stop()`.

Rules:

1. A source yields a `Cursor` after each page or batch of at most 200
   upserts. The engine writes the changes before a `Cursor` and the cursor in
   one transaction. A stop or a crash loses at most one batch, and the source
   reads it again.
2. `sync` is idempotent. An upsert with the digest of the current version
   changes nothing. A delete of an unknown key changes nothing.
3. The engine stops at the first `Cursor` after the time limit (45 seconds
   for one source in one helper cycle; the helper calls again soon) or after
   a pause or a removal was asked.
4. A source does not hold the full item list in memory; it uses `known`.
5. A fault that the person must see is a `SourceFault` with a code
   (`rate_limited`, `offline`, `quota`, `auth_expired`, `permission_lost`,
   `not_found`, `client_missing`, `cursor_expired`, `unknown`). The engine
   keeps the last cursor and stores the fault in `source_state`. Each other
   exception is `unknown`. A fault text holds no URL, no item name, and no
   token.
6. `scan()` of a v2 source raises `ConnectorError("use sync")`.

Accounts and tokens of v2 sources are in `local/sources/credentials.py`; the sign-in
is in `local/sources/oauth.py` (OAuth for an installed app: loopback redirect and PKCE). A source never
sees a token: it calls `credentials.request(account, method, url)`.

### 2.2 Media type

The folder source finds the media type from the **magic bytes** of the file
(`local/index/media.py`). The extension is the fallback.

| Magic bytes | Media type |
| --- | --- |
| `%PDF-` | `application/pdf` |
| PNG, JPEG, GIF, WebP, TIFF signatures | `image/*` |
| ZIP with `[Content_Types].xml` and `word/`, `ppt/`, or `xl/` | docx, pptx, xlsx |
| ZIP with `mimetype` = `application/epub+zip` (or OpenDocument) | epub (or ODF) |
| other ZIP | `application/zip` |
| OLE (`D0 CF 11 E0`) | `.doc`, `.xls`, `.ppt`, `.msg` by extension |
| `{\rtf`, gzip, `<!doctype html`, `<html` | rtf, gzip, html |
| no NUL byte in the first 4 KiB | the extension, else `text/plain` |
| other | a binary extension, else `application/octet-stream` |

The sniffer reads 4 KiB and, for a ZIP file, the names in the archive. An
unchanged file (same size and mtime) keeps the media type of the last scan.

## 3. Sources

| Source | Item | Key | Network |
| --- | --- | --- | --- |
| `folder` | each regular file | path relative to the root | none |
| `obsidian` | each note and `.canvas` file of a vault (frontmatter, tags, aliases, and links become facts and relations) | path relative to the vault | none |
| `git` | each commit reachable from `HEAD` (a record) | commit ID | none |
| `github` | each commit of each selected repository (a record) | `owner/name@sha` | GitHub API, after device-flow sign-in |
| `zotero_file` | each CSL-JSON item (a record) | CSL `id` | none |
| `zotero_web` | each library item (a record) | CSL `id` | Zotero Web API v3, user API key |
| `orcid_works` | each work summary (a record) | ORCID put-code | ORCID public API (sends the ORCID iD only) |
| `gdrive` (v2) | each file in the selected folders, My Drive, or shared drives; a Google Docs file as its export | Drive file ID | Google Drive API v3, OAuth `drive.readonly` |
| `gmail` (v2) | each message in the filter (default: threads that the member wrote in, 2 years, 20 000 items), and each attachment | `<thread id>/<message id>`, attachment `<message key>/a<n>` | Gmail API v1, OAuth `gmail.readonly` |
| `notion` (v2) | each page that the person selected in the Notion consent screen, and its child pages (a record) | Notion page ID | Notion API `2022-06-28`, OAuth of a public integration |

`github` is not in the UI. A Gmail source is private only: it cannot go to a
lab space. The text that other people wrote in a mail is third-party text
(section 5.5). A received message, its attachments, and a Drive file of
another owner are third-party text in full.

Rules:

- The folder source ignores `.git` internals, other VCS folders, OS junk
  (`.DS_Store`, `Thumbs.db`, `desktop.ini`, `._*`, `~$*`, `.~lock.*#`, trash
  and index folders), and symbolic links. It covers sync folders (Dropbox,
  Google Drive, OneDrive, Box) with no OAuth.
- A **record** item has exact evidence bytes: canonical JSON of
  `{"schema": "anagram.index.record.v1", "kind", "record", "text", "title", "prose"}`.
  The digest is over these bytes. The store keeps these bytes with the
  version, so a later conversion reads the same bytes.
- A Git commit record holds the Git commit ID and tree ID as labels and our
  own tree hash `tree_sha256 = SHA-256(canonical_json([[path, mode, sha256(blob)], ...]))`.
  So a proof does not depend on SHA-1. The source reads blobs of new commits
  only, through `git cat-file --batch`. It does not hash pack files.
- A repository can come from another person, and its `.git/config` can name
  programs (`core.fsmonitor`, `gpg.program` with `log.showSignature`, hooks).
  Each Git command gets fixed settings through `GIT_CONFIG_COUNT` (the
  priority of `git -c`) that turn these off, no global or system config, and
  no network protocols. The source uses only commands that read objects
  (`log`, `ls-tree`, `cat-file`), not the working tree or the index.
- API tokens (GitHub, Zotero) and OAuth tokens (Google, Notion) stay in the
  client keystore (`acct-<account id>` for an account). A source config never
  holds a token. An access token goes only to the API hosts of its provider.
- The space of a source (`source_state.space`) is `private` or
  `lab:<lab id>`. A private source is never refused. A lab space needs the
  lab policy (`client.lab_policy(lab_id).allows_source(kind)`); the policy
  binds the lab space only.
- API sources call the network only through a `Transport` (v1) or an
  `HttpTransport` (v2: HTTPS only, no redirect to another host). Tests use
  `FakeGitHub`, `FakeZotero`, `FakeOrcid`, `FakeGoogle`, and `FakeNotion`. No
  test uses the network.

### Change detection

A scan compares each item with the last scan:

- Same size and same mtime: the folder source keeps the last digest and does
  not read the file. A **full scan** (`scan(full=True)`, nightly in the
  helper) hashes each file again, so it also sees a change that keeps size
  and mtime.
- Different digest: the item is **changed**. It gets a new version.
- A key that is gone: the item is **removed**. Its records stay.

A v2 source does not list all items. It reads changes from a cursor that the
provider gives:

| Source | Live changes | Deletes | Reconcile |
| --- | --- | --- | --- |
| `gdrive` | `changes.list` from the stored page token | a removed or trashed file, or a file that left the selection | a new listing when the token expires or the selection changes |
| `gmail` | `history.list` from the stored history ID | `messagesDeleted`, trash, spam | a new query when the history ID expires (HTTP 404) or the filter changes |
| `notion` | search by edit time, newest first, to the last edit time seen | an archived or trashed page at once; an ID list each 24 hours | a new search after "Choose pages" |

An expired cursor (`cursor_expired`) is not shown to the person: the source
runs a reconcile, which deletes each known item that the provider no longer
gives.

## 4. Evidence and streams

Each new or changed item gets a version with a salted evidence record
(`anagram.evidence.v1`, formats.md section 5) with fields `content`,
`media_type`, `name`, `schema`, and `source` (the source kind). Its root goes
into the pending list of the source.

Each source is one stream. The stream ID is a random 16-byte value. A
checkpoint is `anagram.stream_checkpoint.v1` (formats.md section 8):

- `items_root` is the Merkle root over the pending evidence roots, in scan
  order. `item_count` is their number.
- `seq` counts from 0. `prev` is the root of the previous checkpoint.
  `start` is the number of items in all previous checkpoints.

Commit sequence (`anagram.local.index.commit.commit_stream_checkpoint`):

1. Build the fields and a salted opening. Sign the root with the device key.
2. Store the opening in the index store (committed at once). Lost salts make a
   proof worthless, so this step comes first.
3. Submit the public log entry (kind and hash only).
4. Check the checkpoint signature, cosignatures, inclusion, and consistency
   with the last seen checkpoint (the client's own checks).
5. Store the proof bundle and mark the versions with the checkpoint `seq`.
   `verify_bundle` checks it offline. The index also checks that `items_root`
   and `item_count` equal the stored item roots.

**Cadence.** `checkpoint_due(source, interval)` is true when the source has
pending items and the last checkpoint is older than the interval (or there is
none). The UI and the helper use one hour (`CHECKPOINT_INTERVAL`,
`CHECKPOINT_S`). So the first checkpoint of a new source is at once, and later
ones are at most hourly. A refresh does not make a checkpoint each time.

## 5. Conversion

A converter reads the evidence bytes of one version and returns a `Document`.
It never changes the evidence.

### 5.1 Converter contract

| Member | Meaning |
| --- | --- |
| `name`, `version` | the registry name; the version goes into each document |
| `external` | true: bytes leave the device (a disclosure recipient) |
| `recipient` | who reads the bytes (for the consent text) |
| `reads` | what it reads ("the files of the sources you turn it on for") |
| `paid` | true: a call costs money (needs an approved budget) |
| `cost` | `cheap` (standard library), `heavy` (local parser or model), `remote` |
| `accepts` | the media types it reads |
| `available()` | false if a package is missing or it is a stub |
| `convert(blob) -> Document` | raises `ConversionError` if the bytes do not read |

### 5.2 Document

| Field | Meaning |
| --- | --- |
| `markdown` | the owner's text as Markdown |
| `title` | a title, if the converter finds one |
| `blocks` | leaf kinds `heading`, `para`, `table`, `code`, `figure`, `caption`, `cell_range`, `image`; container kinds `slide`, `page`, `sheet`, `message`. Each block has an `anchor`, the `parent` container, a `span`, and `attrs` (data of the kind, for example `reply_to` of a message) |
| `meta` | metadata (for example image size, email headers) |
| `quoted` | third-party text, kept apart (section 5.5) |
| `prose` | false: do not look for need and offer cues (tables, code, bibliographies) |
| `converter`, `converter_version` | who made the document |
| `schema` | the document schema: 1 (before spans, anchors by position such as `para-3`) or 2 (spans, anchors by content). Old documents stay readable |

**Anchor (schema 2).** The identity of a block, not its place:
`<kind>-<first 8 hex of SHA-256 of the text>` (white space runs as one
space); for a container, the hash covers the kind and text of its children.
The next blocks of the same kind and text get `.2`, `.3`. An edit that
changes one block keeps the anchors of the other blocks (measured: 1.00 of the
unchanged blocks for markdown, docx, PDF, pptx, xlsx and email, against 0.04
to 0.30 with anchors by position; `tests/test_document_spans.py`). A
converter that makes its own blocks uses `content_anchors`. The reading copy
(a locked format, [vault.md](vault.md) section 14) does not change: it carries the
schema-1 form (`wire_blocks_v1`: five fields, anchors by position), so the
anchors by content and the spans stay on the device.

**Span.** The place of a block in the evidence file. A converter fills the
fields of its type:

| Field | Type |
| --- | --- |
| `page`, `bbox` | PDF, image: page (1-based); box (x0, y0, x1, y1) in points from the top left |
| `slide`, `shape` | pptx: slide number; shape ID or name |
| `sheet`, `cells` | xlsx, CSV: sheet name; cell range such as `A1:C9` |
| `message`, `part` | email: Message-ID; MIME part path such as `1.2` |
| `lines` | each block of Markdown: first and last line (1-based) of `markdown` |

`blocks_from_markdown` fills `lines`, `page` (from form feeds) and `slide`
(from slide comments). The other fields come from the converters.

### 5.3 Built-in converters

| Converter | Reads | Cost | Notes |
| --- | --- | --- | --- |
| `markitdown` | PDF, docx, pptx, xlsx, HTML, EPUB | heavy | Microsoft markitdown (MIT). The default for these types. Plug-ins off. It gets bytes only, never a URL. Slides become `<!-- Slide number: N -->` blocks. |
| `basic` | text, Markdown, code, CSV, TSV, pptx, docx, eml, PNG, JPEG, simple PDF, JSON, CSL-JSON, index records | cheap | today's standard-library extractors (section 5.4) |
| `datalab` | PDF, Office, images | remote | **stub only**. `available()` is false. External, paid, recipient "Datalab (datalab.to)". Not built until Datalab confirms in writing that it keeps no input. Never in tests. |

### 5.4 Router

`Router` picks the converter for one blob:

1. the converters that the user prefers for the source (`prefs.prefer`),
2. then the local converters, in registry order (`markitdown` before `basic`),
3. then the external converters, only if the user opted in for this source
   (`prefs.allow_external`).

A preference is not an opt-in: an external converter is never a candidate
without the opt-in. The router calls `check_converter` before each external
call (defence in depth) and writes a `disclosure` row (time, recipient,
adapter, source). The first converter that gives a document wins. If it
raises `ConversionError`, the next one tries. The document records the
converter and its version.

If no converter gives a document, the job is `skipped` with a reason and a
fix:

| Reason | Fix |
| --- | --- |
| no converter reads `<type>` | the file stays as evidence; install a converter plug-in |
| only an outside converter reads `<type>` | turn on the named recipient for this source, if the user agrees |
| conversion failed (each converter's error) | open and save the file again, or export it as PDF |
| too large to convert (over 64 MiB) | the file stays as evidence |
| the file changed before conversion | none; the next scan converts the new version |

Before conversion, the index reads the file and checks its digest against the
version. So a document always describes the committed bytes.

The basic converter (standard library only):

| Format | Result |
| --- | --- |
| text, markdown | the text; the first line is the title |
| code files | the text, with no need or offer cues |
| CSV, TSV | the header and the first 5 rows, no cues |
| .pptx | slide text; the first shape of a slide becomes a heading |
| .docx | paragraph text; heading styles become headings |
| .eml | the plain body; quoted text is apart (section 5.5) |
| PNG | size and text chunks (`tEXt`, `zTXt`, `iTXt`) only |
| JPEG | size, comments, and an EXIF flag only |
| PDF | text from `Tj`, `TJ`, `'`, `"` operators in plain or Flate streams |
| CSL-JSON | titles, venues, abstracts, notes, tags; no cues |
| Git repository | README and the file list (for the newest commit) |

The Git source gives a repository summary (README and file list) with the
newest commit as a hint. The index adds it to the document of that commit.
The hint is derived meaning, not evidence.

### 5.5 Third-party text

In an email, lines that start with `>` go to `quoted`, and so does all text
from the first quote marker to the end: an attribution ("On ..., X wrote:",
also when it wraps onto more lines), a forwarded or original message marker,
"Begin forwarded message:", an Outlook underscore line, or a header block
("From:" with "Sent:", "To:", or "Subject:"). After a marker, no line is own
text again (fail closed). In an own message, a subject with "Re:" or "Fwd:"
is quoted too.

A message is own only when the source says so (Gmail label `SENT`) or when
its sender is in the owner's addresses. Each other message (also with no
known address or no sender) is third-party: the subject and the whole body
are `quoted`, and it has no title.

A full item that another person wrote has `extra.third_party` from its
source: a received Gmail message and its attachments, and a Drive file whose
owners do not include the member (or any file with owners when the member's
address is not known). Its name is neutral ("Received mail, <date>",
"Attachment <n> of received mail, <date>", "Shared file, <date>"). The
converter puts all its text in `quoted` (`local/understanding/third_party.py`), with no
external converter. `items(own_only=True)`, the timeline, the lab space, and
MCP `read_item` leave it out.

Quoted text is never chunked, embedded, or used for facts,
chips, claims, or a drafter. A draft with such evidence has
`third_party = true` and lists the items in `third_party_keys`.
`approve_finding` gives these flags to `Client.findings.commit_finding(third_party=...)`,
so a grant or a publish of the finding needs an explicit acknowledgement
(`ThirdPartyWarning`).

## 6. Enrichers and facts

An enricher reads a document (`markdown` only, never `quoted`) and returns
facts. A fact is `(kind, value, score, data)` for one version, with the
enricher name and version, the `span` it came from, and the `extractor`
(`converter@version` of the document). The span is JSON: the `anchor` and
`parent` of a block and the fields of its `Span`. An enricher can give the
span; else the index uses the first leaf block that holds the value (case
and white space do not matter). `summary` and `kind` facts have no span.

| Fact kind | Meaning |
| --- | --- |
| `topic`, `need`, `offer` | vocabulary IDs with a score |
| `phrase` | a topic phrase hit (for topic selection) |
| `summary` | a short summary (title and the first text) |
| `kind` | the item kind (`anagram.item_kind.v1`), with `data.by` and a confidence |
| `title` | a short phrase for people, in the words of the item; never a path |
| `entity`, `claim`, `person` | names, claims, and people from the owner's text (the `understand` stage) |

The built-in `chips` enricher is the keyword fallback (sections 11 and 12). It
writes `topic`, `need`, `offer`, `phrase`, and `summary` facts.
`LocalIndex.meaning()` builds the chips from these facts, so profile and
finding drafts work with no model. An external enricher needs the same opt-in
as an external converter.

The `kind_rules` enricher (no model) runs next to `chips` and writes one
`kind` and one `title` fact for each version. A new version of a prose item
can then get an `understand` job (section 7.1): a model writes `kind`,
`title`, `claim`, `entity`, `person`, and `summary` facts with the enricher
name `understand`. A new run of the enrichers keeps the `understand` facts.
The kind taxonomy, the passes, the prompts, and the grounding rules are in
[understanding.md](understanding.md).

## 7. Jobs and the background helper

### 7.1 Job queue

One `job` row for each stage and version: `convert`, `enrich`, `embed`, and
`understand` (the model stage; `understanding.md` section 4). The helper runs
`understand` jobs after the other stages, newest version first. With no model
an `understand` job ends `skipped` with a reason.

| State | Meaning |
| --- | --- |
| `queued` | waits until `next_at` |
| `running` | claimed (atomic, `BEGIN IMMEDIATE`) |
| `done` | finished |
| `skipped` | no converter (reason and fix) |
| `failed` | 5 failed attempts |

A failed attempt goes back to `queued` with backoff `min(6 h, 30 s × 2^(n-1))`.
The error is logged (`anagram.local.index`) and kept in the job row. A `running` job
of a stopped process goes back to `queued` when the helper starts (its first
cycle), if the job is older than 10 minutes. Embed jobs wait while there is no
embedder.

`LocalIndex.scan(process=True)` (the default) runs all ready jobs after the
scan. The helper and the UI use `scan(process=False)` and then run jobs in
batches.

### 7.2 Background helper (`anagram indexer`)

The helper runs the pipeline with no UI:

- **Watch:** folder, Git, and Zotero export sources with `watchdog`. An event
  marks the source. The helper scans it after 5 seconds with no new events.
- **Poll:** a scan of all sources each 15 minutes (`--poll`).
- **Nightly:** one full scan each day after 03:00 local time.
- **Jobs:** batches of 20, so the UI can use the index between batches.
- **Checkpoints:** when `checkpoint_due(source, 1 h)`.
- **Status:** the `status` table, key `indexer`: start time, last cycle, next
  poll, last full scan, number of watched paths, the last 20 errors, and for
  each source: total items, indexed items, converting, the skipped list (with
  reasons), last change, errors. A heartbeat each minute.
- **Errors:** each error is logged to `<home>/logs/indexer.log` and kept in the
  status. The loop goes on.
- One helper for each data directory (`<home>/indexer.lock`).
- `--once` does one scan and all jobs, then stops. `--no-embed` turns off
  embeddings (no model download). `--no-watch` polls only.

The UI shows the progress counts and the skipped list in Sources. When a
helper status is less than 3 minutes old, the UI does not scan in its own
background thread and does not run jobs in a refresh. Install as a login item
(launchd, systemd) is a later step.

## 8. Search and embeddings

- Chunks: the blocks of a document in runs of at most 1,200 characters. A
  heading, slide, or page starts a chunk. A chunk keeps the anchor of its
  first block (for example `slide-2/para-1`).
- Full text: FTS5 (`porter unicode61`), BM25 rank.
- Vectors: sqlite-vec `vec0` table, cosine distance. One embedder at a time:
  the store records its ident (model and size). A new embedder drops the old
  vectors and queues new embed jobs.
- Retrieval store port: `store_port.RetrievalStore`
  (`upsert`, `delete`, `vector_search`, `text_search`, `count`, `close`) with
  a typed `Filter`. The index uses it as `LocalIndex.retrieval`; the adapter
  `vec_store.SqliteVecStore` is the `vec0` and FTS5 code above, with no
  change. An adapter refuses a filter field that it cannot apply. Fusion
  stays above the port, in `retrieve.py`.
- `LocalIndex.search(query, k)` merges the text rank and the vector rank by
  reciprocal rank fusion (k = 60). It returns the current versions of present
  items only, unless `all_versions=True`.
- `FastEmbedder`: fastembed (ONNX Runtime, no torch), model
  `BAAI/bge-small-en-v1.5` (384 values). The model downloads on first use into
  `<home>/models/`. The download sends no user data. Text never leaves the
  device. Tests use `FakeEmbedder` (hashed words). No test downloads a model.
- Scope: `retrieve.search(index, query, scope=...)` gives hits only of the
  spaces in `scope` (a set of `private` and `lab:<lab id>`). The filter is in
  SQL. `LocalIndex.search` uses the same fusion.
- Text that other people wrote (quoted mail, received messages) is in
  separate tables (`context_chunk`, `context_fts`). It is full-text only, is
  found only in a private scope, and has `third_party = True`. A caller that
  must not see it passes `context=False`. Details: `understanding.md`
  section 6.

## 9. Disclosure rules

This follows the disclosure recipient pattern
([docs/design/disclosure-recipient.md](../docs/design/disclosure-recipient.md)):

1. Each converter, enricher, and drafter declares `external`, `recipient`,
   and `paid`. The defaults are local.
2. The index refuses an external converter or enricher unless the user opted
   in **for that source** (`set_source_prefs(sid, allow_external=[...])`).
   The default is off. A preference is not an opt-in.
3. A paid adapter also needs an approved budget in config. A paid model runs
   only inside the spend gate `Gate` (`understanding.md` section 3.3).
4. Each external call writes a `disclosure` row: time, recipient, adapter,
   what, source.
5. Tests use local fakes only (`FakeRemote` in tests, `FakeEmbedder`,
   `FakeModelDrafter`). The Datalab stub is never available.
6. Output of an external adapter is derived meaning (a document or facts),
   never a commit.
7. A model profile is a disclosure recipient with the opt-in key
   `model:<profile id>`. A lab-space source also needs the lab to allow the
   recipient. The person's AI assistant (MCP) gets a `disclosure` row with
   adapter `mcp` for each source that a result read (`understanding.md`
   section 9).

## 10. Index store

All index data is in one file, `<home>/index.sqlite`, encrypted with
**SQLCipher 4** (`sqlcipher3` wheels, SQLite 3.53 with FTS5; sqlite-vec loads
as an extension):

    db_key = HMAC-SHA256(index_key, "anagram.index.sqlcipher.v1")
    PRAGMA key = "x'<db_key hex>'"      (a raw key: no passphrase derivation)

- SQLCipher encrypts each page with AES-256-CBC and checks it with
  HMAC-SHA512. A wrong key or a changed page fails (`IndexStoreError`).
- The file has no plaintext header, table name, path, name, title, chip, or
  text. The FTS5 and vector tables are pages in the same encrypted file.
- The rollback journal is encrypted too. The store does not use WAL. A closed
  store is one file, so a backup can copy it as opaque bytes.
- SQLCipher does not encrypt SQLite temp files (sorts, temp tables, VACUUM).
  The store sets `PRAGMA temp_store = MEMORY`, so none is written. A test
  (`tests/test_index_plaintext_scan.py`) scans the store folder, the OS temp
  folders, and the files open during a load for canary words and vector
  bytes.
- Page cache: `PRAGMA cache_size` = 512 MB (`store.CACHE_MB`). SQLCipher
  keeps decrypted pages only in this cache; with the 8 MB default each
  vector search decrypts all vector pages again (10k chunks: 54 ms against
  6 ms). Only pages that are read use RAM: about 160 to 250 MB for a box of
  100k chunks, at most 512 MB for each open connection.
- The index key is `index-key` in the client keystore.

Tables (schema version 2):

| Table | Holds |
| --- | --- |
| `meta` | schema version, embedder ident, migration note |
| `source` | ID (= stream ID), kind, label, config, stream state (`seq`, `prev`, `start`, `last_checkpoint_at`), `prefs` (converter preference and opt-ins), last scan, last change, last error |
| `item` | one row for each source key: kind, name, media type, ref, path, mtime, time, current digest, present |
| `version` | one row for each content version: digest, media type, evidence root, opening (salts), `checkpoint_seq` (NULL = pending), record bytes, source hints |
| `checkpoint` | seq, root, opening (salts), item roots, proof bundle |
| `document` | one for each version: the `Document`, with its `schema` |
| `chunk`, `chunk_fts`, `chunk_vec` | chunks, full-text index (external content, triggers), vectors |
| `fact` | facts for each version, with enricher and version, `span` (JSON) and `extractor` (`converter@version`) |
| `relation` | `version_of`, `same_project`, `duplicate_of`; `includes`, `builds_on`, `cites` (reserved for enrichers) |
| `finding_ref` | committed finding root -> versions |
| `job` | the job queue (section 7.1) |
| `disclosure` | external calls (section 9) |
| `status` | the helper status |
| `account` | one row for each connected account of a provider: provider, the ID and label at the provider, OAuth client, granted scopes, status. No token: a token is only in the keystore. |
| `source_state` | one row for each source: account, space (`private` or `lab:<lab id>`), status, pause flag, cursor (contract v2), progress, last fault, time of the next try. `source_state.ensure` makes the row on first read, so a store from before these tables needs no migration. |
| `source_event` | the last 2 000 source events (`source.*`, `account.state`, `oauth.flow`): time, topic, JSON data. No secret and no item text. The local UI reads the rows and sends them on its event stream. |

Structural relations (no content needed):

- `version_of`: `version:<new>` -> `version:<previous>` of the same item.
- `same_project`: `item:<id>` -> `project:git:<repo path>` (Git commits, and
  files in the folder of a repository) or `project:folder:<top folder>`.
- `duplicate_of`: `item:<id>` -> `item:<first>` when another present item has
  the same content digest (also across sources).

Meaning is never committed and never leaves the device.

Columns added after version 2 (`ADDED_COLUMNS` in `store.py`):
`document.schema` (default 1), `fact.span`, `fact.extractor`. `IndexStore`
adds a missing column when it opens a store, so the schema version stays 2
and an old store needs no copy. Old rows read as before.

### 10.1 Migration from version 1

The version 1 store (`rows(ns, name, nonce, ct)`, each value sealed with
ChaCha20-Poly1305 under the index key, keyed-hash row names) migrates when
`LocalIndex` opens it:

1. Write a new store to `index.sqlite.migrating`.
2. Copy sources, items, all versions with their openings, checkpoints with
   bundles, and the pending list (in the same order).
3. The stored meaning of each current version becomes a `basic` document,
   chunks, and `chips` facts. Embed jobs wait. Old versions had no stored
   meaning.
4. Rename the old file to `index.sqlite.v1` (it stays sealed with the same
   key) and move the new file in place. A failure leaves the old file as it
   was.

## 11. Vocabulary

Bundled files in `src/anagram/local/understanding/vocab/`:

| File | Contents | Licence |
| --- | --- | --- |
| `openalex-topics-2026-10-15.json.gz` | all 4,516 OpenAlex Topics: ID, name, keywords, field | CC0 (OpenAlex) |
| `capabilities-v1.json` | 56 curated needs and offers, with phrases | MIT (this repo) |
| `topic-aliases-v1.json` | extra phrases for some topics (for example "cryo-EM") | MIT |

- Topic IDs: `openalex:t<number>`. Need and offer IDs: `anagram:<slug>`. One
  ID is both a need and an offer.
- The room refuses `/` in a chip ID (`CHIP_PATTERN`). So the IDs use `:` and
  `-`, not `anagram:need/...`.
- Version: `VOCAB_VERSION = "anagram-vocab.1.oa-20261015"`. It goes into the
  `vocab` field of each profile. Profiles with different versions never match.
  Aliases add phrases, not IDs, so they do not change the version.
- Remake the snapshot (maintainers only; this is the only OpenAlex call, and it
  sends no private data):
  `uv run python -m anagram.local.understanding.vocab_build src/anagram/local/understanding/vocab --date YYYY-MM-DD`.
- Users see labels only, never IDs.

## 12. Chips

Deterministic phrase matching (`anagram.local.understanding.chips`):

1. Normalise: lower case, each run of other characters becomes one space.
   Phrases match as whole words.
2. Split the owner's text into units (sentences and bullets). A heading with
   "need", "gaps", "asks", "blocks us" makes a need section. A heading with
   "offer", "assets", "resources", "available" makes an offer section.
3. Polarity of a unit, first match wins: strong offer cue ("we can offer",
   "can provide", "we can host", "free for"); need cue ("we need", "needs",
   "looking for", "we have no", "no way to", "cannot", "want"); the section;
   weak offer cue ("we have", "idle", "unused", "spare", "free").
4. A capability phrase in a unit with a polarity gives one need or offer hit.
   Text that is not prose (tables, bibliographies, image metadata) gives no
   needs or offers.
5. Topics: each item keeps its topic phrase hits (whole words, at most twice
   for each phrase). A one-word OpenAlex keyword counts only if it looks like
   a name or an acronym; an acronym (for example "NOTES") must match its exact
   form. "cryo" in "cryo-EM" is the word "cryo", never a part of a longer word.
6. Topic selection (`select_topics`, over the hits of one finding draft or of
   all items for a profile):
   - Phrase weight = hits × word count × vocabulary weight. The vocabulary
     weight is the mean inverse topic frequency of the phrase words
     (`log(N / topics with the word)`), divided by `log(N)`. Generic words
     ("data", "model", "analysis", "network", "tracking") weigh less.
   - Evidence: a topic needs two distinct phrases, or one curated phrase (the
     topic name or a hand-made alias), or one phrase of 3 or more words. One
     two-word OpenAlex keyword alone ("ice thickness", "particle filter") is
     not enough.
   - Relative score: at least 0.25 of the best topic.
   - Field agreement: the OpenAlex field of the topic must have 0.25 or more
     of the phrase weight of all candidates (each phrase counts once for each
     field). A topic in another field needs two distinct phrases and 0.5 of
     the best score.

A finding draft: top 3 topics with score 1 or more. (The chip profile draft
is removed.) A migrated record from before phrase hits gets its chips again from the
stored text.

The `chips` enricher writes these hits as facts (section 6). Embeddings are
for search (section 8), not for chips.

## 13. Drafts and approval

- `proposals.propose_findings(index)` gives the proposed findings from the
  kinds and the links of the items (`understanding.md` section 5). With no
  seed item it uses the folder fallback below. A proposal has a state (`new`,
  `later`, `dismissed`, `stamped`). Nothing stamps a finding without the
  person.
- `draft_findings(index)` groups evidence by source and folder (a Git
  repository's commits form one group), splits a group at a 14-day gap, and
  suggests a one-line claim from the owner's text only. Reference items
  (Zotero, ORCID works) do not go into finding drafts.
- `approve_finding(client, draft, claim=...)` commits through
  `Client.findings.commit_finding`. The claim is what the caller passes. The suggestion
  is never used on its own.
- The chip profile draft (`draft_profile`, `approve_profile`) is removed.
  Matching uses the lines that the person approves, sealed in a pack
  ([pack.md](pack.md)).

## 14. Drafter (opt-in model provider)

`Drafter` is the interface for a model that proposes claims. The default is
`NullDrafter` (no model). A drafter with `external = True` sends text off the
device. It is a **disclosure recipient**: the UI must name `recipient` and say
"This provider reads the files you select for drafts". `draft_findings`
refuses an external drafter unless the caller passes `allow_external=True`.
An external drafter reads only the drafts whose IDs are in `select` (the
drafts that the user picks). Without `select`, it reads nothing. A drafter sees only the owner's text, never quoted third-party text.
`ProviderDrafter(model)` is the adapter over a `TextModel` of the model layer
(`src/anagram/models/`): `external` and `recipient` come from the model, the
texts go in as escaped JSON lines, the answer is one JSON object
(`{"claim"}`, at most 300 characters), and a fault, a refusal, or an empty
answer gives no claim (the deterministic claim is then used).
`FakeModelDrafter` is for tests. Matching never calls a drafter.
The model of the task `draft` comes from the model profiles
(`understanding.md` section 3.2).

## 15. Command line

- `anagram indexer` (`--once`, `--no-embed`, `--no-watch`, `--poll MIN`): the
  background helper (section 7.2).
- `python -m anagram.shell.cli.index` (`add-folder`, `add-git`, `add-zotero`,
  `add-orcid`, `sources`, `scan`, `checkpoint`,
  `draft-findings`, `search`, `skipped`). It uses the same data directory as
  `anagram`.

## 16. Real or fake

| Part | State |
| --- | --- |
| Folder, Git, Zotero file sources | Real |
| GitHub device flow and commit reader | Real code; tested only with `FakeGitHub` |
| Zotero Web API, ORCID public API | Real code; tested only with fakes |
| Source, converter, enricher registries with entry points | Real |
| Media type from magic bytes | Real |
| `markitdown` converter | Real (local) |
| `basic` converter | Real, standard library |
| `datalab` converter | Stub only (never available) |
| `chips` enricher (keyword fallback) | Real, deterministic |
| SQLCipher store, FTS5, sqlite-vec | Real |
| Migration from the version 1 store | Removed; no released store was version 1 |
| Job queue with backoff | Real |
| `FastEmbedder` (fastembed) | Real code; tests use `FakeEmbedder` |
| Background helper (`anagram indexer`) | Real; no login item install yet |
| OpenAlex Topics snapshot | Real (full list, fetched 2026-10-15) |
| Needs and offers list, topic aliases | Hand-made, version 1 |
| Stream checkpoints | Real, through the client and the node log |
| Drafter | `NullDrafter`, `ProviderDrafter` over the model layer, `FakeModelDrafter` |
