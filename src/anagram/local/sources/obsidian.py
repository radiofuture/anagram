"""Obsidian vault source (`obsidian`, contract v1). Read-only.

A vault is a local folder that contains `.obsidian/`. A walk with the size
and mtime shortcut is cheap, so this source is a contract v1 source: it is a
`FolderConnector` with the rules of a vault.

- Each file is one item (key: the POSIX path relative to the vault root).
  Notes are `text/markdown`. Attachments (images, PDF, audio) are items too.
  A `.canvas` file is JSON; `ObsidianConverter` reads its text nodes.
- Ignored: `.obsidian/`, `.trash/`, the folders of the config key `exclude`,
  and all that the folder source ignores.
- Private notes: a note with the frontmatter key `anagram: false`, or with
  the tag `#private`, is not yielded. Anagram does not index it.
- A vault that is gone raises the fault `not_found`. It does not mark each
  item as removed.

Meaning (never committed, never off the device):

- `ObsidianConverter` (converter `obsidian`): takes the YAML frontmatter out
  of the note text and keeps it in `Document.meta["frontmatter"]`. The index
  prefers it for an `obsidian` source (`ObsidianConnector.default_prefs`).
- `ObsidianEnricher` (enricher `obsidian`, local): runs only for documents
  that `ObsidianConverter` made. It writes the facts `frontmatter` (one for
  each key), `tag`, `alias`, and `link`. YAML that does not parse gives one
  `frontmatter_error` fact and no failure.
- `resolve_links(index, sid)`: makes `links_to` and `embeds` relations from
  the `link` facts of the current versions, as Obsidian resolves a link:
  exact path, else a unique file name, else the shortest path. A link with no
  target stays a fact only.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import urllib.parse
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

import yaml

from anagram.core.crypto.chunked import ContentDigest, hash_file
from anagram.local.index import extract
from anagram.local.index.convert.base import CHEAP, Blob, ConversionError, Converter
from anagram.local.index.convert.document import Document, blocks_from_markdown
from anagram.local.index.enrich import EnrichContext, Enricher, Fact
from anagram.local.index.media import sniff_file
from anagram.local.index.store import dumps, loads
from anagram.local.sources.base import EvidenceItem, KnownItem, SourceContext, Suggestion
from anagram.local.sources.folder import IGNORED_DIRS, FolderConnector
from anagram.local.sources.http import SourceFault

if TYPE_CHECKING:
    from anagram.local.index.local import LocalIndex

VAULT_DIR = ".obsidian"
VAULT_IGNORED = frozenset({VAULT_DIR, ".trash"})
MARKDOWN = "text/markdown"
CANVAS = "application/x-obsidian-canvas+json"
NOTE_SUFFIXES = (".md", ".markdown")
CONVERTER = "obsidian"
PRIVATE_TAG = "private"
PRIVATE_KEY = "anagram"
DISCOVER_DEPTH = 4  # folder levels below a path in which `discover` looks for vaults
MAX_NOTE_BYTES = extract.MAX_TEXT_BYTES
LINKS_STATUS = "obsidian-links:"

_FRONTMATTER = re.compile(r"\A---[ \t]*\r?\n(.*?)\r?\n(?:---|\.\.\.)[ \t]*(?:\r?\n|\Z)", re.S)
_FENCE = re.compile(r"^(```|~~~).*?^\1[^\n]*$", re.S | re.M)
_INLINE_CODE = re.compile(r"`[^`\n]*`")
_TAG = re.compile(r"(?<![\w/#])#([\w/-]*[^\W\d][\w/-]*)")
_WIKILINK = re.compile(r"(!?)\[\[([^\[\]\n]+?)\]\]")
_MDLINK = re.compile(r"(!?)\[([^\]\n]*)\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")


def split_frontmatter(text: str) -> tuple[str | None, str]:
    """(the YAML text or None, the note body)."""
    m = _FRONTMATTER.match(text)
    if m is None:
        return None, text
    return m.group(1), text[m.end() :]


def parse_frontmatter(raw: str | None) -> dict:
    """The frontmatter as a mapping. Raise `yaml.YAMLError` or `ValueError`
    if it does not parse or is not a mapping. `safe_load` makes no objects."""
    if raw is None or not raw.strip():
        return {}
    data = yaml.safe_load(raw)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("frontmatter is not a mapping")
    return data


def _prose(body: str) -> str:
    """The body with no code blocks and no inline code."""
    return _INLINE_CODE.sub(" ", _FENCE.sub("\n", body))


def _list(value: object) -> list[str]:
    """A frontmatter value as a list of texts (`tags: a, b` or a YAML list)."""
    if value is None:
        return []
    if isinstance(value, str):
        return [p for p in re.split(r"[,\s]+", value) if p]
    if isinstance(value, list | tuple):
        return [str(v).strip() for v in value if v is not None and str(v).strip()]
    return [str(value)]


def _aliases(value: object) -> list[str]:
    if isinstance(value, str):
        return [p.strip() for p in value.split(",") if p.strip()]
    return _list(value)


def note_tags(front: Mapping, body: str) -> list[str]:
    """Tags of a note, in first-seen order, with no `#`. A tag is compared
    with no regard to case."""
    found = [t.lstrip("#") for key in ("tags", "tag") for t in _list(front.get(key))]
    # A heading part of a link (`[[Note#Part]]`, `(note.md#part)`) is no tag.
    text = _MDLINK.sub(lambda m: m.group(2), _WIKILINK.sub(" ", _prose(body)))
    found += [m.group(1).rstrip("/-") for m in _TAG.finditer(text)]
    out, seen = [], set()
    for tag in found:
        if tag and tag.lower() not in seen:
            seen.add(tag.lower())
            out.append(tag)
    return out


_BAD_YAML_PRIVATE = re.compile(
    r"(?im)^[ \t]*(?:anagram\s*:|tags?\s*:[^\n]*\bprivate\b|-\s*#?private\b)"
)
_PRIVATE_TAG_RE = re.compile(r"(?<![\w/#])#private(?![\w/-])", re.I)


def is_private(text: str) -> bool:
    """True for a note that the person keeps out of Anagram: frontmatter
    `anagram: false`, or the tag `#private`. Unparseable frontmatter that
    mentions `anagram:` or `private` fails closed."""
    raw, body = split_frontmatter(text)
    try:
        front = parse_frontmatter(raw)
    except (yaml.YAMLError, ValueError):
        if raw is not None and _BAD_YAML_PRIVATE.search(raw):
            return True
        front = {}
    if PRIVATE_KEY in front:
        val = front[PRIVATE_KEY]
        if val is False or (isinstance(val, str) and val.strip().lower() in ("false", "no", "off")):
            return True
    return any(t.lower() == PRIVATE_TAG for t in note_tags(front, body))


def _file_is_private(path: Path, size: int) -> bool:
    """Check `is_private` for any note size, including notes over `MAX_NOTE_BYTES`."""
    if size <= MAX_NOTE_BYTES:
        return is_private(extract.decode_text(path.read_bytes()))
    chunk_size = 1024 * 1024
    with path.open("rb") as fh:
        head = fh.read(MAX_NOTE_BYTES)
        if is_private(extract.decode_text(head)):
            return True
        tail = head[-64:]
        while True:
            buf = fh.read(chunk_size)
            if not buf:
                return False
            window = extract.decode_text(tail + buf)
            if _PRIVATE_TAG_RE.search(window):
                return True
            tail = buf[-64:]


def note_links(body: str) -> list[tuple[str, dict]]:
    """(target text, `{"alias", "embed", "heading"}`) for each wikilink,
    embed, and Markdown link to a local file, in text order."""
    text = _prose(body)
    found: list[tuple[int, str, dict]] = []
    for m in _WIKILINK.finditer(text):
        inner, _, alias = m.group(2).partition("|")
        target, _, heading = inner.partition("#")
        found.append((m.start(), target.strip(), _link(alias, bool(m.group(1)), heading)))
    for m in _MDLINK.finditer(text):
        url = m.group(3)
        if _SCHEME.match(url) or url.startswith(("#", "/")):
            continue  # a web link, a link inside the note, or a path outside the vault
        target, _, heading = urllib.parse.unquote(url).partition("#")
        if target:
            found.append((m.start(), target, _link(m.group(2), bool(m.group(1)), heading)))
    return [(target, data) for _, target, data in sorted(found, key=lambda f: f[0])]


def _link(alias: str, embed: bool, heading: str) -> dict:
    return {"alias": alias.strip() or None, "embed": embed, "heading": heading.strip() or None}


# ------------------------------------------------------------------ source


class ObsidianConnector(FolderConnector):
    kind = "obsidian"
    label = "Obsidian vault"
    # The index gives these source prefs to a new source of this kind.
    default_prefs: ClassVar[dict] = {"prefer": [CONVERTER]}

    @classmethod
    def from_config(cls, cfg: dict, ctx: SourceContext) -> ObsidianConnector:
        return cls(cfg["root"], exclude=cfg.get("exclude", ()))

    @classmethod
    def discover(cls, path: Path) -> list[Suggestion]:
        """The vaults in `path`: the path itself, or folders below it (to
        `DISCOVER_DEPTH` levels). The walk does not go into a vault."""
        p = Path(path).expanduser()
        if not p.is_dir():
            return []
        p = p.resolve()
        out = []
        for dirpath, dirnames, _ in os.walk(p, followlinks=False):
            here = Path(dirpath)
            if VAULT_DIR in dirnames:
                vault = cls(here)
                out.append(Suggestion(cls.kind, vault.describe(), vault.config()))
                dirnames[:] = []
                continue
            if len(here.relative_to(p).parts) >= DISCOVER_DEPTH:
                dirnames[:] = []
                continue
            dirnames[:] = sorted(
                d for d in dirnames if d not in IGNORED_DIRS and not d.startswith(".")
            )
        return out

    def __init__(
        self, root: str | Path, exclude: tuple[str, ...] | list[str] = (), chunk_size=None
    ) -> None:
        super().__init__(root, chunk_size, exclude=exclude, ignored_dirs=VAULT_IGNORED)

    def describe(self) -> str:
        return f"Obsidian vault {self.root.name}"

    def scan(self, known: Mapping[str, KnownItem]) -> Iterator[EvidenceItem]:
        if not self.root.is_dir():
            raise SourceFault("not_found", "the vault folder is gone")
        for p in self.files():
            rel = p.relative_to(self.root).as_posix()
            st = p.stat()
            prev = known.get(rel)
            same = prev is not None and prev.size == st.st_size and prev.mtime_ns == st.st_mtime_ns
            suffix = p.suffix.lower()
            if suffix in NOTE_SUFFIXES and not same:
                try:
                    if _file_is_private(p, st.st_size):
                        continue
                except OSError:
                    continue  # the file was gone before the read
            if same:
                digest = ContentDigest.from_json(prev.digest)
            else:
                digest = hash_file(p, self.chunk_size)
            if suffix == ".canvas":
                media_type = CANVAS
            elif same and prev.media_type:
                media_type = prev.media_type
            else:
                media_type = sniff_file(p)
            yield EvidenceItem(
                key=rel,
                kind="file",
                name=p.name,
                media_type=media_type,
                digest=digest,
                ref=rel,
                mtime_ns=st.st_mtime_ns,
                path=p,
            )

    def after_scan(self, index: LocalIndex, sid: str) -> None:
        resolve_links(index, sid)


# --------------------------------------------------------------- converter


class ObsidianConverter(Converter):
    """Notes and canvases of a vault, on this computer. The frontmatter goes
    into `meta`, so the note text has only what the person wrote as text."""

    name = CONVERTER
    version = "1"
    cost = CHEAP
    accepts = frozenset({MARKDOWN, CANVAS})

    def convert(self, blob: Blob) -> Document:
        if len(blob.data) > MAX_NOTE_BYTES:
            raise ConversionError(f"too large for a note ({len(blob.data)} bytes)")
        text = extract.decode_text(blob.data).replace("\r\n", "\n")
        stem = Path(blob.name).stem
        if blob.media_type == CANVAS:
            return self._canvas(text, stem)
        raw, body = split_frontmatter(text)
        title = None
        try:
            front_title = parse_frontmatter(raw).get("title")
            title = str(front_title).strip()[:200] if front_title else None
        except (yaml.YAMLError, ValueError):
            pass  # the enricher reports it
        body = body.strip("\n")
        return Document(
            markdown=body,
            title=title or stem,
            blocks=blocks_from_markdown(body),
            meta={"frontmatter": raw} if raw is not None else {},
            kind="markdown",
            prose=True,
        )

    def _canvas(self, text: str, stem: str) -> Document:
        try:
            canvas = json.loads(text)
            nodes = canvas.get("nodes", []) if isinstance(canvas, dict) else None
        except ValueError as exc:
            raise ConversionError("the canvas is not JSON") from exc
        if not isinstance(nodes, list):
            raise ConversionError("the canvas has no node list")
        parts = []
        for node in nodes:
            if not isinstance(node, dict):
                continue
            kind = node.get("type")
            if kind == "text" and isinstance(node.get("text"), str):
                parts.append(node["text"].strip())
            elif kind == "file" and isinstance(node.get("file"), str):
                parts.append(f"[[{node['file']}]]")
            elif kind == "link" and isinstance(node.get("url"), str):
                parts.append(node["url"])
            elif kind == "group" and isinstance(node.get("label"), str):
                parts.append(f"## {node['label'].strip()}")
        md = "\n\n".join(p for p in parts if p)
        return Document(
            markdown=md,
            title=stem,
            blocks=blocks_from_markdown(md),
            meta={},
            kind="canvas",
            prose=True,
            note=None if md else "the canvas has no text",
        )


# ---------------------------------------------------------------- enricher


def _json_value(value: object) -> object:
    """A frontmatter value as JSON (a YAML date becomes text)."""
    return json.loads(json.dumps(value, default=str, sort_keys=True))


class ObsidianEnricher(Enricher):
    """Frontmatter, tags, aliases, and links of a vault note. Local."""

    name = "obsidian"
    version = "1"

    def enrich(self, doc: Document, ctx: EnrichContext) -> list[Fact]:
        if doc.converter != CONVERTER:
            return []  # not an item of an Obsidian source
        facts: list[Fact] = []
        try:
            front = parse_frontmatter(doc.meta.get("frontmatter"))
        except (yaml.YAMLError, ValueError) as exc:
            front = {}
            facts.append(Fact("frontmatter_error", type(exc).__name__))
        for key in sorted(front, key=str):
            facts.append(Fact("frontmatter", str(key), data={"value": _json_value(front[key])}))
        facts += [Fact("tag", tag) for tag in note_tags(front, doc.markdown)]
        seen = set()
        for key in ("aliases", "alias"):
            for alias in _aliases(front.get(key)):
                if alias.lower() not in seen:
                    seen.add(alias.lower())
                    facts.append(Fact("alias", alias))
        done = set()
        for target, data in note_links(doc.markdown):
            mark = (target, dumps(data))
            if mark not in done:
                done.add(mark)
                facts.append(Fact("link", target, data=data))
        return facts


# ------------------------------------------------------------------- links


def _resolve(target: str, src_key: str, keys: dict[str, int], names: dict[str, list[str]]):
    """The key that a link target means, or None. `keys`: lower-case key ->
    item ID. `names`: lower-case file name (with and without the note
    suffix) -> keys."""
    t = target.strip().lstrip("/").replace("\\", "/").lower()
    if not t:
        return None
    tries = [t, *(t + s for s in NOTE_SUFFIXES)]
    for cand in tries:  # 1. the exact path from the vault root
        if cand in keys:
            return cand
    here = posixpath.dirname(src_key.lower())
    for cand in tries:  # 2. a path relative to the folder of the note
        rel = posixpath.normpath(posixpath.join(here, cand))
        if rel in keys:
            return rel
    base = posixpath.basename(t)
    found = [k for k in names.get(base, []) if "/" not in t or _ends(k, t)]
    if not found:
        return None
    # 3. a unique file name; 4. else the shortest path.
    return min(found, key=lambda k: (k.count("/"), len(k), k))


def _ends(key: str, target: str) -> bool:
    return any(
        key == cand or key.endswith("/" + cand)
        for cand in (target, *(target + s for s in NOTE_SUFFIXES))
    )


def resolve_links(index: LocalIndex, sid: str) -> int:
    """Make the `links_to` and `embeds` relations of one Obsidian source from
    the `link` facts of the current versions of its notes. Relations of links
    that are gone are deleted. Return the number of relations. The work is
    skipped when no fact and no item changed since the last call."""
    store = index.store
    mark = store.one(
        "SELECT (SELECT coalesce(max(f.id), 0) FROM fact f JOIN version v ON v.id = f.version_id"
        " WHERE v.source_id = ?) AS facts,"
        " (SELECT count(*) FROM item WHERE source_id = ? AND present = 1) AS items,"
        " (SELECT coalesce(max(id), 0) FROM version WHERE source_id = ?) AS versions",
        (sid, sid, sid),
    )
    state = {"facts": mark["facts"], "items": mark["items"], "versions": mark["versions"]}
    last = index.get_status(LINKS_STATUS + sid)
    if last is not None and {k: last.get(k) for k in state} == state:
        return int(last.get("relations", 0))
    keys: dict[str, int] = {}
    names: dict[str, list[str]] = {}
    for row in store.q("SELECT id, key FROM item WHERE source_id = ? AND present = 1", (sid,)):
        key = row["key"].lower()
        keys[key] = row["id"]
        base = posixpath.basename(key)
        names.setdefault(base, []).append(key)
        for suffix in NOTE_SUFFIXES:
            if base.endswith(suffix):
                names.setdefault(base[: -len(suffix)], []).append(key)
    want: dict[tuple[str, str, str], dict] = {}
    rows = store.q(
        "SELECT i.id, i.key, f.value, f.data FROM fact f JOIN version v ON v.id = f.version_id"
        " JOIN item i ON i.id = v.item_id WHERE i.source_id = ? AND i.present = 1"
        " AND f.kind = 'link' AND f.enricher = ?"
        " AND v.n = (SELECT max(n) FROM version WHERE item_id = i.id) ORDER BY f.id",
        (sid, ObsidianEnricher.name),
    )
    for row in rows:
        data = loads(row["data"]) or {}
        dst = _resolve(row["value"], row["key"], keys, names)
        if dst is None or keys[dst] == row["id"]:
            continue
        kind = "embeds" if data.get("embed") else "links_to"
        want.setdefault((kind, f"item:{row['id']}", f"item:{keys[dst]}"), {})
    now = index.now()
    with store.transaction():
        have = store.q(
            "SELECT r.id, r.kind, r.src, r.dst FROM relation r JOIN item i"
            " ON r.src = 'item:' || i.id WHERE i.source_id = ? AND r.kind IN ('links_to', 'embeds')",
            (sid,),
        )
        for row in have:
            if (row["kind"], row["src"], row["dst"]) not in want:
                store.x("DELETE FROM relation WHERE id = ?", (row["id"],))
        for (kind, src, dst), data in want.items():
            index.relate(kind, src, dst, now, data)
        index.set_status(LINKS_STATUS + sid, {**state, "relations": len(want)})
    return len(want)
