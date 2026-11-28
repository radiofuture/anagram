"""The local index: sources, scans, streams, and derived meaning.

    index = LocalIndex.for_client(client)
    sid = index.add_source(FolderConnector("~/lab"))
    report = index.scan()                     # evidence first, then convert/enrich/embed jobs
    index.streams.checkpoint(client, sid)     # Merkle root of new items -> log
    hits = index.search("cryo-EM")            # full-text (+ vectors with an embedder)
    drafts = draft_findings(index)            # see drafts.py; the user approves

`LocalIndex` holds the store, the sources, and the reads of meaning. Three
parts do the rest:

- `index.scanner` (`scan.py`): evidence for new and changed items.
- `index.jobs` (`pipeline.py`): the convert, enrich, and embed jobs.
- `index.streams` (`streams.py`): the checkpoints of each source.

Pipeline (spec/index.md section 2):

1. Scan: each new or changed item gets a version with a salted evidence
   record (`anagram.evidence.v1`). Its root goes into the source's pending
   list. The scan writes this in one transaction, before any conversion.
2. Jobs (`jobs.py`): convert (a converter makes a `Document`; chunks go into
   full-text search), enrich (facts), embed (vectors). A job that fails waits
   and tries again. A file that no converter reads is "skipped" with a reason.
3. A checkpoint commits the Merkle root over the pending roots
   (`anagram.stream_checkpoint.v1`). `checkpoint_due` gives the cadence.

Meaning is keyed by version: a new version gets new meaning, and the meaning
of old versions stays. Meaning is never committed and never leaves the device.
"""

from __future__ import annotations

import logging
import secrets
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from anagram.core.crypto import aead
from anagram.core.crypto.hashing import TAG_EVIDENCE_ROOT
from anagram.core.timefmt import format_time
from anagram.local.index import jobs
from anagram.local.index.convert import Block, Converter, Document, all_converters
from anagram.local.index.enrich import ENRICHERS, Enricher, Fact, facts_to_chips
from anagram.local.index.extract import Extracted
from anagram.local.index.pipeline import JobRunner
from anagram.local.index.scan import Scanner, ScanReport
from anagram.local.index.store import IndexStore, dumps, loads
from anagram.local.index.store_port import RetrievalStore
from anagram.local.index.streams import Streams
from anagram.local.index.vec_store import SqliteVecStore
from anagram.local.sources import (
    Connector,
    SecretFn,
    SourceKinds,
    Transport,
    connector_from_config,
    source_labels,
    source_state,
)
from anagram.local.sources.http import HttpTransport
from anagram.local.sources.sync import is_own
from anagram.local.understanding.chips import ItemChips
from anagram.local.understanding.vocabulary import Vocabulary, default_vocabulary
from anagram.models.embed import Embedder
from anagram.proofs.records import Opening

if TYPE_CHECKING:
    from anagram.local.ports import LocalClient
    from anagram.local.sources.credentials import CredentialStore

log = logging.getLogger("anagram.local.index")

INDEX_KEY = "index-key"
INDEX_DB = "index.sqlite"
RRF_K = 60


@dataclass(frozen=True)
class ItemView:
    """One indexed item, as drafts and the UI see it."""

    source_id: str
    key: str
    kind: str
    name: str | None
    media_type: str
    ref: str
    path: str | None
    time: str | None
    root: str  # evidence root of the current version
    present: bool
    versions: int


@dataclass(frozen=True)
class Meaning:
    """Derived meaning of one item version. Never committed."""

    extracted: Extracted
    chips: ItemChips
    summary: str
    digest: str
    converter: str | None = None

    @property
    def has_third_party(self) -> bool:
        return self.extracted.has_third_party


@dataclass(frozen=True)
class SearchHit:
    source_id: str
    key: str
    name: str | None
    version: int
    anchor: str
    text: str
    score: float
    via: tuple[str, ...]  # "text", "vector"


@dataclass(frozen=True)
class SkippedItem:
    source_id: str
    key: str
    name: str | None
    media_type: str
    reason: str
    fix: str | None


def _source_dict(row) -> dict:
    return {
        "config": loads(row["config"]),
        "created_at": row["created_at"],
        "kind": row["kind"],
        "label": row["label"],
        "last_change_at": row["last_change_at"],
        "last_checkpoint_at": row["last_checkpoint_at"],
        "last_scan_at": row["last_scan_at"],
        "prefs": loads(row["prefs"]),
        "prev": row["prev"],
        "seq": row["seq"],
        "start": row["start"],
        "stream_id": row["id"],
    }


class LocalIndex:
    def __init__(
        self,
        path: str | Path,
        key: bytes,
        *,
        vocab: Vocabulary | None = None,
        owner_emails: Iterable[str] = (),
        secret: SecretFn | None = None,
        transport: Transport | None = None,
        http: HttpTransport | None = None,
        credentials: CredentialStore | None = None,
        clock: Callable[[], float] = time.time,
        converters: Iterable[Converter] | None = None,
        enrichers: Iterable[Enricher] | None = None,
        embedder: Embedder | None = None,
        sources: Iterable[type[Connector]] = (),
    ) -> None:
        """`sources`: source kinds of a higher layer, besides the registry
        (the composition root gives them; for example the lab space)."""
        self.kinds = SourceKinds(sources)
        self.store = IndexStore(path, key)
        # Vector and full-text search (plan net 01: the retrieval store port).
        self.retrieval: RetrievalStore = SqliteVecStore(self.store)
        source_labels.migrate(self.store)  # no source label is a path
        self.vocab = vocab or default_vocabulary()
        self.owner_emails = frozenset(e.lower() for e in owner_emails)
        self.secret = secret
        self.transport = transport
        self.http = http
        self.credentials = credentials
        self.clock = clock
        self.converters = list(converters) if converters is not None else all_converters()
        if enrichers is None:
            enrichers = [cls() for _, cls in ENRICHERS]
        self.enrichers = [e for e in enrichers if e.available()]
        self.embedder = embedder
        # The open connector of each source. A config change drops it.
        self.connectors: dict[str, Connector] = {}
        self.scanner = Scanner(self)
        self.jobs = JobRunner(self)
        self.streams = Streams(self)

    @classmethod
    def for_client(cls, client: LocalClient, **kwargs) -> LocalIndex:
        """Open the index in the client home. The key is `index-key` in the
        client keystore (made on first use). The source kinds of the higher
        layers come from the composition root (`client.index_sources`)."""
        key = client.keystore.get_or_create(INDEX_KEY, aead.new_key)
        kwargs.setdefault("sources", client.index_sources)

        def secret(name: str) -> str:
            value = client.keystore.get(name)
            if value is None:
                raise KeyError(f"no {name} in the keystore")
            return value.decode()

        kwargs.setdefault("secret", secret)
        explicit_http = kwargs.get("http")
        if "http" not in kwargs:
            from anagram.local.sources import http as http_mod

            kwargs["http"] = http_mod.default_http()
        if "transport" not in kwargs and explicit_http is not None:
            from anagram.local.sources import http as http_mod

            kwargs["transport"] = http_mod.as_v1(explicit_http)
        given = kwargs.pop("credentials", None)
        idx = cls(Path(client.home) / INDEX_DB, key, **kwargs)
        if given is None:
            # Accounts of connected sources: tokens in the client
            # keystore, the OAuth client from the lab, the build, or the home.
            from anagram.local.sources.credentials import CredentialStore
            from anagram.local.sources.oauth import client_resolver

            given = CredentialStore(
                client.keystore,
                idx.store,
                idx.http,
                client_resolver(client.lab_context, client.home),
                clock=idx.clock,
                publish=source_state.publisher(idx.store, idx.clock),
            )
        idx.credentials = given
        # The address of each connected Google account is the member's own:
        # a received message from another sender is third-party text, and a
        # Drive file of another owner is marked.
        mine = {a.label.lower() for a in given.accounts() if "@" in a.label}
        idx.owner_emails = idx.owner_emails | mine
        return idx

    def close(self) -> None:
        self.store.close()

    def now(self) -> str:
        return format_time(datetime.fromtimestamp(int(self.clock()), UTC))

    # ------------------------------------------------------------ sources

    def add_source(self, connector: Connector, label: str | None = None) -> str:
        sid = secrets.token_bytes(16).hex()
        self.store.x(
            "INSERT INTO source (id, kind, label, config, created_at, prefs)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                sid,
                connector.config()["kind"],
                label or source_labels.source_label(connector.config()),
                dumps(connector.config()),
                self.now(),
                # A kind can give first prefs (for example its own converter).
                dumps(dict(getattr(connector, "default_prefs", None) or {})),
            ),
        )
        self.connectors[sid] = connector
        return sid

    def sources(self) -> dict[str, dict]:
        """The sources, with no source that is being removed."""
        out = {}
        for row in self.store.q(
            "SELECT s.* FROM source s LEFT JOIN source_state st ON st.source_id = s.id"
            " WHERE coalesce(st.status, '') != ? ORDER BY s.id",
            (source_state.REMOVING,),
        ):
            d = _source_dict(row)
            d["pending"] = [r.hex() for r in self.streams.pending(row["id"])]
            out[row["id"]] = d
        return out

    def source(self, sid: str) -> dict:
        row = self.store.one("SELECT * FROM source WHERE id = ?", (sid,))
        if row is None:
            raise KeyError(f"no source {sid}")
        d = _source_dict(row)
        d["pending"] = [r.hex() for r in self.streams.pending(sid)]
        return d

    def connector(self, sid: str) -> Connector:
        if sid not in self.connectors:
            cfg = self.source(sid)["config"]
            self.connectors[sid] = connector_from_config(
                cfg,
                self.secret,
                self.transport,
                http=self.http,
                credentials=self.credentials,
                kinds=self.kinds,
            )
        return self.connectors[sid]

    def is_own(self, sid: str) -> bool:
        """False for a source whose items are the work of other people (the
        class flag `own` of its kind). Such a source gets no checkpoint, and
        its items go into no finding draft and no matching lines."""
        conn = self.connectors.get(sid)
        if conn is None:
            row = self.store.one("SELECT kind FROM source WHERE id = ?", (sid,))
            conn = self.kinds.get(row["kind"]) if row is not None else None
        return is_own(conn)

    def removing(self, sid: str) -> bool:
        """True while the source is being removed (`retention.remove_source`)."""
        state = source_state.read(self.store, sid)
        return state is not None and state.stored_status == source_state.REMOVING

    def own_sources(self) -> list[str]:
        """IDs of the sources with the member's own items, in ID order."""
        return [
            r["id"]
            for r in self.store.q("SELECT id FROM source ORDER BY id")
            if self.is_own(r["id"])
        ]

    def set_source_prefs(
        self,
        sid: str,
        *,
        prefer: list[str] | None = None,
        allow_external: list[str] | None = None,
        assistant: bool | None = None,
    ) -> dict:
        """The user's choices for one source: `prefer` (converter names, in
        order), `allow_external` (the external converters and enrichers that
        the user opted in to for this source), and `assistant` (an
        assistant can read the source). A value of None keeps the stored value."""
        prefs = self.source(sid)["prefs"]
        if prefer is not None:
            prefs["prefer"] = list(prefer)
        if allow_external is not None:
            prefs["allow_external"] = sorted(set(allow_external))
        if assistant is not None:
            prefs["assistant"] = bool(assistant)
        self.store.x("UPDATE source SET prefs = ? WHERE id = ?", (dumps(prefs), sid))
        return prefs

    def set_source_label(self, sid: str, label: str) -> None:
        self.source(sid)  # KeyError for an unknown source
        self.store.x("UPDATE source SET label = ? WHERE id = ?", (label, sid))

    def set_source_config(self, sid: str, cfg: dict) -> None:
        """Replace the config of a source (what to include; no secrets). The
        kind cannot change. The next scan reads the source with the new
        config."""
        if cfg.get("kind") != self.source(sid)["config"]["kind"]:
            raise ValueError("the kind of a source cannot change")
        self.store.x("UPDATE source SET config = ? WHERE id = ?", (dumps(cfg), sid))
        self.connectors.pop(sid, None)

    # --------------------------------------------------------------- scan

    def scan(
        self, sources: Iterable[str] | None = None, *, process: bool = True, full: bool = False
    ) -> ScanReport:
        """Scan the sources (`index.scanner`): evidence for new and changed
        items, in one transaction for each source. With `process` (the
        default), then run the jobs (convert, enrich, embed) until the queue
        is empty. With `full`, hash each file again (then a change that keeps
        size and mtime is seen too)."""
        report = ScanReport()
        scanned: list[str] = []
        for sid in sources if sources is not None else sorted(self.sources()):
            try:
                self.scanner.scan_source(sid, report, full, run_after=not process)
                self.store.x("UPDATE source SET error = NULL WHERE id = ?", (sid,))
                scanned.append(sid)
            except Exception as exc:  # one bad source must not stop the rest
                msg = f"{type(exc).__name__}: {exc}"
                log.warning("scan of source %s failed: %s", sid, msg, exc_info=True)
                report.errors.append((sid, msg))
                self.store.x("UPDATE source SET error = ? WHERE id = ?", (msg, sid))
                self.scanner.record_fault(sid, exc)
        if process:
            self.jobs.run()
            for sid in scanned:
                try:
                    self.scanner.after_scan(sid)
                except Exception as exc:  # one bad source must not stop the rest
                    msg = f"{type(exc).__name__}: {exc}"
                    log.warning("after_scan of source %s failed: %s", sid, msg, exc_info=False)
                    report.errors.append((sid, msg))
        return report

    # ---------------------------------------------------------- relations

    def relate(self, kind: str, src: str, dst: str, now: str, data: dict | None = None) -> None:
        """Add one relation (no change if it is there)."""
        self.store.x(
            "INSERT OR IGNORE INTO relation (kind, src, dst, data, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (kind, src, dst, dumps(data or {}), now),
        )

    def relations(self, kind: str | None = None) -> list[tuple[str, str, str]]:
        sql, args = "SELECT kind, src, dst FROM relation", ()
        if kind is not None:
            sql, args = sql + " WHERE kind = ?", (kind,)
        return [tuple(r) for r in self.store.q(sql + " ORDER BY id", args)]

    def item_ref(self, sid: str, key: str) -> str:
        row = self.store.one("SELECT id FROM item WHERE source_id = ? AND key = ?", (sid, key))
        if row is None:
            raise KeyError(key)
        return f"item:{row[0]}"

    # ------------------------------------------------------------ meaning

    def document(self, vid: int) -> Document | None:
        row = self.store.one("SELECT * FROM document WHERE version_id = ?", (vid,))
        if row is None:
            return None
        return Document(
            markdown=row["markdown"],
            title=row["title"],
            blocks=[Block.from_json(b) for b in loads(row["blocks"])],
            meta=loads(row["meta"]),
            quoted=row["quoted"],
            converter=row["converter"],
            converter_version=row["converter_version"],
            kind=row["kind"],
            prose=bool(row["prose"]),
            note=row["note"],
            schema=row["schema"],
        )

    def current_version(self, sid: str, key: str):
        """The newest version row of an item, or None."""
        return self.store.one(
            "SELECT v.* FROM version v JOIN item i ON i.id = v.item_id"
            " WHERE i.source_id = ? AND i.key = ? ORDER BY v.n DESC LIMIT 1",
            (sid, key),
        )

    def meaning(self, sid: str, key: str, version: int | None = None) -> Meaning | None:
        """Meaning of the current version (or of version `n`). None while the
        version waits for conversion. A skipped version gives empty meaning
        with the reason as the note."""
        if version is None:
            v = self.current_version(sid, key)
        else:
            v = self.store.one(
                "SELECT v.* FROM version v JOIN item i ON i.id = v.item_id"
                " WHERE i.source_id = ? AND i.key = ? AND v.n = ?",
                (sid, key, version),
            )
        if v is None:
            return None
        doc = self.document(v["id"])
        if doc is None:
            job = self.store.one(
                "SELECT state, reason FROM job WHERE stage = 'convert' AND version_id = ?",
                (v["id"],),
            )
            if job is None or job["state"] not in (jobs.SKIPPED, jobs.FAILED):
                return None
            ex = Extracted(kind="binary", prose=False, note=job["reason"] or "not converted")
            return Meaning(ex, ItemChips(), "", v["digest_hex"], None)
        facts = [
            Fact(r["kind"], r["value"], r["score"])
            for r in self.store.q(
                "SELECT kind, value, score FROM fact WHERE version_id = ? AND enricher = 'chips'",
                (v["id"],),
            )
        ]
        summary = next((f.value for f in facts if f.kind == "summary"), "")
        return Meaning(
            extracted=doc.to_extracted(),
            chips=facts_to_chips(facts),
            summary=summary,
            digest=v["digest_hex"],
            converter=doc.converter,
        )

    def facts(self, sid: str, key: str, kind: str | None = None) -> list[Fact]:
        v = self.current_version(sid, key)
        if v is None:
            return []
        sql = "SELECT kind, value, score, data FROM fact WHERE version_id = ?"
        args: tuple = (v["id"],)
        if kind is not None:
            sql, args = sql + " AND kind = ?", (*args, kind)
        return [Fact(r[0], r[1], r[2], loads(r[3])) for r in self.store.q(sql, args)]

    def third_party_ids(self) -> set[int]:
        """IDs of the items whose current version is the text of another
        person (`local/understanding/third_party.py`): the mark of the connector on the
        version, or the mark of the converter on the document."""
        rows = self.store.q(
            "SELECT i.id FROM item i JOIN version v ON v.item_id = i.id"
            " LEFT JOIN document d ON d.version_id = v.id"
            " WHERE v.n = (SELECT max(n) FROM version WHERE item_id = i.id)"
            " AND (coalesce(json_extract(v.extra, '$.third_party'), 0) = 1"
            " OR coalesce(json_extract(d.meta, '$.third_party'), 0) = 1)"
        )
        return {r[0] for r in rows}

    def is_third_party(self, vid: int) -> bool:
        """True if version `vid` is the text of another person."""
        row = self.store.one(
            "SELECT 1 FROM version v LEFT JOIN document d ON d.version_id = v.id"
            " WHERE v.id = ? AND (coalesce(json_extract(v.extra, '$.third_party'), 0) = 1"
            " OR coalesce(json_extract(d.meta, '$.third_party'), 0) = 1)",
            (vid,),
        )
        return row is not None

    def items(
        self, sid: str | None = None, present_only: bool = True, *, own_only: bool = False
    ) -> list[ItemView]:
        """The indexed items. With `own_only`, only the member's own work: no
        item of a source whose items are the work of other people (`own =
        False`), and no item whose text another person wrote (a received
        mail, its attachments, a file of another owner)."""
        own = set(self.own_sources()) if own_only else None
        others = self.third_party_ids() if own_only else set()
        sql = (
            "SELECT i.*, (SELECT root FROM version WHERE item_id = i.id ORDER BY n DESC LIMIT 1)"
            " AS root, (SELECT count(*) FROM version WHERE item_id = i.id) AS versions"
            " FROM item i WHERE 1 = 1"
        )
        args: list = []
        if sid is not None:
            sql += " AND i.source_id = ?"
            args.append(sid)
        if present_only:
            sql += " AND i.present = 1"
        out = []
        for v in self.store.q(sql + " ORDER BY i.source_id, i.key", args):
            if own is not None and v["source_id"] not in own:
                continue
            if v["id"] in others:
                continue
            out.append(
                ItemView(
                    source_id=v["source_id"],
                    key=v["key"],
                    kind=v["kind"],
                    name=v["name"],
                    media_type=v["media_type"],
                    ref=v["ref"],
                    path=v["path"],
                    time=v["time"],
                    root=v["root"],
                    present=bool(v["present"]),
                    versions=v["versions"],
                )
            )
        return out

    def evidence_opening(self, sid: str, key: str, version: int = -1) -> Opening:
        rows = self.store.q(
            "SELECT v.opening FROM version v JOIN item i ON i.id = v.item_id"
            " WHERE i.source_id = ? AND i.key = ? ORDER BY v.n",
            (sid, key),
        )
        if not rows:
            raise KeyError(key)
        return Opening.from_json(TAG_EVIDENCE_ROOT, loads(rows[version][0]))

    def skipped(self, sid: str | None = None) -> list[SkippedItem]:
        """Current versions that no converter read, with the reason and a fix."""
        sql = (
            "SELECT i.source_id, i.key, i.name, v.media_type, j.reason, j.fix, j.state, j.error"
            " FROM job j JOIN version v ON v.id = j.version_id JOIN item i ON i.id = v.item_id"
            " WHERE j.stage = 'convert' AND j.state IN ('skipped', 'failed') AND i.present = 1"
            " AND v.n = (SELECT max(n) FROM version WHERE item_id = i.id)"
        )
        args: tuple = ()
        if sid is not None:
            sql, args = sql + " AND i.source_id = ?", (sid,)
        out = []
        for r in self.store.q(sql + " ORDER BY i.source_id, i.key", args):
            reason = r["reason"] if r["state"] == jobs.SKIPPED else f"failed: {r['error']}"
            out.append(SkippedItem(r[0], r[1], r[2], r[3], reason, r["fix"]))
        return out

    def projects(self) -> dict[tuple[str, str], str]:
        """(source_id, key) -> project node of the item (`same_project`)."""
        rows = self.store.q(
            "SELECT i.source_id, i.key, r.dst FROM relation r"
            " JOIN item i ON r.src = 'item:' || i.id WHERE r.kind = 'same_project'"
        )
        return {(r[0], r[1]): r[2] for r in rows}

    def stamped(self) -> set[tuple[str, str]]:
        """Items whose version is in a stamped finding (`finding_ref`)."""
        rows = self.store.q(
            "SELECT DISTINCT i.source_id, i.key FROM finding_ref f"
            " JOIN version v ON v.id = f.version_id JOIN item i ON i.id = v.item_id"
        )
        return {(r[0], r[1]) for r in rows}

    def log_disclosure(
        self, recipient: str, adapter: str, what: str, source_id: str | None = None
    ) -> None:
        """One local log row for each external call (disclosure-recipient rule 4)."""
        self.store.x(
            "INSERT INTO disclosure (at, recipient, adapter, what, source_id)"
            " VALUES (?, ?, ?, ?, ?)",
            (self.now(), recipient, adapter, what, source_id),
        )

    def disclosures(self) -> list[dict]:
        return [
            {"adapter": r[1], "at": r[0], "recipient": r[2], "source_id": r[3], "what": r[4]}
            for r in self.store.q(
                "SELECT at, adapter, recipient, source_id, what FROM disclosure ORDER BY id"
            )
        ]

    def record_finding(self, finding_root: str, keys: Iterable[tuple[str, str]]) -> None:
        """Link a committed finding to the current versions of its items."""
        now = self.now()
        for sid, key in keys:
            v = self.current_version(sid, key)
            if v is not None:
                self.store.x(
                    "INSERT OR IGNORE INTO finding_ref (finding_root, version_id, created_at)"
                    " VALUES (?, ?, ?)",
                    (finding_root, v["id"], now),
                )

    # ------------------------------------------------------------- search

    def search(self, query: str, k: int = 10, *, all_versions: bool = False) -> list[SearchHit]:
        """Full-text search (FTS5, BM25), plus vector search when there is an
        embedder. The two rankings merge by reciprocal rank fusion. Only the
        current versions of present items, unless `all_versions`."""
        from anagram.local.index import retrieve

        ranked, via = retrieve.fused(self, query, max(k * 5, 50))
        if not ranked:
            return []
        marks = ",".join("?" for _ in ranked)
        sql = (
            "SELECT c.id, c.anchor, c.text, v.n, i.source_id, i.key, i.name, i.present,"  # noqa: S608
            " (SELECT max(n) FROM version WHERE item_id = i.id) AS last"
            " FROM chunk c JOIN version v ON v.id = c.version_id JOIN item i ON i.id = v.item_id"
            " WHERE c.id IN (" + marks + ")"
        )
        rows = self.store.q(sql, list(ranked))
        hits = []
        for r in rows:
            if not all_versions and (not r["present"] or r["n"] != r["last"]):
                continue
            hits.append(
                SearchHit(
                    source_id=r["source_id"],
                    key=r["key"],
                    name=r["name"],
                    version=r["n"],
                    anchor=r["anchor"],
                    text=r["text"],
                    score=ranked[r["id"]],
                    via=tuple(sorted(via[r["id"]])),
                )
            )
        hits.sort(key=lambda h: (-h.score, h.source_id, h.key, h.anchor))
        return hits[:k]

    # ------------------------------------------------------------- status

    def set_status(self, key: str, value: dict) -> None:
        self.store.x(
            "INSERT OR REPLACE INTO status (key, value, updated_at) VALUES (?, ?, ?)",
            (key, dumps(value), self.clock()),
        )

    def get_status(self, key: str) -> dict | None:
        row = self.store.one("SELECT value, updated_at FROM status WHERE key = ?", (key,))
        if row is None:
            return None
        return {**loads(row[0]), "updated_at": row[1]}


__all__ = [
    "INDEX_DB",
    "INDEX_KEY",
    "ItemView",
    "LocalIndex",
    "Meaning",
    "SearchHit",
    "SkippedItem",
]
