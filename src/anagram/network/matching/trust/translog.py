"""The enclave transparency log and its witnesses (spec/enclave-trust.md
2.1 to 2.4), with storage and witnesses as ports.

- `TransparencyLog`: the append-only log. It refuses an entry that fails
  its form (2.2) and an instance key whose attestation evidence fails rules
  1 to 6 and 8 or whose lease is longer than 24 hours (5.4). It signs a
  checkpoint after each entry and asks each witness to cosign it.
- `EntryWitness`: one witness with its two keys (cosignature/v1 and the
  entry key). An Anagram witness (`reads_entries`) keeps its own copy of
  the entries, checks that they give the checkpoint root, and refuses a
  checkpoint that forks a line or logs a line ID twice. It also signs
  `enclave_entry_cosign` entries, after the checks of 5.6 and 5.7.
- `LogStore`: sqlite tables that keep the entries, the cosigned notes and
  the attestation documents of a log (or the entries of a witness) between
  restarts. Without a store, everything is in memory (tests).

The `simulated` profile (`simulated.py`) runs all of this in one process;
the deployable processes (`anagram log serve`, `anagram witness serve`)
put HTTP between the log and each witness.
"""

from __future__ import annotations

import bisect
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto import merkle
from anagram.core.crypto.hashing import tagged_hash
from anagram.core.crypto.signing import SigningKey
from anagram.core.shared_db import SharedDB
from anagram.network.formats.strict import Refused, parse_time
from anagram.network.matching.trust.attestation import verify_evidence
from anagram.network.matching.trust.entries import TAG_ENTRY, check_entry, entry_digest, sign_entry
from anagram.network.matching.trust.issuance import EXPIRY_WINDOW
from anagram.network.matching.trust.lines import (
    MAX_LEASE,
    _walk,
    latest_epoch,
    lease_ended,
    line_forked,
    line_writer,
)
from anagram.network.matching.trust.logview import LogView
from anagram.network.matching.trust.roots import Roots, quorum_times
from anagram.proofs.log.checkpoint import Checkpoint, open_checkpoint, sign_checkpoint
from anagram.proofs.log.note import (
    ALG_COSIGNATURE_V1,
    NoteSigner,
    NoteVerifier,
    add_signature_lines,
)
from anagram.proofs.log.witness import Witness as LogWitness
from anagram.proofs.log.witness import WitnessConflict, WitnessRefused

__all__ = [
    "Cosigner",
    "EntryWitness",
    "LogStore",
    "TransparencyLog",
    "WitnessConflict",
    "WitnessRefused",
    "check_entry_cosign",
    "reader_refuses",
]


class LogStore:
    """Append-only sqlite tables. `":memory:"` keeps nothing on disk."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._db = SharedDB(path)
        self._db.executescript(
            "CREATE TABLE IF NOT EXISTS entries (i INTEGER PRIMARY KEY, body TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS notes (i INTEGER PRIMARY KEY, size INTEGER NOT NULL,"
            " text TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS evidence (digest TEXT PRIMARY KEY, body TEXT NOT NULL);"
        )

    def entries(self) -> list[JsonObject]:
        rows = self._db.execute("SELECT body FROM entries ORDER BY i").fetchall()
        return [json.loads(r[0]) for r in rows]

    def add_entries(self, start: int, entries: list[JsonObject]) -> None:
        self._db.executemany(
            "INSERT INTO entries (i, body) VALUES (?, ?)",
            [(start + n, canonical_json(e).decode()) for n, e in enumerate(entries)],
        )

    def notes(self) -> list[tuple[int, str]]:
        return [(int(s), t) for s, t in self._db.execute("SELECT size, text FROM notes ORDER BY i")]

    def add_note(self, size: int, text: str) -> None:
        self._db.execute("INSERT INTO notes (size, text) VALUES (?, ?)", (size, text))

    def evidence(self) -> dict[str, JsonObject]:
        rows = self._db.execute("SELECT digest, body FROM evidence")
        return {d: json.loads(b) for d, b in rows}

    def add_evidence(self, digest: str, doc: JsonObject) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO evidence (digest, body) VALUES (?, ?)",
            (digest, canonical_json(doc).decode()),
        )


def _view_refuses(view: LogView, roots: Roots) -> bool:
    lines = [
        e["line_id"]
        for e in view.entries
        if e["kind"] == "enclave_line" and e["signer"] == roots.release_key
    ]
    if len(lines) != len(set(lines)):
        return True
    return any(line_forked(view, line, roots) for line in set(lines))


def reader_refuses(entries: list[JsonObject], roots: Roots) -> bool:
    """An Anagram witness refuses a log that forks a line or logs one line
    ID twice (section 2.4). Unauthorized `enclave_line` entries are ignored."""
    return _view_refuses(LogView(entries, [0] * len(entries)), roots)


def check_failover(view: LogView, line_id: str, writer: str, roots: Roots, now: int) -> JsonObject:
    """Rules 3 to 5 of section 5.7 at time `now`: the latest state epoch of
    the line names `writer` as a holder, `writer` is not the current writer,
    and every lease of the current writer ended. Return the latest epoch."""
    latest = latest_epoch(view, line_id)
    old = line_writer(view, line_id, roots)
    if latest is None or old is None or writer not in latest["holders"] or writer == old:
        raise Refused("bad_entry", "not a holder of the latest state epoch")
    if not lease_ended(view, line_id, old, len(view.entries), now):
        raise Refused("bad_entry", "the writer's lease has not ended")
    return latest


def check_entry_cosign(entry: JsonObject, view: LogView, roots: Roots, now: int) -> None:
    """What a witness checks before it cosigns an entry (sections 5.6 and
    5.7). The entry must be in the log that the witness read. It cosigns
    only an `enclave_line` or an `enclave_writer` entry of the release key:
    a line ID that no other line has, or a failover that holds now."""
    check_entry(entry)
    if view.find(entry_digest(entry)) is None:
        raise Refused("bad_entry", "the entry is not in the log yet")
    if entry["signer"] != roots.release_key:
        raise Refused("bad_entry", "not signed by the release key")
    if entry["kind"] == "enclave_line":
        same = [
            e
            for _, e in view.of_kind("enclave_line")
            if e["line_id"] == entry["line_id"] and e["signer"] == roots.release_key
        ]
        if len(same) != 1:
            raise Refused("bad_entry", "the line ID is logged twice")
        return
    if entry["kind"] != "enclave_writer":
        raise Refused("bad_entry", "a witness cosigns only lines and failovers")
    latest = check_failover(view, entry["line_id"], entry["writer"], roots, now)
    digest = entry_digest(latest).hex()
    if (entry["counter"], entry["epoch"]) != (latest["counter"], digest):
        raise Refused("bad_entry", "the entry does not name the latest state epoch")


class Cosigner(Protocol):
    """One witness as the log asks it (C2SP tlog-witness style): the note,
    the size that the witness cosigned last, the consistency proof from that
    size, and the entries after it (a reading witness checks them)."""

    name: str

    def cosign(self, note: str, old: int, proof: list[bytes], new: list[JsonObject]) -> str: ...


@dataclass
class EntryWitness:
    """One witness. `cosign` gives a cosignature line or raises
    `WitnessRefused` (`WitnessConflict` when `old` is not its size)."""

    name: str
    cosign_key: SigningKey  # cosignature/v1
    entry_key: SigningKey  # enclave_entry_cosign
    reads_entries: bool  # an Anagram witness
    log_verifier: NoteVerifier  # of the log key
    roots: Roots
    clock: Callable[[], int]
    state: str | Path = ":memory:"  # the sqlite file of the cosigned size
    store: LogStore | None = None  # the entries of a reading witness
    entries: list[JsonObject] = field(default_factory=list)
    _witness: LogWitness = field(init=False, repr=False)
    _frontier: list[bytes] = field(init=False, repr=False)
    _digests: list[bytes] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        signer = NoteSigner(self.name, self.cosign_key, ALG_COSIGNATURE_V1)
        self._witness = LogWitness(signer, self.state, [self.log_verifier], self.clock)
        if self.store is not None:
            self.entries = self.store.entries()
        self._frontier = []
        self._digests = []
        for i, e in enumerate(self.entries):
            raw = canonical_json(e)
            self._frontier = merkle.frontier_append(self._frontier, i, merkle.leaf_hash(raw))
            self._digests.append(tagged_hash(TAG_ENTRY, raw))

    @property
    def signer(self) -> NoteSigner:
        return self._witness.signer

    @property
    def cosigned_size(self) -> int:
        """The tree size that this witness cosigned last."""
        known = self._witness.known(self.log_verifier.name)
        return known[0] if known else 0

    def cosign(self, note: str, old: int, proof: list[bytes], new: list[JsonObject]) -> str:
        if not self.reads_entries:
            return self._witness.cosign(note, old, proof)
        if old != len(self.entries):
            raise WitnessConflict(len(self.entries))
        candidate = self.entries + new
        try:
            cp = open_checkpoint(note, [self.log_verifier]).checkpoint
        except ValueError as exc:  # NoteError
            raise WitnessRefused("bad checkpoint note") from exc
        raws = [canonical_json(e) for e in new]
        frontier = self._frontier
        for offset, raw in enumerate(raws):
            frontier = merkle.frontier_append(frontier, old + offset, merkle.leaf_hash(raw))
        if cp.size != len(candidate) or merkle.frontier_root(frontier) != cp.root:
            raise WitnessRefused("the entries do not give the checkpoint root")
        try:
            for e in new:
                check_entry(e)
        except Refused as exc:
            raise WitnessRefused(f"bad entry: {exc}") from exc
        digests = self._digests + [tagged_hash(TAG_ENTRY, raw) for raw in raws]
        view = LogView.from_parts(candidate, [0] * len(candidate), digests, frontier)
        if _view_refuses(view, self.roots):
            raise WitnessRefused("the checkpoint forks a line or logs a line twice")
        line = self._witness.cosign(note, old, proof)
        if self.store is not None:
            self.store.add_entries(old, new)
        self.entries = candidate
        self._frontier = frontier
        self._digests = digests
        return line

    def sign_entry_cosign(self, entry: JsonObject) -> JsonObject:
        fields = {"entry": entry_digest(entry).hex(), "time": self.clock()}
        return sign_entry("enclave_entry_cosign", fields, self.entry_key)

    def checked_entry_cosign(self, entry: JsonObject, view: LogView) -> JsonObject:
        """The `enclave_entry_cosign` of an entry after the checks of
        `check_entry_cosign` at the witness's own time."""
        check_entry_cosign(entry, view, self.roots, self.clock())
        return self.sign_entry_cosign(entry)


class TransparencyLog:
    """The enclave log (section 2): entries, cosigned checkpoints, and the
    reads that apps, nodes and instances use."""

    def __init__(
        self,
        origin: str,
        log_key: SigningKey,
        roots: Roots,
        clock: Callable[[], int],
        cosigners: list[Cosigner],
        store: LogStore | None = None,
    ) -> None:
        self.origin = origin
        self.signer = NoteSigner(origin, log_key)
        self.roots = roots
        self.clock = clock
        self.cosigners = cosigners
        self.store = store
        self.entries: list[JsonObject] = []
        self.notes: list[str] = []  # every cosigned checkpoint, oldest first
        self.sizes: list[int] = []  # the tree size of each note
        self.evidence: dict[str, JsonObject] = {}  # evidence digest -> attestation document
        self._leaves: list[bytes] = []
        self._frontier: list[bytes] = []
        self._view: LogView | None = None
        self._cosigned: dict[str, int] = {c.name: 0 for c in cosigners}
        if store is not None:
            self._load(store)

    def _load(self, store: LogStore) -> None:
        """The log trusts its own storage: it rebuilds its view from the
        stored notes without checking each root again."""
        self.entries = store.entries()
        raws = [canonical_json(e) for e in self.entries]
        self._leaves = [merkle.leaf_hash(r) for r in raws]
        frontier: list[bytes] = []
        for i, leaf in enumerate(self._leaves):
            frontier = merkle.frontier_append(frontier, i, leaf)
        self._frontier = frontier
        self.evidence = store.evidence()
        notes = store.notes()
        self.sizes = [s for s, _ in notes]
        self.notes = [t for _, t in notes]
        if not notes:
            return
        logged_by: list[int] = []
        for size, text in notes:
            upper = quorum_times(text, self.roots)[3]
            logged_by += [upper] * (size - len(logged_by))
        n = self.sizes[-1]
        view_frontier: list[bytes] = []
        for i, leaf in enumerate(self._leaves[:n]):
            view_frontier = merkle.frontier_append(view_frontier, i, leaf)
        self._view = LogView.from_parts(
            self.entries[:n],
            logged_by,
            [tagged_hash(TAG_ENTRY, r) for r in raws[:n]],
            view_frontier,
        )

    # ---- write ----------------------------------------------------------

    def _add(self, entry: JsonObject) -> int:
        index = len(self.entries)
        leaf = merkle.leaf_hash(canonical_json(entry))
        self.entries.append(entry)
        self._leaves.append(leaf)
        self._frontier = merkle.frontier_append(self._frontier, index, leaf)
        if self.store is not None:
            self.store.add_entries(index, [entry])
        return index

    def _check_state_epoch(self, entry: JsonObject) -> int | None:
        """Validate an `enclave_state_epoch`. Return the existing index if an
        identical epoch is already stored (idempotent), else None."""
        line_id, counter = entry["line_id"], entry["counter"]
        for i, existing in enumerate(self.entries):
            if (
                existing.get("kind") == "enclave_state_epoch"
                and existing.get("line_id") == line_id
                and existing.get("counter") == counter
            ):
                if existing == entry:
                    return i
                raise Refused("bad_entry", "a state epoch for this line and counter already exists")
        if not any(
            e.get("kind") == "enclave_line"
            and e.get("line_id") == line_id
            and e.get("signer") == self.roots.release_key
            for e in self.entries
        ):
            raise Refused("bad_entry", "state epoch for an unknown line")
        cur_view = LogView(self.entries, [0] * len(self.entries))
        walk = _walk(cur_view, line_id, self.roots)
        if walk.forked:
            raise Refused("bad_entry", "line is already forked")
        walk.epoch(entry, entry_digest(entry).hex())
        if walk.forked:
            raise Refused(
                "bad_entry", "state epoch does not extend the line under the active writer"
            )
        return None

    def _check_append_signer(self, entry: JsonObject) -> None:
        kind, signer = entry["kind"], entry["signer"]
        witness_keys = {w.entry_key for w in self.roots.witnesses}
        if kind in ("enclave_release", "enclave_floor", "enclave_line", "enclave_writer"):
            if signer != self.roots.release_key:
                raise Refused("bad_entry", f"{kind} must be signed by the release key")
        elif kind == "enclave_rebuild":
            if signer not in self.roots.rebuilders:
                raise Refused("bad_entry", "enclave_rebuild must be signed by a pinned rebuilder")
        elif kind == "enclave_entry_cosign":
            if signer not in witness_keys:
                raise Refused("bad_entry", "enclave_entry_cosign must be signed by a witness")
        elif kind == "enclave_revoke":
            if signer != self.roots.release_key and signer not in witness_keys:
                raise Refused("bad_entry", "enclave_revoke signer is not authorised")
        elif kind in ("roster_checkpoint", "node_admission"):
            if self.roots.roster_key is not None and signer != self.roots.roster_key:
                raise Refused("bad_entry", f"{kind} must be signed by the roster key")

    def append(self, entry: JsonObject) -> int:
        """Append a signed entry (section 2.2) after enforcing signer
        authorization and line/epoch invariants. Return its index."""
        check_entry(entry)
        kind = entry["kind"]
        if kind == "enclave_instance_key":
            raise Refused("bad_entry", "an instance key needs its attestation document")
        self._check_append_signer(entry)
        if kind == "enclave_state_epoch":
            existing_index = self._check_state_epoch(entry)
            if existing_index is not None:
                return existing_index
        elif kind == "member_credential":
            # Section 2.3: `expires` in the next 24 hours, so the month of a
            # join entry (network.md 6.7) is the month of its append.
            expires = parse_time(entry["expires"], "expires")
            if not self.clock() < expires <= self.clock() + EXPIRY_WINDOW:
                raise Refused("bad_entry", "a member credential expires in the next 24 hours")
        return self._add(entry)

    def append_instance_key(self, entry: JsonObject, document: JsonObject) -> int:
        """Section 5.4: the log takes an instance key only with a document
        whose evidence passes rules 1 to 6 and 8, and with a lease that ends
        at most 24 hours after the log's own time (rule 7 (a), section 2.4)."""
        check_entry(entry)
        if entry["kind"] != "enclave_instance_key":
            raise Refused("bad_entry", "expected enclave_instance_key")
        if parse_time(entry["lease_until"], "lease_until") > self.clock() + MAX_LEASE:
            raise Refused("instance_not_logged", "lease longer than 24 h")
        need_doc = {
            "instance_id",
            "intake_key",
            "key_epoch",
            "line_id",
            "output_key",
            "platform_evidence",
            "profile",
            "release",
        }
        if not isinstance(document, dict) or not need_doc <= set(document):
            raise Refused("bad_attestation", "document form")
        try:
            digest = hashlib.sha256(canonical_json(document["platform_evidence"])).hexdigest()
        except ValueError as exc:  # CanonicalError
            raise Refused("bad_attestation", "evidence form") from exc
        if (
            entry["evidence_digest"] != digest
            or entry["signer"] != document["output_key"]
            or entry["line_id"] != document["line_id"]
            or entry["instance_id"] != document["instance_id"]
            or entry["intake_key"] != document["intake_key"]
            or entry["key_epoch"] != document["key_epoch"]
            or entry["profile"] != document["profile"]
            or entry["release"] != document["release"]
        ):
            raise Refused("bad_attestation", "the entry does not name this document")
        for existing in self.entries:
            if (
                existing.get("kind") == "enclave_instance_key"
                and existing.get("line_id") == entry["line_id"]
                and existing.get("instance_id") == entry["instance_id"]
                and existing.get("signer") != entry["signer"]
            ):
                raise Refused("bad_entry", "instance_id is already bound to another output key")
        view = self.view()
        index = view.find(bytes.fromhex(entry["release"]))
        if index is None:
            raise Refused("release_not_logged")
        release = view.entries[index]
        if (
            release.get("kind") != "enclave_release"
            or release.get("signer") != self.roots.release_key
        ):
            raise Refused("release_not_logged")
        verify_evidence(document, release, view, self.roots, self.clock())
        self.evidence[digest] = document
        if self.store is not None:
            self.store.add_evidence(digest, document)
        return self._add(entry)

    def publish(self) -> str:
        """Sign a checkpoint of all entries and collect the cosignatures.
        Raise Refused if fewer than a quorum cosign; the note is then not
        kept."""
        size = len(self.entries)
        tree = merkle.list_subtree(self._leaves)
        note = sign_checkpoint(
            Checkpoint(self.origin, size, merkle.frontier_root(self._frontier)), self.signer
        )
        lines = [line for c in self.cosigners if (line := self._ask(c, note, tree, size))]
        signed = add_signature_lines(note, lines)
        if self._view is None:
            self._view = LogView.from_checkpoints(self.entries, [signed], self.roots)
        else:  # `extend` changes the view only after all of its checks pass
            self._view.extend(self.entries[len(self._view.entries) :], signed, self.roots)
        self.notes.append(signed)
        self.sizes.append(size)
        if self.store is not None:
            self.store.add_note(size, signed)
        return signed

    def _ask(self, c: Cosigner, note: str, tree: merkle.Subtree, size: int) -> str | None:
        """One cosignature, or None. A witness that knows another size
        (`WitnessConflict`, for example after a restart of the log) is asked
        again from that size."""
        old = self._cosigned.get(c.name, 0)
        for _ in range(2):
            if old > size:
                return None
            proof = merkle.consistency_path(tree, old, size) if 0 < old < size else []
            try:
                line = c.cosign(note, old, proof, self.entries[old:size])
            except WitnessConflict as exc:
                old = exc.known_size
                continue
            except WitnessRefused:
                return None
            self._cosigned[c.name] = size
            return line
        return None

    # ---- read -----------------------------------------------------------

    def checkpoint(self) -> str:
        return self.notes[-1]

    def read(self, start: int, end: int) -> list[JsonObject]:
        return self.entries[start:end]

    def covering(self, index: int) -> str:
        """`GET /log/checkpoint/covering/{index}` (section 2.4): the first
        cosigned checkpoint whose tree holds entry `index`, with its
        cosignatures."""
        at = bisect.bisect_right(self.sizes, index)
        if at == len(self.notes):
            raise Refused("bad_entry", "no cosigned checkpoint holds the entry yet")
        return self.notes[at]

    def view(self) -> LogView:
        """The entries under the latest checkpoint with a quorum."""
        return self._view if self._view is not None else LogView([], [])

    def inclusion(self, index: int, size: int) -> list[str]:
        tree = merkle.list_subtree(self._leaves[:size])
        return [h.hex() for h in merkle.inclusion_path(tree, index, size)]

    def root_at(self, size: int) -> bytes:
        return merkle.root(self._leaves[:size])
