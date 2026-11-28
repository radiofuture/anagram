"""The line rules (spec/enclave-trust.md 5.4 to 5.7): leases, authorised
lines, shards, state epochs, the writer and failovers.

A line is the state of one shard. It is authorised by an `enclave_line`
entry of the release key that both independent witnesses cosigned; its
state epochs must make one chain with one writer at a time. These rules
read only a checked `LogView`, so the app, the log, the witnesses and the
instances compute the same answer from the same entries.
"""

from __future__ import annotations

from dataclasses import dataclass

from anagram.core.canonical import JsonObject
from anagram.core.crypto.hashing import tagged_hash
from anagram.network.formats.strict import Refused, parse_time
from anagram.network.matching.trust.logview import LogView
from anagram.network.matching.trust.roots import Roots

TAG_SHARD = "anagram/v1/enclave/shard"
MAX_LEASE = 86_400  # 5.4: a lease of at most 24 hours
TOTAL_LOSS_GAP = 30 * 86400
V1_SHARDS = 1  # v1 uses a single shard until cross-shard matching is specified


def lease(e: JsonObject) -> int:
    """`lease_until` of a checked `enclave_instance_key` entry."""
    return parse_time(e["lease_until"], "lease_until")


def shard(subject: bytes, n: int) -> int:
    """The shard of a subject key among n (section 5.6)."""
    return int.from_bytes(tagged_hash(TAG_SHARD, subject)[:4], "big") % n


def _line_entries(view: LogView, roots: Roots) -> dict[str, tuple[int, JsonObject]]:
    """Authorised `enclave_line` entries by line ID: signed by the release
    key and cosigned by both independent witnesses. A line ID logged twice
    is not authorised."""
    seen: dict[str, list[tuple[int, JsonObject]]] = {}
    for i, e in view.of_kind("enclave_line"):
        if e["signer"] == roots.release_key and view.cosign_quorum(
            view.digests[i], roots, independent_only=True
        ):
            seen.setdefault(e["line_id"], []).append((i, e))
    return {k: v[0] for k, v in seen.items() if len(v) == 1}


def _leased_at(view: LogView, line_id: str, at: int) -> bool:
    """True if an instance of the line had an unexpired lease at time `at`."""
    return any(
        e["line_id"] == line_id and view.logged_by[i] <= at and lease(e) > at
        for i, e in view.of_kind("enclave_instance_key")
    )


def _reason_ok(
    view: LogView, lines: dict[str, tuple[int, JsonObject]], i: int, e: JsonObject
) -> bool:
    if e["reason"] != "total_loss":
        return e["replaces"] is None
    old = lines.get(e["replaces"] or "")
    if old is None or old[1]["shard"] != e["shard"]:
        return False
    at = view.logged_by[i]
    if _leased_at(view, e["replaces"], at):
        return False  # the old line still runs: no total loss
    return not any(
        o["reason"] == "total_loss"
        and o["shard"] == e["shard"]
        and j < i
        and at - view.logged_by[j] < TOTAL_LOSS_GAP
        for j, o in lines.values()
    )


def line_authorised(view: LogView, line_id: str, roots: Roots, subject: bytes | None) -> None:
    """Rule 7 (b): the line has an authorised `enclave_line` entry, it is not
    replaced by a later total-loss line, it has n = 1 shard in v1, and (with
    `subject`) it serves the subject's shard (section 5.6; W4 finding H-a,
    re-check R4)."""
    lines = _line_entries(view, roots)
    found = lines.get(line_id)
    if found is None or not _reason_ok(view, lines, *found):
        raise Refused("line_not_authorised")
    i, e = found
    if any(
        o["reason"] == "total_loss" and o["replaces"] == line_id and _reason_ok(view, lines, j, o)
        for j, o in lines.values()
    ):
        raise Refused("line_not_authorised", "replaced by a total-loss line")
    if e["shard"]["n"] != V1_SHARDS:
        raise Refused("line_not_authorised", "v1 has one shard")
    if subject is not None and shard(subject, e["shard"]["n"]) != e["shard"]["k"]:
        raise Refused("line_not_authorised", "another shard")


def latest_epoch(view: LogView, line_id: str) -> JsonObject | None:
    epochs = [e for _, e in view.of_kind("enclave_state_epoch") if e["line_id"] == line_id]
    return epochs[-1] if epochs else None


def writer_of(epoch: JsonObject) -> str:
    """The instance that writes after this epoch by the epoch alone:
    `next_writer`, else the writer of this epoch. A failover entry can
    change it (see `line_writer`)."""
    writer: str = epoch["next_writer"] or epoch["instance_id"]
    return writer


@dataclass(frozen=True)
class Failover:
    """An `enclave_writer` entry that the independent quorum cosigned
    (section 5.7). It takes effect at the log index of the later of the two
    cosignatures; `cosigned` is the earlier cosignature time."""

    entry: JsonObject
    effective: int
    cosigned: int


def _failovers(view: LogView, line_id: str, roots: Roots) -> list[Failover]:
    """`enclave_writer` entries of the line signed by the release key, each
    with its first `enclave_entry_cosign` from every independent witness."""
    independent = {w.entry_key for w in roots.witnesses if w.independent}
    out = []
    for i, e in view.of_kind("enclave_writer"):
        if e["line_id"] != line_id or e["signer"] != roots.release_key:
            continue
        first: dict[str, tuple[int, int]] = {}
        for j, c in view.of_kind("enclave_entry_cosign"):
            if j > i and c["signer"] in independent and c["entry"] == view.digests[i].hex():
                first.setdefault(c["signer"], (j, c["time"]))
        if len(independent) >= 2 and set(first) == independent:
            at = max(j for j, _ in first.values())
            out.append(Failover(e, at, min(t for _, t in first.values())))
    return out


def lease_ended(view: LogView, line_id: str, instance: str, before: int, at: int) -> bool:
    """Every lease that `instance` logged before index `before` ended at or
    before time `at`."""
    return all(
        lease(e) <= at
        for i, e in view.of_kind("enclave_instance_key")
        if i < before and e["line_id"] == line_id and e["instance_id"] == instance
    )


@dataclass
class _Walk:
    """The state of one line while its entries are read in log order."""

    keys: dict[str, str]  # instance ID -> output key
    last: JsonObject | None = None
    last_digest: str | None = None
    writer: str | None = None
    forked: bool = False

    def epoch(self, e: JsonObject, digest: str) -> None:
        counter = self.last["counter"] + 1 if self.last else 0
        if (
            e["counter"] != counter
            or e["prev"] != self.last_digest
            or self.keys.get(e["instance_id"]) != e["signer"]
            or (self.writer is not None and e["instance_id"] != self.writer)
            or e["instance_id"] not in e["holders"]
            or writer_of(e) not in e["holders"]
        ):
            self.forked = True
            return
        self.last, self.last_digest, self.writer = e, digest, writer_of(e)

    def failover(self, f: Failover, view: LogView, line_id: str) -> None:
        """Apply a failover only if it names the latest epoch, a holder of
        it, and a writer whose every lease ended before both independent
        cosignatures. Else it changes nothing: it never forks the line."""
        e, last = f.entry, self.last
        if (
            last is None
            or self.writer is None
            or (e["counter"], e["epoch"]) != (last["counter"], self.last_digest)
            or e["writer"] not in last["holders"]
            or e["writer"] == self.writer
            or not lease_ended(view, line_id, self.writer, f.effective, f.cosigned)
        ):
            return
        self.writer = e["writer"]


def _walk(view: LogView, line_id: str, roots: Roots) -> _Walk:
    keys = {
        e["instance_id"]: e["signer"]
        for _, e in view.of_kind("enclave_instance_key")
        if e["line_id"] == line_id
    }
    walk = _Walk(keys)
    steps: list[tuple[int, int, JsonObject | Failover]] = [
        (i, 0, e) for i, e in view.of_kind("enclave_state_epoch") if e["line_id"] == line_id
    ]
    steps += [(f.effective, 1, f) for f in _failovers(view, line_id, roots)]
    for i, _, step in sorted(steps, key=lambda s: (s[0], s[1])):
        if isinstance(step, Failover):
            walk.failover(step, view, line_id)
        else:
            walk.epoch(step, view.digests[i].hex())
        if walk.forked:
            break
    return walk


def line_forked(view: LogView, line_id: str, roots: Roots) -> bool:
    """A line is forked if its state epochs are not one chain with one writer
    at a time, or a writer is not a holder (spec section 5.5). The writer
    changes only by `next_writer` or by a failover (section 5.7)."""
    return _walk(view, line_id, roots).forked


def line_writer(view: LogView, line_id: str, roots: Roots) -> str | None:
    """The instance that may write the line's next state epoch (5.5, 5.7),
    or None for a line with no epoch or a forked line."""
    walk = _walk(view, line_id, roots)
    return None if walk.forked else walk.writer
