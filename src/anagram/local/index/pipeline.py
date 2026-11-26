"""The job pipeline of the local index: convert, enrich, embed.

    index.jobs.run()                       # until no job is ready
    index.jobs.store_document(vid, sid, doc)
    index.jobs.progress(sid)               # counts for the Sources view

`JobRunner` is the part `LocalIndex.jobs`. The job queue is in `jobs.py`.
A job that fails waits and tries again. A file that no converter reads is
"skipped" with a reason and a fix. Convert keeps the document and its
chunks (full-text search), enrich keeps the facts and plans the
`understand` job, and embed keeps the vectors (only with an embedder).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from anagram.core.crypto.chunked import ContentDigest, hash_bytes
from anagram.local.index import jobs, retention
from anagram.local.index.chunk import chunk_document, context_chunks
from anagram.local.index.convert import (
    Blob,
    Converter,
    Document,
    Router,
    Skip,
    Skipped,
    blocks_from_markdown,
)
from anagram.local.index.enrich import EnrichContext, check_enricher, fact_span
from anagram.local.index.extract import Extracted
from anagram.local.index.store import dumps, loads
from anagram.local.understanding import kind_rules, third_party, understand

if TYPE_CHECKING:
    from anagram.local.index.local import LocalIndex

log = logging.getLogger("anagram.local.index")

MAX_CONVERT_BYTES = 64 * 1024 * 1024
EMBED_BATCH = 32


@dataclass
class JobReport:
    done: int = 0
    skipped: int = 0
    retry: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)


class JobRunner:
    """The job part of one `LocalIndex`."""

    def __init__(self, index: LocalIndex) -> None:
        self.index = index
        self.store = index.store

    def recover_stale(self) -> int:
        """Put each job that a stopped process left `running` for more than
        `jobs.STALE_S` back in the queue. Return the number of jobs."""
        return jobs.recover_stale(self.store, self.index.clock())

    def run(self, limit: int | None = None, stages: tuple[str, ...] | None = None) -> JobReport:
        """Run ready jobs until none is ready (or `limit` jobs). Embed jobs
        wait when there is no embedder."""
        clock = self.index.clock
        report = JobReport()
        if stages is None:
            stages = jobs.STAGES if self.index.embedder is not None else (jobs.CONVERT, jobs.ENRICH)
        while limit is None or report.done + report.skipped + report.retry < limit:
            job = jobs.claim(self.store, stages, clock())
            if job is None:
                break
            try:
                skip = self._run_job(job)
            except Exception as exc:  # logged, retried with backoff
                msg = f"{type(exc).__name__}: {exc}"
                log.warning("%s job %d failed: %s", job.stage, job.id, msg, exc_info=True)
                state = jobs.fail(self.store, job, msg, clock())
                report.errors.append(f"{job.stage}: {msg}")
                if state == jobs.FAILED:
                    report.failed += 1
                else:
                    report.retry += 1
                continue
            if skip is not None:
                jobs.finish(self.store, job, clock(), jobs.SKIPPED, skip.reason, skip.fix)
                report.skipped += 1
            else:
                jobs.finish(self.store, job, clock())
                report.done += 1
        return report

    def _run_job(self, job: jobs.Job) -> Skip | None:
        if job.stage == jobs.CONVERT:
            return self._convert(job)
        if job.stage == jobs.ENRICH:
            self.enrich(job.version_id)
            return None
        if job.stage == jobs.EMBED:
            self._embed(job.version_id)
            return None
        raise ValueError(f"unknown stage {job.stage}")

    def version(self, vid: int):
        """The version row `vid` with the key, name, path, and source (`sid`)
        of its item."""
        row = self.store.one(
            "SELECT v.*, i.key, i.name, i.path, i.source_id AS sid FROM version v"
            " JOIN item i ON i.id = v.item_id WHERE v.id = ?",
            (vid,),
        )
        if row is None:
            raise KeyError(f"no version {vid}")
        return row

    def _blob(self, v) -> Blob | Skip:
        if v["blob"] is not None:
            data = bytes(v["blob"])
        elif v["path"]:
            data = _read_file(Path(v["path"]), ContentDigest.from_json(loads(v["digest"])))
        else:
            # A large blob of a source that can give it again was deleted
            # after its first conversion (`retention.after_convert`).
            data = retention.refetch(self.index, v)
        if isinstance(data, Skip):
            return data
        extra = loads(v["extra"]) or {}
        return Blob(
            data=data,
            name=v["name"] or v["key"],
            media_type=v["media_type"],
            owner_emails=self.index.owner_emails,
            path=Path(v["path"]) if v["path"] else None,
            extra=extra,
        )

    def router(self, sid: str, *, local_only: bool = False) -> Router:
        """The converter router of a source. `local_only`: no external
        converter (an item of another person's text never leaves the device)."""
        prefs = self.index.source(sid)["prefs"]

        def log_external(conv: Converter, blob: Blob) -> None:
            self.index.log_disclosure(
                conv.recipient or conv.name, conv.name, "file for conversion", sid
            )

        return Router(
            self.index.converters,
            prefer=prefs.get("prefer", []),
            allow_external=[] if local_only else prefs.get("allow_external", []),
            on_external=log_external,
        )

    def _convert(self, job: jobs.Job) -> Skip | None:
        blob = self._blob(self.version(job.version_id))
        if isinstance(blob, Skip):
            return blob
        other = third_party.marked(blob.extra)
        try:
            doc = self.router(job.source_id, local_only=other).convert(blob)
        except Skipped as exc:
            return exc.skip
        if other:  # a received mail, its attachment, a file of another owner
            doc = third_party.as_context(doc)
        summary = None if other else blob.extra.get("summary")
        if summary:  # a repository summary from the Git source (a hint, not evidence)
            hint = Extracted.from_json(summary)
            doc.markdown = (doc.markdown + "\n\n" + hint.text).strip()
            doc.blocks = blocks_from_markdown(doc.markdown)
            doc.meta = {**doc.meta, "repo": hint.meta}
            doc.title = hint.title or doc.title
        self.store_document(job.version_id, job.source_id, doc)
        retention.after_convert(self.index, job.version_id)
        return None

    def store_document(self, vid: int, sid: str, doc: Document) -> None:
        """Keep the document of one version, chunk it for search, and queue
        enrich and embed."""
        t = self.index.clock()
        with self.store.transaction():
            self.drop_chunks(vid)
            self.store.x(
                "INSERT OR REPLACE INTO document (version_id, converter, converter_version, kind,"
                " title, markdown, blocks, meta, quoted, prose, note, created_at, schema)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    vid,
                    doc.converter,
                    doc.converter_version,
                    doc.kind,
                    doc.title,
                    doc.markdown,
                    dumps([b.to_json() for b in doc.blocks]),
                    dumps(doc.meta),
                    doc.quoted,
                    int(doc.prose),
                    doc.note,
                    self.index.now(),
                    doc.schema,
                ),
            )
            self.store.many(
                "INSERT INTO chunk (version_id, n, anchor, text) VALUES (?, ?, ?, ?)",
                [(vid, c.n, c.anchor, c.text) for c in chunk_document(doc)],
            )
            # Text of other people: chunks of class `context`.
            self.store.many(
                "INSERT INTO context_chunk (version_id, n, anchor, text) VALUES (?, ?, ?, ?)",
                [(vid, c.n, c.anchor, c.text) for c in context_chunks(doc)],
            )
            jobs.enqueue(self.store, jobs.ENRICH, vid, sid, t, reset=True)
            jobs.enqueue(self.store, jobs.EMBED, vid, sid, t, reset=True)

    def drop_chunks(self, vid: int) -> None:
        """Delete the chunks, the context chunks, and the vectors of a version."""
        ids = self.store.q("SELECT id FROM chunk WHERE version_id = ?", (vid,))
        self.index.retrieval.delete(r[0] for r in ids)
        self.store.x("DELETE FROM chunk WHERE version_id = ?", (vid,))
        self.store.x("DELETE FROM context_chunk WHERE version_id = ?", (vid,))

    def enrich(self, vid: int) -> None:
        """Run the enrichers on the document of version `vid`, keep their
        facts, and add an `understand` job if the version needs one."""
        index = self.index
        doc = index.document(vid)
        if doc is None:
            return
        prefs = index.source(self.version(vid)["sid"])["prefs"]
        allowed = set(prefs.get("allow_external", []))
        ctx = EnrichContext(vocab=index.vocab, item=kind_rules.item_info(index, vid))
        extractor = f"{doc.converter}@{doc.converter_version}"
        rows = []
        for e in index.enrichers:
            if e.external and e.name not in allowed:
                continue
            check_enricher(e, e.name in allowed)
            for f in e.enrich(doc, ctx):
                span = fact_span(doc, f)
                rows.append(
                    (
                        vid,
                        f.kind,
                        f.value,
                        f.score,
                        dumps(f.data),
                        e.name,
                        e.version,
                        None if span is None else dumps(span),
                        extractor,
                    )
                )
        with self.store.transaction():
            # The facts of the `understand` stage (a model call) stay.
            self.store.x(
                "DELETE FROM fact WHERE version_id = ? AND enricher != ?", (vid, "understand")
            )
            self.store.many(
                "INSERT INTO fact (version_id, kind, value, score, data, enricher,"
                " enricher_version, span, extractor) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
        understand.plan(index, vid)

    def _embed(self, vid: int) -> None:
        emb = self.index.embedder
        if emb is None or not self.store.ensure_vec(emb.ident(), emb.dim):
            return
        rows = self.store.q(
            "SELECT id, text FROM chunk WHERE version_id = ? AND embedded = 0 ORDER BY n", (vid,)
        )
        for i in range(0, len(rows), EMBED_BATCH):
            part = rows[i : i + EMBED_BATCH]
            vecs = emb.embed([r["text"] for r in part])
            with self.store.transaction():
                for r, vec in zip(part, vecs, strict=True):
                    self.index.retrieval.upsert(r["id"], vec)
                    self.store.x("UPDATE chunk SET embedded = 1 WHERE id = ?", (r["id"],))

    def queue_embeddings(self) -> int:
        """Queue embed jobs for all chunks without a vector (for example after
        the embedder changed). Return the number of versions."""
        t = self.index.clock()
        rows = self.store.q(
            "SELECT DISTINCT c.version_id, v.source_id FROM chunk c"
            " JOIN version v ON v.id = c.version_id WHERE c.embedded = 0"
        )
        with self.store.transaction():
            for vid, sid in rows:
                jobs.enqueue(self.store, jobs.EMBED, vid, sid, t, reset=True)
        return len(rows)

    # ------------------------------------------------------------- progress

    def progress_counts(self, sid: str) -> dict:
        """The counts of `progress` with no lists: `total`, `indexed`,
        `converting`, `embedding`."""
        total = self.store.one(
            "SELECT count(*) FROM item WHERE source_id = ? AND present = 1", (sid,)
        )[0]
        indexed = self.store.one(
            "SELECT count(*) FROM item i JOIN version v ON v.item_id = i.id"
            " AND v.n = (SELECT max(n) FROM version WHERE item_id = i.id)"
            " JOIN job j ON j.version_id = v.id AND j.stage = 'convert'"
            " WHERE i.source_id = ? AND i.present = 1"
            " AND j.state IN ('done', 'skipped', 'failed')",
            (sid,),
        )[0]
        c = jobs.counts(self.store, sid)

        def waiting(stage: str) -> int:
            s = c.get(stage, {})
            return s.get(jobs.QUEUED, 0) + s.get(jobs.RUNNING, 0)

        return {
            "converting": waiting(jobs.CONVERT) + waiting(jobs.ENRICH),
            "embedding": waiting(jobs.EMBED) if self.index.embedder is not None else 0,
            "indexed": indexed,
            "total": total,
        }

    def progress(self, sid: str) -> dict:
        """Counts for the Sources view and the helper status."""
        counts = self.progress_counts(sid)
        errors = [
            r[0]
            for r in self.store.q(
                "SELECT DISTINCT error FROM job WHERE source_id = ? AND error IS NOT NULL"
                " AND state IN ('queued', 'failed') LIMIT 5",
                (sid,),
            )
        ]
        src = self.store.one("SELECT error FROM source WHERE id = ?", (sid,))
        if src is not None and src[0]:
            errors.insert(0, src[0])
        return {
            "converting": counts["converting"],
            "embedding": counts["embedding"],
            "errors": errors,
            "indexed": counts["indexed"],
            "skipped": [
                {"key": s.key, "name": s.name, "reason": s.reason, "fix": s.fix}
                for s in self.index.skipped(sid)
            ],
            "total": counts["total"],
        }


def _read_file(p: Path, digest: ContentDigest) -> bytes | Skip:
    """The bytes of a file version, or a `Skip` when they cannot be read or
    no longer have the digest of the version."""
    if digest.size > MAX_CONVERT_BYTES:
        return Skip(
            f"too large to convert ({digest.size} bytes)",
            "The file stays as evidence and keeps its date proof.",
        )
    try:
        data = p.read_bytes()
    except FileNotFoundError:
        return Skip("the file was gone before conversion", "Nothing to do.")
    if hash_bytes(data, digest.chunk_size).digest != digest.digest:
        return Skip(
            "the file changed before conversion; the next scan converts the new version",
            "Nothing to do.",
        )
    return data
