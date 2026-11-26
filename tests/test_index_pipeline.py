"""Index pipeline: registries, media types, converters, jobs, search,
relations, and the skipped report. No network, no model download."""

from __future__ import annotations

import io
import shutil
import subprocess
import zipfile
from importlib.metadata import EntryPoint

import pytest
from indexkit import KEY

from anagram.local.index import jobs, registry
from anagram.local.index.convert import (
    CONVERTERS,
    BasicConverter,
    Blob,
    ConversionError,
    Converter,
    ConverterRefused,
    DatalabConverter,
    Document,
    MarkItDownConverter,
    Router,
    Skipped,
    check_converter,
)
from anagram.local.index.enrich import ENRICHERS
from anagram.local.index.local import LocalIndex
from anagram.local.index.media import DOCX, EPUB, PPTX, XLSX, ZIP, sniff_bytes, sniff_file
from anagram.local.sources import (
    SOURCES,
    FolderConnector,
    GitConnector,
    connector_from_config,
    describe_suggestions,
    discover,
)
from anagram.local.sources.git import git_env
from anagram.models.embed import FakeEmbedder

pytestmark = pytest.mark.usefixtures("no_network")
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


class Clock:
    def __init__(self, t: float = 1_790_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


# ------------------------------------------------------------------ fixtures

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
CT = "http://schemas.openxmlformats.org/package/2006/content-types"
RELS = "http://schemas.openxmlformats.org/package/2006/relationships"
OFFDOC = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"


def make_docx(heading: str, body: str) -> bytes:
    """A minimal Word file: content types, one relationship, one part."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(
            "[Content_Types].xml",
            f'<?xml version="1.0"?><Types xmlns="{CT}">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.'
            'relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.'
            'openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
        )
        z.writestr(
            "_rels/.rels",
            f'<?xml version="1.0"?><Relationships xmlns="{RELS}">'
            f'<Relationship Id="rId1" Type="{OFFDOC}" Target="word/document.xml"/>'
            "</Relationships>",
        )
        z.writestr(
            "word/document.xml",
            f'<?xml version="1.0"?><w:document xmlns:w="{W}"><w:body>'
            f'<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>{heading}</w:t></w:r>'
            f"</w:p><w:p><w:r><w:t>{body}</w:t></w:r></w:p></w:body></w:document>",
        )
    return buf.getvalue()


def make_pptx(slides: list[tuple[str, str]]) -> bytes:
    from pptx import Presentation

    prs = Presentation()
    for title, body in slides:
        s = prs.slides.add_slide(prs.slide_layouts[1])
        s.shapes.title.text = title
        s.placeholders[1].text = body
    buf = io.BytesIO()
    prs.save(buf)
    return buf.getvalue()


def make_xlsx(rows: list[list[str]]) -> bytes:
    from openpyxl import Workbook

    wb = Workbook()
    for r in rows:
        wb.active.append(r)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def make_epub_like() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("mimetype", "application/epub+zip")
        z.writestr("META-INF/container.xml", "<container/>")
    return buf.getvalue()


PDF = (
    b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 300 300]/Contents 4 0 R"
    b"/Resources<</Font<</F1 5 0 R>>>>>>endobj\n"
    b"4 0 obj<</Length 52>>stream\nBT /F1 12 Tf 20 200 Td (Lattice cryo results) Tj ET\n"
    b"endstream endobj\n5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n"
    b"trailer<</Root 1 0 R>>\n%%EOF"
)


def _git(repo, *args):
    subprocess.run(  # noqa: S603
        [shutil.which("git"), "-C", str(repo), *args],
        env=git_env(),
        check=True,
        capture_output=True,
    )


def _commit(repo, msg):
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=T", "-c", "user.email=t@example.invalid", "commit", "-qm", msg)


# ---------------------------------------------------------------- registries


def test_builtin_registries():
    assert {"folder", "git", "zotero_file", "zotero_web", "orcid_works", "github"} <= set(
        SOURCES.names()
    )
    assert CONVERTERS.names()[:3] == ["markitdown", "basic", "datalab"]
    assert "chips" in ENRICHERS
    assert isinstance(connector_from_config({"kind": "folder", "root": "."}), FolderConnector)


def test_entry_points_load_and_cannot_replace_builtins(monkeypatch, caplog):
    eps = [
        EntryPoint("basic", "anagram.local.index.convert.builtin:MarkItDownConverter", "g.test"),
        EntryPoint("extra", "anagram.local.index.convert.builtin:BasicConverter", "g.test"),
        EntryPoint("broken", "no_such_module_xyz:Thing", "g.test"),
    ]
    monkeypatch.setattr(registry, "entry_points", lambda group: eps if group == "g.test" else [])
    reg = registry.Registry("g.test")
    reg.register("basic", BasicConverter, builtin=True)
    assert reg.names() == ["basic", "extra"]
    assert reg.get("basic") is BasicConverter  # the built-in wins
    assert reg.get("extra") is BasicConverter
    assert "broken" in reg.errors  # logged, left out
    with pytest.raises(ValueError):
        reg.register("basic", object)


def test_plugin_source_from_config(tmp_path):
    class NoteSource(FolderConnector):
        kind = "notes_plugin"

        def config(self) -> dict:
            return {"kind": self.kind, "root": str(self.root)}

    SOURCES.register("notes_plugin", NoteSource)
    try:
        (tmp_path / "a.md").write_text("# A\n")
        conn = connector_from_config({"kind": "notes_plugin", "root": str(tmp_path)})
        assert isinstance(conn, NoteSource)
        index = LocalIndex(tmp_path.parent / "p.sqlite", KEY)
        sid = index.add_source(conn)
        index.scan()
        assert index.source(sid)["kind"] == "notes_plugin"
        assert [i.key for i in index.items(sid)] == ["a.md"]
    finally:
        SOURCES.unregister("notes_plugin")


@needs_git
def test_discover_suggests_sources(tmp_path):
    root = tmp_path / "work"
    for name in ("repo1", "deep/repo2"):
        repo = root / name
        repo.mkdir(parents=True)
        _git(repo, "init", "-q")
    (root / "refs").mkdir()
    (root / "refs" / "zotero-export.json").write_text('[{"id": "a", "title": "T"}]')
    found = discover(root)
    kinds = [s.kind for s in found]
    assert kinds.count("folder") == 1 and kinds.count("git") == 2
    assert kinds.count("zotero_file") == 1
    assert describe_suggestions(found) == "1 Folder, 2 Git repository, 1 Zotero library"
    for s in found:
        connector_from_config(s.config)  # each suggestion opens


# ------------------------------------------------------------------- sniffing


@pytest.mark.parametrize(
    ("data", "name", "want"),
    [
        (PDF, "notes.txt", "application/pdf"),
        (b"\x89PNG\r\n\x1a\n" + bytes(20), "figure.bin", "image/png"),
        (b"\xff\xd8\xff\xe0" + bytes(20), "x", "image/jpeg"),
        (b"GIF89a" + bytes(10), "x.dat", "image/gif"),
        (make_docx("H", "B"), "report.bin", DOCX),
        (make_pptx([("T", "B")]), "deck", PPTX),
        (make_xlsx([["a", "b"]]), "sheet.zip", XLSX),
        (make_epub_like(), "book", EPUB),
        (make_docx("H", "B")[:4] + b"junk", "plain.zip", ZIP),
        (b"<!DOCTYPE html><html></html>", "page", "text/html"),
        (b"hello world\n", "README", "text/plain"),
        (b"hello world\n", "notes.md", "text/markdown"),
        (b"\x00\x01\x02\x03binary", "notes.md", "application/octet-stream"),
        (b"\x00\x01\x02\x03binary", "data.pptx", PPTX),  # broken, but no better guess
        (b"{\\rtf1 hi}", "x.doc", "application/rtf"),
    ],
)
def test_sniff_media_type(data, name, want):
    assert sniff_bytes(data, name) == want


def test_folder_scan_uses_magic_bytes(tmp_path):
    (tmp_path / "paper.txt").write_bytes(PDF)
    assert sniff_file(tmp_path / "paper.txt") == "application/pdf"
    item = next(iter(FolderConnector(tmp_path).scan({})))
    assert item.media_type == "application/pdf"


# ----------------------------------------------------------------- converters


def _blob(data: bytes, name: str, mt: str | None = None) -> Blob:
    return Blob(data=data, name=name, media_type=mt or sniff_bytes(data, name))


def test_markitdown_converts_office_pdf_and_html():
    md = MarkItDownConverter()
    assert md.available()
    doc = md.convert(_blob(make_docx("Cryo results", "We need GPU hours."), "r.docx"))
    assert doc.converter == "markitdown" and doc.converter_version.endswith("+anagram.1")
    assert [b.kind for b in doc.blocks] == ["heading", "para"]
    assert doc.title == "Cryo results"
    deck = md.convert(_blob(make_pptx([("Aims", "Map NbT7"), ("Needs", "GPU time")]), "d.pptx"))
    slides = [b for b in deck.blocks if b.kind == "slide"]
    assert [s.span.slide for s in slides] == [1, 2]  # the place is in the span
    assert all(s.anchor.startswith("slide-") for s in slides)  # the anchor is by content
    assert any(b.parent == slides[1].anchor and "GPU" in b.text for b in deck.blocks)
    sheet = md.convert(_blob(make_xlsx([["sample", "yield"], ["A1", "3.2"]]), "s.xlsx"))
    assert any(b.kind == "table" for b in sheet.blocks) and not sheet.prose
    pdf = md.convert(_blob(PDF, "p.pdf"))
    assert "Lattice cryo results" in pdf.markdown
    html = md.convert(
        _blob(b"<html><body><h1>Lab</h1><p>We offer beam time.</p></body></html>", "x.html")
    )
    assert "We offer beam time." in html.markdown


def test_basic_converter_keeps_quoted_email_apart():
    eml = (
        b"From: me@lab.org\r\nSubject: Plan\r\n\r\nWe need a cryo slot.\r\n\r\n"
        b"On Mon, X wrote:\r\n> secret third-party text\r\n"
    )
    doc = BasicConverter().convert(_blob(eml, "m.eml", "message/rfc822"))
    assert doc.markdown == "" and "cryo slot" in doc.quoted  # no owner address: fail closed
    blob = Blob(
        data=eml, name="m.eml", media_type="message/rfc822", owner_emails=frozenset({"me@lab.org"})
    )
    doc = BasicConverter().convert(blob)
    assert "cryo slot" in doc.markdown and "third-party" not in doc.markdown
    assert "secret third-party text" in doc.quoted and doc.has_third_party


class FakeRemote(Converter):
    name = "fake-remote"
    external = True
    recipient = "Fake Remote Converter (tests only)"
    cost = "remote"
    accepts = frozenset({"application/x-special"})

    def __init__(self) -> None:
        self.seen: list[str] = []

    def convert(self, blob: Blob) -> Document:
        self.seen.append(blob.name)
        return Document(markdown="remote text about lattice", converter=self.name)


class Flaky(Converter):
    name = "flaky"
    accepts = frozenset({"text/markdown"})

    def __init__(self, fail_times: int) -> None:
        self.fail_times = fail_times

    def convert(self, blob: Blob) -> Document:
        if self.fail_times > 0:
            self.fail_times -= 1
            raise RuntimeError("temporary trouble")
        return Document(markdown=blob.data.decode(), converter=self.name)


def test_router_order_preference_and_external_opt_in():
    remote = FakeRemote()
    convs = [MarkItDownConverter(), BasicConverter(), DatalabConverter(), remote]
    r = Router(convs)
    assert [c.name for c in r.candidates("application/pdf")] == ["markitdown", "basic"]
    assert [c.name for c in Router(convs, prefer=["basic"]).candidates("application/pdf")] == [
        "basic",
        "markitdown",
    ]
    # Datalab is a stub: never a candidate, even with an opt-in.
    assert not DatalabConverter().available()
    assert "datalab" not in [
        c.name for c in Router(convs, allow_external=["datalab"]).candidates("application/pdf")
    ]
    # No opt-in: the external converter is refused, and the reason names it.
    with pytest.raises(Skipped) as exc:
        r.convert(Blob(b"x", "f.special", "application/x-special"))
    assert "Fake Remote Converter" in exc.value.skip.fix and remote.seen == []
    with pytest.raises(ConverterRefused):
        check_converter(remote, allowed=False)
    # A preference alone is not an opt-in.
    with pytest.raises(Skipped):
        Router(convs, prefer=["fake-remote"]).convert(
            Blob(b"x", "f.special", "application/x-special")
        )
    logged = []
    opted = Router(convs, allow_external=["fake-remote"], on_external=lambda c, b: logged.append(c))
    assert opted.convert(Blob(b"x", "f.special", "application/x-special")).converter == (
        "fake-remote"
    )
    assert logged == [remote] and remote.seen == ["f.special"]
    with pytest.raises(Skipped) as exc:
        r.convert(Blob(b"\x00", "f.bin", "application/octet-stream"))
    assert "no converter reads application/octet-stream" in exc.value.skip.reason


def test_router_falls_back_when_a_converter_fails():
    class Broken(MarkItDownConverter):
        def convert(self, blob):
            raise ConversionError("bad")

    doc = Router([Broken(), BasicConverter()]).convert(_blob(PDF, "p.pdf"))
    assert doc.converter == "basic" and "Lattice cryo results" in doc.markdown


# ------------------------------------------------------- pipeline and jobs


def _index(tmp_path, **kw) -> LocalIndex:
    return LocalIndex(tmp_path / "i.sqlite", KEY, **kw)


def test_evidence_first_then_jobs(tmp_path):
    root = tmp_path / "lab"
    root.mkdir()
    (root / "notes.md").write_text("# Notes\n\nWe need statistics help.\n")
    (root / "report.docx").write_bytes(make_docx("Results", "Lattice strain map."))
    index = _index(tmp_path, clock=Clock())
    sid = index.add_source(FolderConnector(root))
    report = index.scan(process=False)
    assert len(report.new) == 2
    # Evidence is pending before any conversion; meaning is not there yet.
    assert len(index.streams.pending(sid)) == 2
    assert index.meaning(sid, "notes.md") is None
    assert jobs.counts(index.store)["convert"] == {"queued": 2}
    p = index.jobs.progress(sid)
    assert p["total"] == 2 and p["indexed"] == 0 and p["converting"] == 2
    done = index.jobs.run()
    assert done.done == 4 and not done.errors  # 2 convert + 2 enrich (no embedder)
    assert index.meaning(sid, "report.docx").converter == "markitdown"
    assert index.meaning(sid, "notes.md").converter == "basic"
    p = index.jobs.progress(sid)
    assert p["indexed"] == 2 and p["converting"] == 0 and p["skipped"] == []


def test_failed_job_retries_with_backoff_then_fails(tmp_path, caplog):
    clock = Clock()
    root = tmp_path / "lab"
    root.mkdir()
    (root / "a.md").write_text("# A\n\nText about lattice strain.\n")
    index = _index(tmp_path, clock=clock, converters=[Flaky(fail_times=2)])
    sid = index.add_source(FolderConnector(root))
    r = index.scan()
    assert len(r.new) == 1
    first = index.jobs.run()
    assert first.done == 0 and first.retry == 0  # already tried once in scan()
    assert "temporary trouble" in index.jobs.progress(sid)["errors"][0]
    assert "temporary trouble" in caplog.text  # logged, not swallowed
    clock.t += jobs.backoff(1)
    assert index.jobs.run().retry == 1  # second failure
    clock.t += jobs.backoff(2) - 1
    assert index.jobs.run().done == 0  # not ready yet
    clock.t += 1
    assert index.jobs.run().done == 2  # convert + enrich
    assert index.meaning(sid, "a.md").converter == "flaky"

    (tmp_path / "x").mkdir()
    always = _index(tmp_path / "x", clock=clock, converters=[Flaky(fail_times=99)])
    sid2 = always.add_source(FolderConnector(root))
    always.scan()
    for _ in range(jobs.MAX_ATTEMPTS):
        clock.t += jobs.BACKOFF_CAP_S
        always.jobs.run()
    assert jobs.counts(always.store)["convert"] == {"failed": 1}
    skipped = always.skipped(sid2)
    assert skipped and skipped[0].reason.startswith("failed: RuntimeError")


def test_skipped_report_and_meaning_by_version(tmp_path):
    root = tmp_path / "lab"
    root.mkdir()
    (root / "blob.bin").write_bytes(b"\x00\x01\x02\x03" * 10)
    (root / "notes.md").write_text("# Notes\n\nWe need cryo-EM time.\n")
    index = _index(tmp_path)
    sid = index.add_source(FolderConnector(root))
    index.scan()
    skipped = index.skipped(sid)
    assert [(s.key, s.media_type) for s in skipped] == [("blob.bin", "application/octet-stream")]
    assert "no converter reads" in skipped[0].reason and skipped[0].fix
    assert index.jobs.progress(sid)["skipped"][0]["key"] == "blob.bin"
    # The skipped file is still evidence.
    assert len(index.streams.pending(sid)) == 2
    m = index.meaning(sid, "blob.bin")
    assert m.extracted.kind == "binary" and "no converter" in m.extracted.note

    (root / "notes.md").write_text("# Notes\n\nWe now offer cryo-EM time.\n")
    index.scan()
    assert "offer" in index.meaning(sid, "notes.md").extracted.text
    assert "need" in index.meaning(sid, "notes.md", version=1).extracted.text  # old meaning stays
    old = index.search("need", all_versions=True)
    assert [h.version for h in old if h.key == "notes.md"] == [1]
    assert not [h for h in index.search("need") if h.key == "notes.md"]


def test_search_text_and_vectors(tmp_path):
    root = tmp_path / "lab"
    root.mkdir()
    (root / "cryo.md").write_text("# Cryo\n\nCryo-EM maps of the NbT7 complex.\n")
    (root / "stats.md").write_text("# Stats\n\nBayesian statistics for growth curves.\n")
    (root / "deck.pptx").write_bytes(make_pptx([("Intro", "Hello"), ("Growth", "Curves fit")]))
    emb = FakeEmbedder()
    index = _index(tmp_path, embedder=emb)
    index.add_source(FolderConnector(root))
    index.scan()
    assert jobs.counts(index.store)["embed"] == {"done": 3}
    hits = index.search("NbT7 cryo")
    assert hits[0].key == "cryo.md" and set(hits[0].via) == {"text", "vector"}
    deck = [h for h in index.search("curves") if h.key == "deck.pptx"]
    pptx = make_pptx([("Intro", "Hello"), ("Growth", "Curves fit")])
    blocks = MarkItDownConverter().convert(_blob(pptx, "deck.pptx")).blocks
    slide2 = next(b for b in blocks if b.kind == "slide" and b.span.slide == 2)
    assert deck and deck[0].anchor.startswith(slide2.anchor + "/")
    # A new embedder makes new vectors; old ones do not mix.
    index.embedder = FakeEmbedder(dim=32)
    assert index.jobs.queue_embeddings() == 0  # vectors are marked per chunk
    assert index.store.ensure_vec(index.embedder.ident(), 32)
    assert index.jobs.queue_embeddings() == 3
    index.jobs.run()
    assert "vector" in index.search("Bayesian")[0].via


def test_external_converter_opt_in_per_source(tmp_path):
    root = tmp_path / "lab"
    root.mkdir()
    (root / "a.special").write_bytes(b"special bytes")

    remote = FakeRemote()
    index = _index(tmp_path, converters=[BasicConverter(), remote])
    sid = index.add_source(FolderConnector(root))
    index.scan(process=False)
    # The folder source sniffs text/plain; give the version a special type.
    index.store.x("UPDATE version SET media_type = 'application/x-special'")
    index.jobs.run()
    assert remote.seen == [] and "Fake Remote Converter" in index.skipped(sid)[0].fix
    index.set_source_prefs(sid, allow_external=["fake-remote"])
    vid = index.store.one("SELECT id FROM version")[0]
    jobs.enqueue(index.store, jobs.CONVERT, vid, sid, index.clock(), reset=True)
    index.jobs.run()
    assert remote.seen == ["a.special"]
    row = index.store.one("SELECT recipient, adapter, source_id FROM disclosure")
    assert tuple(row) == ("Fake Remote Converter (tests only)", "fake-remote", sid)
    assert index.meaning(sid, "a.special").converter == "fake-remote"


@needs_git
def test_structural_relations(tmp_path):
    root = tmp_path / "lab"
    repo = root / "code"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    (repo / "README.md").write_text("# Code\n")
    _commit(repo, "first")
    (root / "notes").mkdir()
    (root / "notes" / "a.md").write_text("# A\n\nSame text.\n")
    other = tmp_path / "other"
    other.mkdir()
    (other / "copy.md").write_text("# A\n\nSame text.\n")
    index = _index(tmp_path)
    folder = index.add_source(FolderConnector(root))
    git = index.add_source(GitConnector(repo))
    second = index.add_source(FolderConnector(other))
    index.scan()
    rel = index.relations()
    readme = index.item_ref(folder, "code/README.md")
    commit = index.items(git)[0]
    proj = f"project:git:{repo.resolve()}"
    assert ("same_project", readme, proj) in rel
    assert ("same_project", index.item_ref(git, commit.key), proj) in rel
    notes_proj = f"project:folder:{(root / 'notes').resolve()}"
    assert ("same_project", index.item_ref(folder, "notes/a.md"), notes_proj) in rel
    dup = [r for r in rel if r[0] == "duplicate_of"]
    pair = {index.item_ref(second, "copy.md"), index.item_ref(folder, "notes/a.md")}
    assert len(dup) == 1 and {dup[0][1], dup[0][2]} == pair  # the later item -> the first
    (root / "notes" / "a.md").write_text("# A\n\nNew text.\n")
    index.scan()
    assert len(index.relations("version_of")) == 1
