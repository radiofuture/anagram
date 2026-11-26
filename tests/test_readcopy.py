"""R5 step 5: the reading copy. Local converters only; a bad file gives view
`file` and never stops a share. No network."""

from __future__ import annotations

import json

import pytest
from readkit import ALL, PNG, csv_bytes, pdf_bytes
from sharekit import commit, make_share_net, people

from anagram.core.crypto.blob import BlobError
from anagram.core.errors import FormatError
from anagram.network.formats.sharing import TABLE_ROWS_MAX, reading_blob_id, validate_reading_copy
from anagram.network.sharing.app import readcopy


@pytest.fixture
def chen(tmp_path):
    net = make_share_net(tmp_path)
    return people(net, tmp_path, "chen")["chen"]


def _copy(client, root):
    doc = client.findings.opening(root)
    paths = {s: m["path"] for s, m in client.vault.evidence_meta(root).items()}
    return readcopy.build(doc, readcopy.read_files(doc, paths))


def test_reading_model_for_each_format(chen, tmp_path):
    files = {name: make() for name, make in ALL.items()}
    root = commit(chen, tmp_path, files, claim="Growth doubled\nmore text")
    copy = _copy(chen, root)
    assert copy["title"] == "Growth doubled"
    by_name = {it["name"]: it for it in copy["items"]}
    assert set(by_name) == set(ALL)
    views = {n: it["view"] for n, it in by_name.items()}
    assert views == {
        "analysis.ipynb": "document",
        "counts.xlsx": "table",
        "data.csv": "table",
        "figure.png": "image",
        "methods.docx": "document",
        "notes.md": "text",
        "paper.pdf": "pdf",
        "talk.pptx": "slides",
    }
    assert by_name["data.csv"]["table"] == {
        "columns": ["sample", "value"],
        "rows": [["s0", "0"], ["s1", "2"], ["s2", "4"]],
        "total_rows": 3,
    }
    assert by_name["counts.xlsx"]["table"]["columns"] == ["gene", "count"]
    assert by_name["counts.xlsx"]["table"]["total_rows"] == 3
    text = lambda n: " ".join(b["text"] for b in by_name[n]["blocks"])  # noqa: E731
    assert "second run failed" in text("notes.md")
    assert "We grew the cells" in text("methods.docx")
    assert "Growth doubled" in text("talk.pptx")
    assert "We fit a model" in text("analysis.ipynb") and "plot(x)" in text("analysis.ipynb")
    assert "Cells grow" in text("paper.pdf")
    # Figures: the docx image (its name made safe) and the notebook output.
    assert [f["id"] for f in by_name["methods.docx"]["figures"]] == ["image_1"]
    assert [f["id"] for f in by_name["analysis.ipynb"]["figures"]] == ["code-1-0"]
    assert by_name["figure.png"]["blocks"] is None and by_name["figure.png"]["size"] == len(PNG)
    assert validate_reading_copy(copy) == copy


def test_large_table_and_figure_limit(chen, tmp_path, monkeypatch):
    root = commit(chen, tmp_path, {"big.csv": csv_bytes(TABLE_ROWS_MAX + 20)})
    (item,) = _copy(chen, root)["items"]
    assert len(item["table"]["rows"]) == TABLE_ROWS_MAX
    assert item["table"]["total_rows"] == TABLE_ROWS_MAX + 20
    monkeypatch.setattr(readcopy, "READING_FIGURES_MAX", len(PNG) + 1)
    root = commit(
        chen, tmp_path, {"m.ipynb": ALL["analysis.ipynb"](), "d.docx": ALL["methods.docx"]()}
    )
    items = _copy(chen, root)["items"]
    assert [len(it["figures"]) for it in items] == [1, 0]
    assert [it["truncated"] for it in items] == [False, True]


def test_a_bad_file_gives_view_file(chen, tmp_path):
    root = commit(
        chen,
        tmp_path,
        {"broken.xlsx": b"not a zip", "broken.ipynb": b"{", "blob.bin": b"\x00\x01"},
    )
    items = _copy(chen, root)["items"]
    assert [(it["name"], it["view"]) for it in items] == [
        ("broken.xlsx", "file"),
        ("broken.ipynb", "file"),
        ("blob.bin", "file"),
    ]
    assert all(it["blocks"] is None and it["table"] is None for it in items)


def test_a_changed_local_file_is_left_out(chen, tmp_path):
    root = commit(chen, tmp_path, {"a.md": b"# A", "b.pdf": pdf_bytes()})
    meta = chen.vault.evidence_meta(root)
    from pathlib import Path

    Path(meta[0]["path"]).write_bytes(b"# changed")
    assert [it["slot"] for it in _copy(chen, root)["items"]] == [1]


def test_seal_and_unseal(chen, tmp_path):
    root = commit(chen, tmp_path, {"a.md": b"# A"})
    copy = _copy(chen, root)
    key, r = chen.grants.content_key(root), bytes.fromhex(root)
    blob = readcopy.seal(copy, key, r)
    assert b"# A" not in blob
    assert readcopy.unseal(blob, key, r) == copy
    with pytest.raises(BlobError):
        readcopy.unseal(blob, bytes(32), r)
    assert len(reading_blob_id(key, r)) == 32


def test_validator_refuses_a_bad_copy():
    with pytest.raises(FormatError):
        validate_reading_copy({"items": [], "made_by": "x", "schema": "other", "title": None})


def test_share_uploads_the_reading_copy_one_time(tmp_path):
    net = make_share_net(tmp_path)
    p = people(net, tmp_path, "chen", "okafor", "varga")
    chen = p["chen"]
    root = commit(chen, tmp_path, {"a.md": b"# A", "d.csv": csv_bytes()})
    chen.shares.share(root, [p["okafor"].device.subject, p["varga"].device.subject])
    key = chen.grants.content_key(root)
    rid = reading_blob_id(key, bytes.fromhex(root))
    assert net.vault.blob_owner(rid) == chen.device.subject
    for g in chen.vault.grants_sent(root):
        (doc,) = net.vault._one("SELECT doc FROM grants WHERE grant_id = ?", g["grant_id"])
        assert rid in json.loads(doc)["blobs"]
    # A sync of the grants posts the same blob list (the node accepts it).
    for g in chen.vault.grants_sent(root):
        chen.vault.add_grant_sent(g["grant_id"], g["root"], g["recipient"], [], g["created_at"])
    assert len(chen.grants.sync_grants()) == 2
