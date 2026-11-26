import csv
import email
import hashlib
import json
import re
import shutil
import subprocess
import tracemalloc
import zipfile
from email import policy
from pathlib import Path
from xml.etree import ElementTree

import pytest

from anagram.sim import LABS, chip_matches, generate_community
from anagram.sim.__main__ import main as sim_main
from anagram.sim.writers import write_large_file

SMALL = 64 * 1024
CANARY_RE = re.compile(rb"CANARY-[A-Z]+-\d{3}-[0-9a-f]{12}")
GIT = shutil.which("git") or "git"
HAS_GIT = shutil.which("git") is not None


@pytest.fixture(scope="module")
def community(tmp_path_factory):
    out = tmp_path_factory.mktemp("sim") / "community"
    return generate_community(out, seed=42, large_bytes=SMALL)


def tree_digest(root: Path) -> dict[str, str]:
    """Hash every file outside .git folders."""
    return {
        p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file() and ".git" not in p.relative_to(root).parts
    }


def git(repo: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603 - fixed program, test data
        [GIT, "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout


def files_of(community, kind):
    return [f for f in community.ground_truth["files"] if f["kind"] == kind]


# --- Determinism -----------------------------------------------------------


def test_same_seed_gives_same_bytes(tmp_path, community):
    again = generate_community(tmp_path / "again", seed=42, large_bytes=SMALL)
    assert tree_digest(community.out_dir) == tree_digest(again.out_dir)
    heads = [f["head"] for f in files_of(community, "git")]
    assert heads == [f["head"] for f in files_of(again, "git")]
    if HAS_GIT:
        assert all(heads)


def test_other_seed_gives_other_bytes(tmp_path, community):
    other = generate_community(tmp_path / "other", seed=43, large_bytes=SMALL)
    a, b = tree_digest(community.out_dir), tree_digest(other.out_dir)
    assert a.keys() == b.keys()
    assert a["canaries.json"] != b["canaries.json"]


def test_refuses_non_empty_out_dir(tmp_path):
    (tmp_path / "x").write_text("x")
    with pytest.raises(FileExistsError):
        generate_community(tmp_path, seed=1, large_bytes=SMALL)


# --- Files parse -----------------------------------------------------------


def test_every_listed_file_exists_with_hash(community):
    for f in community.ground_truth["files"]:
        path = community.out_dir / f["path"]
        assert path.exists(), f["path"]
        if f["sha256"] is not None:
            data = path.read_bytes()
            assert len(data) == f["size"]
            assert hashlib.sha256(data).hexdigest() == f["sha256"]


def test_pptx_is_valid_ooxml(community):
    decks = files_of(community, "slides")
    assert len(decks) == len(LABS)
    for f in decks:
        with zipfile.ZipFile(community.out_dir / f["path"]) as zf:
            assert zf.testzip() is None
            names = zf.namelist()
            assert names[0] == "[Content_Types].xml"
            for name in names:
                if name.endswith((".xml", ".rels")):
                    ElementTree.fromstring(zf.read(name))  # noqa: S314 - own output
            assert "ppt/slides/slide1.xml" in names
            # Each relationship target exists in the package.
            for name in names:
                if not name.endswith(".rels"):
                    continue
                base = name.replace("_rels/", "").removesuffix(".rels")
                folder = base.rsplit("/", 1)[0] if "/" in base else ""
                for rel in ElementTree.fromstring(zf.read(name)):  # noqa: S314 - own output
                    target = rel.get("Target")
                    parts = (folder.split("/") if folder else []) + target.split("/")
                    resolved = []
                    for part in parts:
                        if part == "..":
                            resolved.pop()
                        elif part:
                            resolved.append(part)
                    if name == "_rels/.rels":
                        resolved = target.split("/")
                    assert "/".join(resolved) in names, (name, target)


def test_png_has_signature_and_text(community):
    for f in files_of(community, "image"):
        data = (community.out_dir / f["path"]).read_bytes()
        assert data.startswith(b"\x89PNG\r\n\x1a\n")
        assert data[12:16] == b"IHDR" and data.endswith(b"IEND\xaeB`\x82")


def test_eml_parses_with_quoted_third_party(community):
    mails = files_of(community, "email")
    assert len(mails) == 2 * len(LABS)
    for f in mails:
        msg = email.message_from_bytes(
            (community.out_dir / f["path"]).read_bytes(), policy=policy.default
        )
        assert msg["From"] and msg["To"] and msg["Message-ID"]
        body = msg.get_body().get_content()
        assert "wrote:\n> " in body


def test_csv_parses(community):
    for f in files_of(community, "dataset"):
        with (community.out_dir / f["path"]).open(newline="") as fh:
            rows = list(csv.reader(fh))
        assert len(rows) > 10
        assert all(len(r) == len(rows[0]) for r in rows)
        assert rows[0][-1] == "note"


def test_zotero_is_csl_json(community):
    for f in files_of(community, "zotero"):
        items = json.loads((community.out_dir / f["path"]).read_text())
        assert len(items) >= 3
        for item in items:
            assert {"id", "type", "title", "author", "issued"} <= item.keys()
            assert item["DOI"].startswith("10.5555/fake.")


@pytest.mark.skipif(not HAS_GIT, reason="git is not installed")
def test_git_repos_have_history(community):
    repos = files_of(community, "git")
    assert len(repos) == len(LABS)
    for f in repos:
        repo = community.out_dir / f["path"]
        log = git(repo, "log", "--format=%H %aI %cI").splitlines()
        assert len(log) == f["commits"] == 3
        assert log[0].split()[0] == f["head"]
        assert all(line.split()[1] == line.split()[2] for line in log)
        assert git(repo, "status", "--porcelain") == ""


# --- Canaries --------------------------------------------------------------


def _read_canary_target(root: Path, entry: dict) -> bytes:
    path = root / entry["path"]
    if entry["member"]:
        with zipfile.ZipFile(path) as zf:
            return zf.read(entry["member"])
    return path.read_bytes()


def test_canaries_unique_and_present(community):
    root = community.out_dir
    values = [c["canary"] for c in community.canaries]
    assert len(values) == len(set(values))
    labs = {lab.id: lab.slug for lab in LABS}
    for c in community.canaries:
        assert CANARY_RE.fullmatch(c["canary"].encode())
        assert c["canary"].startswith(f"CANARY-{labs[c['lab_id']].upper()}-")
        assert c["canary"].encode() in _read_canary_target(root, c), c
        if c["kind"] == "git" and HAS_GIT:
            repo = root / c["path"].rsplit("/", 1)[0]
            assert c["canary"] in git(repo, "show", "HEAD:README.md")


def test_every_canary_in_files_is_in_manifest(community):
    root = community.out_dir
    listed = {c["canary"].encode() for c in community.canaries}
    found = set()
    for p in (root / "labs").rglob("*"):
        if not p.is_file() or ".git" in p.relative_to(root).parts:
            continue
        data = p.read_bytes()
        if p.suffix == ".pptx":
            with zipfile.ZipFile(p) as zf:
                data = b"".join(zf.read(n) for n in zf.namelist())
        found |= set(CANARY_RE.findall(data))
    assert found == listed


def test_each_lab_has_every_evidence_kind_and_canary_kind(community):
    kinds = {"note", "image", "slides", "email", "dataset", "git", "zotero", "large"}
    for lab in LABS:
        have = {f["kind"] for f in community.ground_truth["files"] if f["lab_id"] == lab.id}
        assert have == kinds, lab.slug
        canary_kinds = {c["kind"] for c in community.canaries if c["lab_id"] == lab.id}
        assert canary_kinds == {"note", "png", "pptx", "eml", "csv", "git", "zotero", "large"}
        assert any(c["third_party"] for c in community.canaries if c["lab_id"] == lab.id)


def test_canary_manifest_file_matches_result(community):
    data = json.loads((community.out_dir / "canaries.json").read_text())
    assert data["canaries"] == community.canaries


# --- Ground truth ----------------------------------------------------------


def test_ground_truth_ids_and_people(community):
    gt = community.ground_truth
    assert gt["fictional"] is True
    orcids = [p["orcid"] for p in gt["people"]]
    assert len(orcids) == len(set(orcids))
    for orcid in orcids:
        assert re.fullmatch(r"fake-0000-000\d-\d{4}-\d{4}", orcid)
    for inst in gt["institutions"]:
        assert re.fullmatch(r"fake-ror-[0-9a-f]{9}", inst["id"])
    inst_ids = {i["id"] for i in gt["institutions"]}
    for lab in gt["labs"]:
        assert lab["institution_id"] in inst_ids
        assert 2 <= len(lab["people"]) <= 3
        roles = {p["role"] for p in gt["people"] if p["lab_id"] == lab["id"]}
        assert {"pi", "scientist"} <= roles
        for kind in ("topics", "needs", "offers"):
            assert lab["profile"][kind]
            for chip in lab["profile"][kind]:
                assert chip["label"] and chip["id"].startswith("tbd:")
    for p in gt["people"]:
        assert (community.out_dir / p["path"]).is_dir()


def test_planted_matches_follow_from_chips_and_block(community):
    gt = community.ground_truth
    ids = {lab.slug: lab.id for lab in LABS}

    def norm(pairs):
        return {frozenset(p) for p in pairs}

    by_chips = norm([[ids[a], ids[b]] for a, b in chip_matches()])
    planted = norm(m["labs"] for m in gt["planted_matches"])
    assert planted == by_chips
    assert planted == norm(
        [
            [ids["chen"], ids["okafor"]],
            [ids["varga"], ids["helix"]],
            [ids["chen"], ids["helix"]],
            [ids["okafor"], ids["helix"]],
        ]
    )
    assert gt["blocks"] == [
        {
            "blocker": ids["helix"],
            "target_kind": "lab",
            "target": ids["okafor"],
            "reason": gt["blocks"][0]["reason"],
        }
    ]
    blocked = {frozenset((b["blocker"], b["target"])) for b in gt["blocks"]}
    assert norm(gt["expected_matches"]) == planted - blocked
    assert norm(gt["suppressed_matches"]) == {frozenset((ids["okafor"], ids["helix"]))}


def test_planted_needs_appear_in_private_text(community):
    """An extractor must be able to find each lab's needs and offers in its notes."""
    root = community.out_dir
    for lab in LABS:
        text = " ".join(
            (root / f["path"]).read_text().lower()
            for f in community.ground_truth["files"]
            if f["lab_id"] == lab.id and f["kind"] == "note"
        )
        for chip in lab.need_chips + lab.offer_chips:
            words = [w.rstrip("s") for w in chip.lower().split() if len(w) > 3]
            assert any(w in text for w in words), (lab.slug, chip)


# --- Large file and CLI ----------------------------------------------------


def test_large_file_is_streamed(tmp_path):
    size = 16 * 1024 * 1024
    path = tmp_path / "big.bin"
    tracemalloc.start()
    try:
        digest = write_large_file(path, size, "seed", b"# head\n", chunk=128 * 1024)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert path.stat().st_size == size
    assert peak < 2 * 1024 * 1024
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    assert h.hexdigest() == digest
    again = tmp_path / "again.bin"
    assert write_large_file(again, size, "seed", b"# head\n") == digest


def test_large_file_size_in_community(community):
    for f in files_of(community, "large"):
        assert (community.out_dir / f["path"]).stat().st_size == SMALL


def test_cli(tmp_path, capsys):
    assert sim_main([str(tmp_path / "c"), "--seed", "5", "--large-mb", "0.01"]) == 0
    assert "4 labs, 11 people" in capsys.readouterr().out
    assert sim_main([str(tmp_path / "c")]) == 2
