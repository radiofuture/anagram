"""Connectors: folder, Git, GitHub (fake), Zotero (file and fake Web API),
ORCID (fake). Change detection. No network."""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest
from indexkit import KEY, lab, lab_index

from anagram.local.index.local import LocalIndex
from anagram.local.sources import (
    ConnectorError,
    FakeGitHub,
    FakeOrcid,
    FakeZotero,
    FolderConnector,
    GitConnector,
    GitHubConnector,
    GitHubDeviceFlow,
    OrcidWorksConnector,
    ZoteroFileConnector,
    ZoteroWebConnector,
)
from anagram.local.sources.git import git_env
from anagram.local.sources.github import DeviceFlowError

pytestmark = pytest.mark.usefixtures("no_network")
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _git(repo, *args):
    subprocess.run(  # noqa: S603
        [shutil.which("git"), "-C", str(repo), *args],
        env=git_env(),
        check=True,
        capture_output=True,
    )


def test_folder_finds_every_evidence_kind(sim_community, tmp_path):
    sim = sim_community
    chen = lab(sim, "chen")
    root = sim.out_dir / chen["path"]
    index, _ = lab_index(tmp_path / "i.sqlite", root)
    report = index.scan()
    assert not report.errors
    items = index.items()
    files = {i.ref for i in items if i.kind == "file"}
    # Every sim file of the lab (not Git repos) is an item, by relative path.
    want = {
        f["path"][len(chen["path"]) + 1 :]
        for f in sim.ground_truth["files"]
        if f["lab_id"] == chen["id"] and f["kind"] != "git"
    }
    assert want <= files
    kinds = {f["kind"] for f in sim.ground_truth["files"] if f["lab_id"] == chen["id"]}
    assert kinds == {"note", "slides", "email", "zotero", "image", "dataset", "git", "large"}
    # No .git internals; the working files of the repository are there.
    assert not any("/.git/" in r or r.startswith(".git/") for r in files)
    assert "tomas-reyes/code/nbt7-processing/README.md" in files
    # Git commits and Zotero items are their own items.
    assert sum(i.kind == "git_commit" for i in items) == 3
    assert sum(i.kind == "zotero_item" for i in items) == 3
    media = {i.media_type for i in items}
    assert {"text/markdown", "message/rfc822", "image/png", "text/csv"} <= media
    # Large file: committed by hash, size from the digest.
    raw = [i for i in items if i.ref.endswith(".mrcs")]
    assert len(raw) == 1


def test_folder_ignores_os_junk(tmp_path):
    root = tmp_path / "src"
    (root / ".git" / "objects").mkdir(parents=True)
    (root / ".git" / "objects" / "ab").write_bytes(b"x")
    (root / "sub").mkdir()
    for junk in (".DS_Store", "Thumbs.db", "desktop.ini", "._paper.pdf", "~$draft.docx"):
        (root / "sub" / junk).write_bytes(b"junk")
    (root / "sub" / "keep.txt").write_text("keep")
    (root / "link.txt").symlink_to(root / "sub" / "keep.txt")
    keys = [i.key for i in FolderConnector(root).scan({})]
    assert keys == ["sub/keep.txt"]


def test_change_detection(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    (root / "a.md").write_text("# A\n")
    (root / "b.txt").write_text("b\n")
    (root / "c.txt").write_text("c\n")
    index = LocalIndex(tmp_path / "i.sqlite", KEY)
    sid = index.add_source(FolderConnector(root))
    r1 = index.scan()
    assert sorted(k for _, k in r1.new) == ["a.md", "b.txt", "c.txt"]
    assert len(index.streams.pending(sid)) == 3

    r2 = index.scan()
    assert not r2.new and not r2.changed and not r2.removed
    assert sorted(k for _, k in r2.unchanged) == ["a.md", "b.txt", "c.txt"]

    # Touch only: same bytes, new mtime -> unchanged.
    st = (root / "b.txt").stat()
    os.utime(root / "b.txt", ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))
    (root / "a.md").write_text("# A, version 2\n")
    (root / "c.txt").unlink()
    (root / "d.txt").write_text("d\n")
    r3 = index.scan()
    assert [k for _, k in r3.changed] == ["a.md"]
    assert [k for _, k in r3.new] == ["d.txt"]
    assert [k for _, k in r3.removed] == ["c.txt"]
    assert "b.txt" in [k for _, k in r3.unchanged]
    # Pending: 3 first roots + changed a.md + new d.txt.
    assert len(index.streams.pending(sid)) == 5
    a = next(i for i in index.items() if i.key == "a.md")
    assert a.versions == 2
    assert not any(i.key == "c.txt" for i in index.items())
    assert any(i.key == "c.txt" for i in index.items(present_only=False))
    # Each version has its own salted evidence record that opens to the bytes.
    op = index.evidence_opening(sid, "a.md")
    assert op.fields["content"]["size"] == len("# A, version 2\n")
    assert op.root().hex() == a.root


@needs_git
def test_repo_config_cannot_run_commands(tmp_path):
    """Security review 2, fix 4: a repository that a user indexes can come
    from someone else. Its .git/config and hooks must not run anything."""
    repo, marker = tmp_path / "evil", tmp_path / "PWNED"
    repo.mkdir()
    plain = {**git_env(), "GIT_CONFIG_COUNT": "0"}

    def g(*args):
        subprocess.run(  # noqa: S603
            [shutil.which("git"), "-C", str(repo), *args], env=plain, check=True
        )

    g("init", "-q")
    (repo / "README.md").write_text("# Evil\n")
    g("add", "README.md")
    g("-c", "user.name=E", "-c", "user.email=e@example.invalid", "commit", "-q", "-m", "x")
    # A commit with a (fake) signature, so `git log` would call gpg.program.
    head = subprocess.run(  # noqa: S603
        [shutil.which("git"), "-C", str(repo), "cat-file", "commit", "HEAD"],
        env=plain,
        check=True,
        capture_output=True,
    ).stdout.decode()
    hdr, body = head.split("\n\n", 1)
    sig = "gpgsig -----BEGIN PGP SIGNATURE-----\n \n AAAA\n -----END PGP SIGNATURE-----"
    signed = f"{hdr}\n{sig}\n\n{body}"
    oid = (
        subprocess.run(  # noqa: S603
            [shutil.which("git"), "-C", str(repo), "hash-object", "-t", "commit", "-w", "--stdin"],
            env=plain,
            input=signed.encode(),
            check=True,
            capture_output=True,
        )
        .stdout.decode()
        .strip()
    )
    g("update-ref", "HEAD", oid)
    evil = tmp_path / "evil.sh"
    evil.write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n")
    evil.chmod(0o755)
    for name in ("pre-commit", "post-checkout", "reference-transaction", "post-index-change"):
        (repo / ".git" / "hooks" / name).write_text(evil.read_text())
        (repo / ".git" / "hooks" / name).chmod(0o755)
    for key, value in (
        ("core.fsmonitor", str(evil)),
        ("log.showSignature", "true"),
        ("gpg.program", str(evil)),
        ("core.pager", str(evil)),
        ("diff.external", str(evil)),
    ):
        g("config", key, value)
    index = LocalIndex(tmp_path / "i.sqlite", KEY)
    index.add_source(GitConnector(repo))
    index.scan()
    assert not marker.exists()


@needs_git
def test_git_commits_are_evidence(sim_community, tmp_path):
    sim = sim_community
    repo_rec = next(
        f for f in sim.ground_truth["files"] if f["kind"] == "git" and "chen" in f["lab_id"]
    )
    repo = tmp_path / "repo"
    shutil.copytree(sim.out_dir / repo_rec["path"], repo)
    index = LocalIndex(tmp_path / "i.sqlite", KEY)
    sid = index.add_source(GitConnector(repo))
    r1 = index.scan()
    assert len(r1.new) == 3
    keys = [k for _, k in r1.new]
    assert keys[-1] == repo_rec["head"]
    conn = index.connector(sid)
    rec = next(iter(conn.scan({})))
    import json

    body = json.loads(rec.data)
    assert body["record"]["commit"] == keys[0]
    assert len(body["record"]["tree"]) == 40
    assert len(body["record"]["tree_sha256"]) == 64
    # Head commit carries the repository summary as derived meaning.
    m = index.meaning(sid, repo_rec["head"])
    assert "filter_particles.py" in m.extracted.text
    assert "Scripts for NbT7 cryo-EM processing" in m.extracted.text

    assert not index.scan().new
    (repo / "NOTES.md").write_text("More notes\n")
    _git(repo, "add", "NOTES.md")
    _git(
        repo,
        "-c",
        "user.name=T",
        "-c",
        "user.email=t@example.invalid",
        "commit",
        "-q",
        "-m",
        "Add notes",
    )
    r3 = index.scan()
    assert len(r3.new) == 1 and not r3.changed and not r3.removed


def test_github_device_flow_and_commits():
    fake = FakeGitHub(approve_after=2)
    sleeps = []
    flow = GitHubDeviceFlow(fake.client_id, transport=fake, sleep=sleeps.append)
    code = flow.start()
    assert code.user_code == "FAKE-0001"
    token = flow.poll(code)
    assert token == fake.token
    assert sleeps == [5, 5]

    fake.add_commit("lab/repo", "a" * 40, "1" * 40, "Initial import", "2026-09-01T10:00:00Z")
    fake.add_commit("lab/repo", "b" * 40, "2" * 40, "We need GPU hours", "2026-09-08T10:00:00Z")
    conn = GitHubConnector(token, ["lab/repo"], transport=fake, per_page=1)
    items = list(conn.scan({}))
    assert [i.key for i in items] == [f"lab/repo@{'b' * 40}", f"lab/repo@{'a' * 40}"]
    assert all(i.kind == "github_commit" for i in items)
    assert "token" not in str(conn.config())

    with pytest.raises(ConnectorError):
        list(GitHubConnector("wrong", ["lab/repo"], transport=fake).scan({}))
    with pytest.raises(DeviceFlowError):
        GitHubDeviceFlow(fake.client_id, transport=FakeGitHub(deny=True), sleep=sleeps.append).poll(
            code
        )


def test_zotero_file_and_web(sim_community, tmp_path):
    sim = sim_community
    z = next(f for f in sim.ground_truth["files"] if f["kind"] == "zotero")
    items = list(ZoteroFileConnector(sim.out_dir / z["path"]).scan({}))
    assert len(items) == 3
    assert all(i.kind == "zotero_item" for i in items)

    import json

    lib = json.loads((sim.out_dir / z["path"]).read_text())
    fake = FakeZotero(items=lib)
    web = ZoteroWebConnector(fake.user_id, fake.api_key, transport=fake, limit=2)
    got = list(web.scan({}))
    assert [i.digest for i in got] == [i.digest for i in items]
    assert len(fake.calls) == 2  # pagination
    with pytest.raises(ConnectorError):
        list(ZoteroWebConnector(fake.user_id, "bad", transport=fake).scan({}))


def test_orcid_works(tmp_path):
    fake = FakeOrcid()
    orcid = "fake-0000-0001-0000-0001"
    fake.add_work(orcid, 11, "A fictional transporter structure", 2025, "10.5555/x.1", "J Imag")
    fake.add_work(orcid, 12, "Another fictional result", 2024, "10.5555/x.2", "J Notional")
    index = LocalIndex(tmp_path / "i.sqlite", KEY, transport=fake)
    sid = index.add_source(OrcidWorksConnector(orcid, transport=fake))
    report = index.scan()
    assert sorted(k for _, k in report.new) == ["11", "12"]
    items = index.items(sid)
    assert {i.kind for i in items} == {"orcid_work"}
    assert items[0].time.endswith("-01-01T00:00:00Z")
    # Reopen from config: the transport given to the index is used.
    index2 = LocalIndex(tmp_path / "i.sqlite", KEY, transport=fake)
    assert not index2.scan().new


def test_one_bad_source_does_not_stop_a_scan(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    (root / "a.txt").write_text("a")
    index = LocalIndex(tmp_path / "i.sqlite", KEY)
    index.add_source(FolderConnector(root))
    bad = tmp_path / "missing.json"
    index.add_source(ZoteroFileConnector(bad))
    report = index.scan()
    assert len(report.new) == 1
    assert len(report.errors) == 1


@needs_git
def test_git_rev_validation_and_record_separator_in_commit_message(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "a.txt").write_text("hello\n")
    _git(repo, "add", "a.txt")
    _git(
        repo,
        "-c",
        "user.name=T",
        "-c",
        "user.email=t@example.invalid",
        "commit",
        "-q",
        "-m",
        "Msg with \x1e record sep\x1f unit sep",
    )
    for bad_rev in ("--all", "-n1", "--output=/tmp/x", "HEAD --all", "HEAD\nfoo", ""):
        with pytest.raises(ConnectorError):
            GitConnector(repo, rev=bad_rev)
    items = list(GitConnector(repo).scan({}))
    assert len(items) == 1
    import json

    body = json.loads(items[0].data)
    assert "\x1e" in body["record"]["message"]

    # Missing blob object in cat-file --batch fails cleanly with ConnectorError.
    with pytest.raises(ConnectorError, match="missing"):
        GitConnector(repo)._blob_hashes(["0" * 40], {})


def test_v1_connectors_validate_repo_user_id_and_orcid():
    for bad_repo in ("../evil", "owner/repo?x=1", "owner/repo#frag", "onlyone", "a/b/c", ""):
        with pytest.raises(ConnectorError):
            GitHubConnector("tok", [bad_repo])
    for bad_uid in ("../123", "123?foo=bar", "abc", ""):
        with pytest.raises(ConnectorError):
            ZoteroWebConnector(bad_uid, "key")
    for bad_orcid in ("../0000-0000-0000-0000", "0000-0001-0000-0001?x=1", "not-an-orcid", ""):
        with pytest.raises(ConnectorError):
            OrcidWorksConnector(bad_orcid)
