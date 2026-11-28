"""The sharing routes of the local UI (`shell/ui/routers/sharing.py`),
the history, the live events, and the task `shares.sync`. Two members, each
with a UI of their own, on one node with the read ledger. No network."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from readkit import PNG, csv_bytes, ipynb_bytes
from sharekit import commit, make_share_net
from test_ui_models_api import RecordingBus

from anagram.core.errors import ClientError
from anagram.proofs.records import LINK_SUPERSEDES, Link
from anagram.shell.ui.server import create_ui_app
from anagram.shell.ui.service import UIService

pytestmark = pytest.mark.usefixtures("no_network")

PORT = 41998
TOKEN = "launch-token-for-sharing-tests"  # noqa: S105 - a test value
BASE = f"http://127.0.0.1:{PORT}"
ORIGIN = {"Origin": BASE}
HOSTILE_HTML = b"<html><script>alert(1)</script><p>Hi</p></html>"
HOSTILE_SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
FILES = {
    "notes.md": b"# Notes\n\nThe second run failed.\n",
    "figure.png": PNG,
    "data.csv": csv_bytes(),
    "page.html": HOSTILE_HTML,
    "logo.svg": HOSTILE_SVG,
    "analysis.ipynb": ipynb_bytes(),
}
ROUTES = (
    ("GET", "/api/share/targets"),
    ("POST", "/api/findings/ab/shares"),
    ("GET", "/api/findings/ab/shares"),
    ("POST", "/api/findings/ab/shares/stop"),
    ("POST", "/api/findings/ab/rekey"),
    ("GET", "/api/findings/ab/preview"),
    ("GET", "/api/history"),
    ("GET", "/api/history/ab/cd/record"),
    ("GET", "/api/shared"),
    ("POST", "/api/shared/ab/open"),
    ("GET", "/api/shared/ab/files/0"),
    ("GET", "/api/shared/ab/figures/0/f"),
    ("GET", "/api/shared/ab/proof"),
    ("POST", "/api/shared/ab/save"),
    ("GET", "/api/reader-claims"),
    ("POST", "/api/reader-claims/ab"),
    # The rings and the inbox of the first screens.
    ("POST", "/api/findings/ab/share"),
    ("POST", "/api/findings/ab/revoke"),
    ("GET", "/api/rings"),
    ("POST", "/api/rings"),
    ("POST", "/api/rings/ab/members"),
    ("POST", "/api/rings/ab/members/remove"),
    ("GET", "/api/inbox"),
    ("POST", "/api/inbox/ab/open"),
    ("GET", "/api/inbox/ab/files/n"),
)


class Member:
    """One member with a home, a client on the share net, and a UI app."""

    def __init__(self, net, tmp_path, name: str) -> None:
        self.home = tmp_path / name
        self.joined = net.join(self.home, f"fake-{name}", name.title())
        self.svc = UIService(self.home, transport=net.transport, clock=net.clock)
        self.bus = RecordingBus()
        self.app = create_ui_app(self.svc, port=PORT, token=TOKEN, bus=self.bus)
        self.tc = TestClient(self.app, base_url=BASE)
        self.sharing = self.app.state.sharing
        self.subject = self.joined.client.device.subject

    def launch(self) -> Member:
        assert self.tc.get(f"/open/{TOKEN}", follow_redirects=False).status_code == 303
        return self

    def call(self, method: str, path: str, body: dict | None = None, status: int = 200):
        r = self.tc.request(method, path, json=body, headers=ORIGIN)
        assert r.status_code == status, (method, path, r.status_code, r.text)
        return r

    def json(self, method: str, path: str, body: dict | None = None, status: int = 200):
        return self.call(method, path, body, status).json()

    def events(self, kind: str) -> list[dict]:
        return [d for t, d in self.bus.seen if t == kind]

    def commit(self, tmp_path, files: dict, claim: str, **kw) -> str:
        with self.svc.session() as c:
            return commit(c, tmp_path, files, claim=claim, **kw)


@pytest.fixture
def two(tmp_path):
    net = make_share_net(tmp_path)
    chen = Member(net, tmp_path, "chen").launch()
    lee = Member(net, tmp_path, "lee").launch()
    return net, chen, lee


def _plain_files(home) -> list[str]:
    base = home / "received"
    if not base.exists():
        return []
    return sorted(
        str(p.relative_to(base))
        for p in base.rglob("*")
        if p.is_file() and not p.name.endswith(".blob")
    )


# ----------------------------------------------------------------- boundary


def test_sharing_routes_obey_the_local_ui_boundary(tmp_path):
    net = make_share_net(tmp_path)
    m = Member(net, tmp_path, "chen")
    paths = {
        (meth, r.path)
        for r in m.app.routes
        for meth in getattr(r, "methods", None) or ()
        if getattr(getattr(r, "endpoint", None), "__module__", "")
        == "anagram.shell.ui.routers.sharing"
    }
    expected = {
        (meth, p.replace("/ab/cd/", "/{finding_id}/{subject}/")
         .replace("/ab/files/0", "/{grant_id}/files/{slot}")
         .replace("/ab/figures/0/f", "/{grant_id}/figures/{slot}/{figure_id}")
         .replace("/api/shared/ab", "/api/shared/{grant_id}")
         .replace("/api/findings/ab", "/api/findings/{root}")
         .replace("/api/reader-claims/ab", "/api/reader-claims/{invite_id}")
         .replace("/api/rings/ab", "/api/rings/{ring}")
         .replace("/api/inbox/ab/files/n", "/api/inbox/{grant_id}/files/{name}")
         .replace("/api/inbox/ab", "/api/inbox/{grant_id}"))
        for meth, p in ROUTES
    }  # fmt: skip
    assert paths == expected
    for method, path in ROUTES:
        r = m.tc.request(method, path, json={}, headers=ORIGIN)
        assert r.status_code == 401, path  # no cookie
    m.launch()
    for method, path in ROUTES:
        evil = m.tc.request(method, path, json={}, headers={"Origin": "http://evil.example"})
        assert evil.status_code == 403, path
        cross = m.tc.request(
            method, path, json={}, headers={**ORIGIN, "Sec-Fetch-Site": "cross-site"}
        )
        assert cross.status_code == 403, path
        if method != "GET":
            assert m.tc.request(method, path, json={}).status_code == 403, path
    assert "shares.sync" in m.app.state.ctx.tasks.names()


def test_task_interval_follows_open_pages_and_invites(tmp_path):
    net = make_share_net(tmp_path)
    m = Member(net, tmp_path, "chen")
    assert m.sharing.interval(m.bus) == 900
    sub = m.bus.subscribe()
    assert m.sharing.interval(m.bus) == 60
    sub.close()
    assert m.sharing.interval(m.bus) == 900
    m.sharing.open_invites = True
    assert m.sharing.interval(m.bus) == 60


# ---------------------------------------------------- share, read, history


def test_share_read_and_history_across_two_members(two, tmp_path):
    _, chen, lee = two
    root = chen.commit(tmp_path, FILES, "Two runs, one failed.\nDetails follow.")
    out = chen.json("POST", f"/api/findings/{root}/shares", {"targets": [lee.subject]})
    assert out["shared"] == [{"label": "Lee", "people": 1, "target": lee.subject}]
    assert out["waiting"] == [] and out["invited"] == []
    assert out["finding"]["root"] == root
    fid = out["finding"]["id"]
    assert chen.events("share.delivered") == [{"finding_id": fid, "subject": lee.subject}]

    # Lee: the task publishes the new grant; the list has a readable row.
    lee.sharing.sync()
    (got,) = lee.events("shared.received")
    gid = got["grant_id"]
    assert got["sender"] == "Chen"  # a name, as in GET /api/shared (Home shows it)
    (row,) = lee.json("GET", "/api/shared")
    assert row["grant_id"] == gid and row["ready"] is True and row["new"] is True
    assert row["sender"] == "Chen" and row["title"] is None
    lee.sharing.sync()  # a second run: no second event
    assert len(lee.events("shared.received")) == 1

    # Lee opens it: the reading model, and no plaintext on disk.
    model = lee.json("POST", f"/api/shared/{gid}/open")
    assert model["owner"] == {"label": "Chen", "subject": chen.subject}
    assert model["claim"].startswith("Two runs") and model["verified"] is True
    items = {it["name"]: it for it in model["items"]}
    assert set(items) == set(FILES)
    assert _plain_files(lee.home) == []
    (row,) = lee.json("GET", "/api/shared")
    assert row["new"] is False and row["title"] == "Two runs, one failed."
    assert row["opened_at"] is not None

    # Originals: PDF, images, and text inline; HTML and SVG as attachments.
    def file(name):
        r = lee.call("GET", f"/api/shared/{gid}/files/{items[name]['slot']}")
        return r.headers["content-type"], r.headers["content-disposition"], r.content

    ctype, disp, data = file("figure.png")
    assert ctype == "image/png" and disp.startswith("inline") and data == PNG
    ctype, disp, data = file("notes.md")
    assert ctype.startswith("text/plain") and disp.startswith("inline")
    for name in ("page.html", "logo.svg"):
        ctype, disp, data = file(name)
        assert ctype == "application/octet-stream" and disp.startswith("attachment"), name
        assert data == FILES[name]
    lee.call("GET", f"/api/shared/{gid}/files/99", status=404)
    lee.call("GET", f"/api/shared/{'0' * 32}/files/0", status=404)
    lee.call("GET", "/api/shared/not-a-grant/files/0", status=404)
    # A figure of the notebook (reading copy).
    (fig,) = items["analysis.ipynb"]["figures"]
    r = lee.call("GET", f"/api/shared/{gid}/figures/{items['analysis.ipynb']['slot']}/{fig['id']}")
    assert r.headers["content-type"] == "image/png" and r.content == PNG
    # The proof bundle with the opened fields.
    proof = lee.call("GET", f"/api/shared/{gid}/proof")
    assert proof.headers["content-disposition"].startswith("attachment")
    assert json.loads(proof.content)["subject"]["root"] == root

    # Chen: the task checks the read and publishes it; the history says Read.
    chen.sharing.sync()
    (read,) = chen.events("share.read")
    assert read["subject"] == lee.subject and read["finding_id"] == fid and read["reads"] == 1
    (h,) = chen.json("GET", f"/api/history?finding={root}")
    assert h["state"] == "read" and h["reads"] == 1 and h["devices"] == 1
    assert h["person"] == {"kind": "member", "label": "Lee", "subject": lee.subject}
    assert h["finding"]["title"] == "Two runs, one failed."
    assert h["evidence"]["grant_receipt"] and len(h["evidence"]["read_receipts"]) == 1
    assert chen.json("GET", f"/api/history?person={lee.subject}") == [h]
    aud = chen.json("GET", f"/api/findings/{root}/shares")
    assert aud["audience"] == [h] and [v["root"] for v in aud["versions"]] == [root]
    rec = chen.call("GET", f"/api/history/{fid}/{lee.subject}/record")
    assert rec.headers["content-disposition"].startswith("attachment")
    doc = json.loads(rec.content)
    assert doc["schema"] == "anagram.share_record.v1"
    assert len(doc["grants"]) == 1 and len(doc["reads"]) == 1 and doc["fetch_events"]

    # Stop: Lee keeps the copy that Lee opened; the node gives nothing new.
    out = chen.json("POST", f"/api/findings/{root}/shares/stop", {"target": lee.subject})
    assert out["stopped"] == lee.subject
    assert chen.events("share.stopped") == [{"finding_id": fid, "target": lee.subject}]
    assert chen.json("GET", f"/api/history?finding={root}")[0]["state"] == "stopped"
    (row,) = lee.json("GET", "/api/shared")
    assert row["withdrawn"] is True and row["ready"] is True
    again = lee.json("POST", f"/api/shared/{gid}/open")
    assert again["claim"] == model["claim"]


def test_save_a_copy_and_preview(two, tmp_path):
    _, chen, lee = two
    root = chen.commit(tmp_path, {"notes.md": FILES["notes.md"]}, "A note")
    preview = chen.json("GET", f"/api/findings/{root}/preview")
    assert preview["preview"] is True and preview["owner"]["label"] == "You"
    assert [it["name"] for it in preview["items"]] == ["notes.md"]
    chen.json("POST", f"/api/findings/{root}/shares", {"targets": [lee.subject]})
    (row,) = lee.json("GET", "/api/shared")
    gid = row["grant_id"]
    lee.json("POST", f"/api/shared/{gid}/open")
    out = lee.json("POST", f"/api/shared/{gid}/save", {"folder": str(tmp_path / "saved")})
    assert out == {"files": ["0-notes.md"]} or out["files"][0].endswith("notes.md")
    assert (tmp_path / "saved" / out["files"][0]).read_bytes() == FILES["notes.md"]
    lee.json("POST", f"/api/shared/{gid}/save", {"folder": "relative/place"}, status=400)


def test_targets_labs_and_reader_invites(two, tmp_path):
    net, chen, lee = two
    with chen.svc.session() as c:
        lab = c.labs.lab_create("Chen lab")["lab_id"]
        c.labs.lab_add(lab, lee.subject)
    got = chen.json("GET", "/api/share/targets?q=chen lab")
    assert {"detail": "Your lab", "id": f"lab:{lab}", "kind": "lab",
            "label": "Everyone in Chen lab"} in got  # fmt: skip
    (email,) = [t for t in chen.json("GET", "/api/share/targets?q=New@Uni.edu")
                if t["kind"] == "invite_email"]  # fmt: skip
    assert email["id"] == "email:new@uni.edu"
    orcid = chen.json("GET", "/api/share/targets?q=0000-0002-1825-0097")
    assert orcid[0]["kind"] == "invite_orcid"

    root = chen.commit(tmp_path, {"r.md": b"x"}, "Lab result")
    out = chen.json("POST", f"/api/findings/{root}/shares",
                    {"targets": [f"lab:{lab}", "email:new@uni.edu"]})  # fmt: skip
    assert out["shared"] == [{"label": "Everyone in Chen lab", "people": 1,
                              "target": f"lab:{lab}"}]  # fmt: skip
    (inv,) = out["invited"]
    assert inv["label"] == "new@uni.edu" and inv["link"] and inv["mailed"] is True
    assert chen.sharing.open_invites is True
    rows = {h["person"]["kind"]: h for h in chen.json("GET", f"/api/history?finding={root}")}
    assert rows["lab"]["person"]["label"] == "Everyone in Chen lab"
    assert rows["lab"]["state"] == "delivered"
    assert (
        rows["invite"]["state"] == "waiting" and rows["invite"]["person"]["label"] == "new@uni.edu"
    )
    with lee.svc.session() as c:
        c.labs.lab_sync(lab)
        assert [i["title"] for i in c.lab_space.lab_items(lab)] == ["Lab result"]
    chen.json("POST", f"/api/findings/{root}/shares", {"targets": ["nobody"]}, status=400)
    chen.json("POST", f"/api/findings/{root}/shares", {"targets": []}, status=400)


def test_third_party_needs_an_acknowledgement(two, tmp_path):
    _, chen, lee = two
    root = chen.commit(tmp_path, {"mail.txt": b"from a colleague"}, "Mail", third_party=[True])
    got = chen.json("POST", f"/api/findings/{root}/shares", {"targets": [lee.subject]}, status=409)
    assert got["third_party"]
    assert lee.json("GET", "/api/shared") == []
    chen.json("POST", f"/api/findings/{root}/shares",
              {"targets": [lee.subject], "ack_third_party": True})  # fmt: skip
    assert len(lee.json("GET", "/api/shared")) == 1


# --------------------------------------------------- versions and the commit


def test_a_commit_gives_the_new_version_to_the_audience(two, tmp_path):
    net, chen, lee = two
    v1 = chen.commit(tmp_path, {"r.md": b"v1"}, "First")
    chen.json("POST", f"/api/findings/{v1}/shares", {"targets": [lee.subject]})
    v2 = chen.commit(tmp_path, {"r.md": b"v2"}, "Second",
                     links=[Link(LINK_SUPERSEDES, bytes.fromhex(v1))])  # fmt: skip
    out = chen.sharing.follow(v2)  # the commit route (`timestamp`) ends with this step
    assert out == {"held": False, "labs": 0, "people": 1, "waiting": 0}
    assert len(lee.json("GET", "/api/shared")) == 2


def test_timestamp_gives_the_new_version_to_the_audience(tmp_path, monkeypatch):
    """`LibraryUI.timestamp` ends with `SharingUI.follow` (the commit route)."""
    from types import SimpleNamespace

    from anagram.shell.ui import library

    net = make_share_net(tmp_path)
    home = tmp_path / "chen"
    net.join(home, "fake-chen", "Chen")
    svc = UIService(home, transport=net.transport, clock=net.clock)
    draft = SimpleNamespace(id="d", polarity=None)
    bundle = SimpleNamespace(subject=SimpleNamespace(root=bytes.fromhex("ab" * 32)))
    monkeypatch.setattr(library, "draft_findings", lambda idx, **kw: [draft])
    monkeypatch.setattr(library, "approve_finding", lambda c, d, claim, keys: bundle)
    monkeypatch.setattr(library.proposals, "set_state", lambda idx, ref, state: None)
    monkeypatch.setattr(svc.library, "finding", lambda ref: {"id": "x", "root": ref})
    calls = []
    monkeypatch.setattr(svc.sharing, "follow", lambda root: calls.append(root) or {"people": 0})
    assert svc.library.timestamp("d", "A claim", [])["followed"] == {"people": 0}
    assert calls == ["ab" * 32]


def test_old_open_route_reads_through_the_encrypted_store(two, tmp_path):
    _, chen, lee = two
    root = chen.commit(tmp_path, {"notes.md": FILES["notes.md"]}, "A note")
    chen.json("POST", f"/api/findings/{root}/shares", {"targets": [lee.subject]})
    (g,) = lee.json("GET", "/api/inbox")
    view = lee.json("POST", f"/api/inbox/{g['id']}/open")
    assert view["files"] == [{"name": "notes.md", "slot": 0}]
    assert view["reader"] == f"/reader/#{g['id']}" and view["folder"] is None
    assert _plain_files(lee.home) == []
    (g,) = lee.json("GET", "/api/inbox")
    assert g["opened"]["reader"] == view["reader"]
    assert ("resource.stale", {"paths": ["/api/inbox", "/api/shared"]}) in lee.bus.seen


def test_first_sync_moves_old_plaintext_into_the_store(two, tmp_path):
    _, chen, lee = two
    root = chen.commit(tmp_path, {"notes.md": FILES["notes.md"]}, "A note")
    chen.json("POST", f"/api/findings/{root}/shares", {"targets": [lee.subject]})
    with lee.svc.session() as c:
        (g,) = c.grants.inbox()
        c.grants.open_grant(g["grant_id"], lee.home / "received" / g["grant_id"])
    assert _plain_files(lee.home)
    lee.sharing.sync()
    assert _plain_files(lee.home) == []
    assert any(t == "resource.stale" for t, _ in lee.bus.seen)


# ------------------------------------------------------------- the sync


def test_sync_delivers_to_a_person_who_was_waiting(two, tmp_path, monkeypatch):
    _, chen, lee = two
    root = chen.commit(tmp_path, {"r.md": b"x"}, "Later")
    from anagram.identity.app.directory import Directory

    real = Directory.lookup

    def no_keys(self, subject, *a, **kw):
        if subject == lee.subject:
            raise ClientError("no active keys")
        return real(self, subject, *a, **kw)

    monkeypatch.setattr(Directory, "lookup", no_keys)
    out = chen.json("POST", f"/api/findings/{root}/shares", {"targets": [lee.subject]})
    assert out["waiting"] == ["Lee"] and out["shared"] == []
    assert chen.json("GET", f"/api/history?finding={root}")[0]["state"] == "waiting"
    monkeypatch.setattr(Directory, "lookup", real)
    chen.sharing.sync()
    fid = chen.json("GET", f"/api/history?finding={root}")[0]["finding"]["id"]
    assert {"finding_id": fid, "subject": lee.subject} in chen.events("share.delivered")
    assert chen.json("GET", f"/api/history?finding={root}")[0]["state"] == "delivered"
    with chen.svc.session() as c:
        kinds = [e["kind"] for e in c.share_store.share_events(finding_id=fid)]
    assert kinds == ["waiting", "shared"]


def test_sync_survives_a_node_fault(two, tmp_path):
    _, chen, _ = two
    with chen.svc.open_client() as c:
        calls = []

        def down(*a, **kw):
            calls.append(1)
            raise OSError("no network")

        c.device.http.call = down
        assert c.share_sync.sync_shares() == {"changed": []}
        assert len(calls) == 2  # the read records and the reader side were each tried


def test_received_file_rejects_traversal_and_symlinks(tmp_path):
    from anagram.shell.ui.errors import UIError
    from anagram.shell.ui.service import UIService

    svc = UIService(tmp_path / "home")
    gid = "a" * 32
    base = svc.home / "received" / gid
    base.mkdir(parents=True)
    ok = base / "report.txt"
    ok.write_text("ok")
    outside = tmp_path / "secret.txt"
    outside.write_text("secret")
    link = base / "escape.txt"
    link.symlink_to(outside)

    assert svc.sharing.received_file(gid, "report.txt") == ok
    for bad in ("..\\secret.txt", "a\\b", "bad\x00.txt", ".hidden", "escape.txt", "../x"):
        with pytest.raises(UIError) as exc:
            svc.sharing.received_file(gid, bad)
        assert exc.value.status == 404
