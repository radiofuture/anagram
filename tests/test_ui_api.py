"""Local UI server: security checks and the API of each screen (TestClient).

The node is the in-process TestClient node of conftest. The UI service talks
to it through the same transport. Two fake PIs (Chen, Okafor) use the UI.
"""

from __future__ import annotations

import json
import urllib.parse

import pytest
from conftest import make_net
from fastapi.testclient import TestClient
from indexkit import own_addresses

from anagram.local.understanding.drafter import FakeModelDrafter
from anagram.shell.ui.institutions import StaticInstitutions
from anagram.shell.ui.server import cookie_name, create_ui_app
from anagram.shell.ui.service import UIService

PORT = 41999
TOKEN = "launch-token-for-tests"  # noqa: S105 - a test value
BASE = f"http://127.0.0.1:{PORT}"
ORIGIN = {"Origin": BASE}


def ui_client(net, home, sim=None) -> tuple[UIService, TestClient]:
    inst = []
    if sim is not None:
        inst = [{"id": i["id"], "label": i["name"]} for i in sim.ground_truth["institutions"]]
    svc = UIService(
        home,
        transport=net.transport,
        clock=net.clock,
        institutions=StaticInstitutions(inst),
        drafters={"fake": FakeModelDrafter()},
        return_to=f"{BASE}/auth/callback",
    )
    app = create_ui_app(svc, port=PORT, token=TOKEN)
    return svc, TestClient(app, base_url=BASE)


def launched(tc: TestClient) -> TestClient:
    r = tc.get(f"/open/{TOKEN}", follow_redirects=False)
    assert r.status_code == 303
    return tc


def join_via_ui(
    net, svc, tc, orcid: str, name: str, prepare: bool = True, route: str = "/api/join"
) -> None:
    """Join with the invite, then link the fake ORCID iD of `prepare`."""
    if prepare:
        svc.join.prepare(net.invite(), login_hint=orcid, name=name)
    tc.post(route, json={}, headers=ORIGIN)
    svc.join.task.thread.join(30)
    assert tc.get("/api/join").json()["status"]["state"] == "joined"
    if svc.state.get("login_hint"):
        link_orcid_via_ui(net, svc, tc)


def link_orcid_via_ui(net, svc, tc) -> None:
    st = tc.post("/api/orcid/link", json={}, headers=ORIGIN).json()
    assert st["state"] == "signin" and st["authorize_url"]
    # The browser goes to the node (fake ORCID) and comes back to the UI.
    url = st["authorize_url"]
    for _ in range(5):
        if url.startswith(svc.return_to):
            break
        status, loc = net.fetch(url)
        assert status in (302, 303), (status, url)
        url = urllib.parse.urljoin(url, loc)
    path = url.removeprefix(BASE)
    r = tc.get(path, headers={"Sec-Fetch-Site": "cross-site"})  # a cross-site top-level return
    assert r.status_code == 200 and "Signed in" in r.text
    svc.join.task.thread.join(30)
    assert tc.get("/api/join").json()["status"]["state"] == "linked"


def setup_person(net, svc, tc, sim, orcid, name, lab_slug):
    join_via_ui(net, svc, tc, orcid, name)
    kit = tc.get("/api/recovery-kit").json()
    assert kit["available"] and kit["code"]
    assert "Recovery code" in tc.get("/api/recovery-kit/file").text
    assert tc.post("/api/recovery-kit/saved", headers=ORIGIN).json() == {"saved": True}
    assert not tc.get("/api/recovery-kit").json()["available"]  # our copy is gone
    lab = next(x for x in sim.ground_truth["labs"] if x["slug"] == lab_slug)
    inst = next(i for i in sim.ground_truth["institutions"] if i["id"] == lab["institution_id"])
    found = tc.get("/api/institutions", params={"q": inst["name"][:6]}).json()
    assert found[0]["id"] == inst["id"]
    ov = tc.put(
        "/api/identity",
        json={
            "name": name,
            "ror": inst["id"],
            "institution_name": inst["name"],
            "new_lab": lab["name"],
        },
        headers=ORIGIN,
    ).json()
    assert ov["setup_done"] and ov["lab"]["name"] == lab["name"]
    r = tc.post(
        "/api/sources",
        json={"kind": "folder", "path": str(sim.out_dir / lab["path"])},
        headers=ORIGIN,
    ).json()
    assert r["added"] >= 3  # the folder, its Git repositories, the Zotero export
    return lab


# ------------------------------------------------------------------ security


@pytest.fixture
def ui(tmp_path):
    net = make_net(tmp_path)
    svc, tc = ui_client(net, tmp_path / "me")
    return net, svc, tc


def test_launch_token_and_cookie(ui):
    _, _, tc = ui
    assert tc.get("/api/overview").status_code == 401
    assert tc.get("/open/wrong", follow_redirects=False).status_code == 403
    r = tc.get(f"/open/{TOKEN}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    cookie = r.headers["set-cookie"].lower()
    assert cookie.startswith(cookie_name(PORT)) and "httponly" in cookie
    assert "samesite=strict" in cookie
    assert TOKEN not in r.headers["set-cookie"]  # the cookie is not the launch token
    ov = tc.get("/api/overview").json()
    assert ov == {
        "can_sign_in_again": False,
        "join": None,
        "joined": False,
        "pending_invite": False,
        "signed_in_before": False,
    }
    # The page itself carries strict headers.
    page = tc.get("/")
    assert "script-src 'self'" in page.headers["content-security-policy"]
    assert page.headers["x-frame-options"] == "DENY"
    assert page.headers["referrer-policy"] == "no-referrer"


def test_host_header_checked(ui):
    _, _, tc = launched(ui[2]) and ui
    assert tc.get("/api/overview", headers={"Host": "evil.example"}).status_code == 421
    assert tc.get("/", headers={"Host": f"rebind.example:{PORT}"}).status_code == 421
    assert tc.get("/api/overview", headers={"Host": f"127.0.0.1:{PORT + 1}"}).status_code == 421
    assert tc.get("/api/overview", headers={"Host": f"localhost:{PORT}"}).status_code == 200


def test_origin_and_fetch_site_checked(ui):
    _, _, tc = ui
    launched(tc)
    evil = {"Origin": "http://evil.example"}
    assert tc.post("/api/join", json={}, headers=evil).status_code == 403
    assert tc.post("/api/join", json={}).status_code == 403  # no Origin on a change
    assert tc.get("/api/overview", headers=evil).status_code == 403
    assert (
        tc.get("/api/overview", headers={"Origin": f"http://127.0.0.1:{PORT + 1}"}).status_code
        == 403
    )
    cross = {"Sec-Fetch-Site": "cross-site"}
    assert tc.get("/api/overview", headers=cross).status_code == 403
    assert tc.get(f"/open/{TOKEN}", headers=cross, follow_redirects=False).status_code == 403
    # The sign-in return is the one cross-site route. It accepts no unknown flow.
    r = tc.get("/auth/callback?code=x&state=y", headers=cross)
    assert r.status_code == 200 and "old" in r.text
    # Same origin works.
    r = tc.post("/api/join", json={"invite": "not a link"}, headers=ORIGIN)
    assert r.status_code == 400 and "invite link" in r.json()["error"]


def test_no_cors(ui):
    _, _, tc = ui
    launched(tc)
    r = tc.options(
        "/api/overview",
        headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in r.headers
    r = tc.get("/api/overview", headers=ORIGIN)
    assert "access-control-allow-origin" not in r.headers


def test_api_without_cookie_is_refused_for_every_route(ui):
    _, _, tc = ui
    for method, path in (
        ("GET", "/api/sources"),
        ("GET", "/api/findings"),
        ("POST", "/api/findings"),
        ("GET", "/api/recovery-kit/file"),
        ("POST", "/api/logout"),
        ("GET", "/api/flows"),
    ):
        r = tc.request(method, path, headers=ORIGIN, json={})
        assert r.status_code == 401, path


def test_flows_list_every_trust_boundary(ui):
    _, _, tc = ui
    launched(tc)
    flows = tc.get("/api/flows").json()
    to = " ".join(f["to"] for f in flows)
    for party in (
        "community server",
        "matching enclave",
        "People you share",
        "Everyone",
        "recovery guardians",
        "match",
        "ORCID",
        "model provider",
    ):
        assert party in to, party


# ------------------------------------------------------------ screens, end to end


@pytest.fixture
def two(tmp_path, sim_community, monkeypatch):
    # The sim mail of each PI is own mail: no Google account gives the addresses.
    own_addresses(monkeypatch, [p["email"] for p in sim_community.ground_truth["people"]])
    net = make_net(tmp_path)
    chen_svc, chen = ui_client(net, tmp_path / "chen", sim_community)
    oka_svc, oka = ui_client(net, tmp_path / "okafor", sim_community)
    launched(chen)
    launched(oka)
    people = {p["lab_id"]: p for p in sim_community.ground_truth["people"] if p["role"] == "pi"}
    pc, po = people["fake-lab-chen"], people["fake-lab-okafor"]
    setup_person(net, chen_svc, chen, sim_community, pc["orcid"], pc["name"], "chen")
    setup_person(net, oka_svc, oka, sim_community, po["orcid"], po["name"], "okafor")
    return net, (chen_svc, chen), (oka_svc, oka)


def test_screens_happy_path(two):
    net, (chen_svc, chen), (_, oka) = two

    # Sources: counts and automatic checkpoints.
    src = chen.get("/api/sources").json()["sources"]
    assert {s["kind_label"] for s in src} >= {"Folder", "Git repository", "Zotero library"}
    assert all(s["last_checkpoint_at"] and s["checkpoints"] == 1 for s in src)
    assert all(s["waiting"] == 0 and s["items"] > 0 for s in src)
    assert all(s["indexed"] == s["items"] and s["converting"] == 0 for s in src)
    assert all(isinstance(s["skipped"], list) for s in src)
    assert chen.post("/api/sources/refresh", headers=ORIGIN).json()["stamped"] == 0
    browse = chen.get("/api/browse", params={"path": str(chen_svc.home)}).json()
    assert "keys" in {d["name"] for d in browse["dirs"]} and browse["parent"]
    assert chen.get("/api/browse", params={"path": "/no/such/dir"}).status_code == 400

    # Findings: a draft, timestamp it, proofs.
    drafts = chen.get("/api/drafts").json()
    notes = next(d for d in drafts if d["title"] == "Chen Lab: Q4 project plan")
    keys = [i["key"] for i in notes["items"] if i["selectable"]]
    f = chen.post(
        "/api/findings",
        json={"draft_id": notes["id"], "claim": "Three NbT7 structures.", "keys": keys},
        headers=ORIGIN,
    ).json()
    assert f["claim"] == "Three NbT7 structures."
    assert f["versions"][0]["proven_by"]  # "Proven to exist by <date>"
    assert notes["id"] not in {d["id"] for d in chen.get("/api/drafts").json()}
    assert [x["root"] for x in chen.get("/api/findings").json()] == [f["root"]]
    proof = chen.get(f"/api/findings/{f['root']}/proof")
    assert "attachment" in proof.headers["content-disposition"]
    bundle = json.loads(proof.text)
    assert bundle["subject"]["root"] == f["root"] and bundle.get("sealed_opening") is None
    fp = chen.get(f"/api/findings/{f['root']}/files/0/proof")
    assert fp.status_code == 200 and "anagram-proof" in fp.headers["content-disposition"]

    # Sharing: default rings, add Okafor to Collaborators, share.
    rings = chen.get("/api/rings").json()
    assert [r["name"] for r in rings] == ["My lab", "Collaborators", "Community", "Public"]
    assert rings[0]["members"][0]["label"] == "Everyone in Chen Lab"
    people = chen.get("/api/people", params={"q": "okafor"}).json()
    assert people[0]["label"] == "Chidi Okafor" and "Okafor Lab" in people[0]["detail"]
    rings = chen.post(
        "/api/rings/Collaborators/members", json={"member": people[0]["id"]}, headers=ORIGIN
    ).json()
    assert rings[1]["members"][0]["label"] == "Chidi Okafor"
    out = chen.post(
        f"/api/findings/{f['root']}/share", json={"ring": "Collaborators"}, headers=ORIGIN
    ).json()
    assert out["shared"] == 1 and not out["public"]
    assert out["finding"]["versions"][0]["shared_with"] == ["Chidi Okafor"]

    # Okafor's inbox: open, verify, download.
    inbox = oka.get("/api/inbox").json()
    assert inbox[0]["sender"] == "Mei-Lin Chen" and inbox[0]["for_this_device"]
    opened = oka.post(f"/api/inbox/{inbox[0]['id']}/open", headers=ORIGIN).json()
    assert opened["verified"] and opened["claim"] == "Three NbT7 structures."
    assert opened["proven_by"] and opened["owner"] == "Mei-Lin Chen"
    # R5: the files stay encrypted; the file route decrypts in memory.
    got = oka.get(f"/api/shared/{inbox[0]['id']}/files/{opened['files'][0]['slot']}")
    assert got.status_code == 200 and b"NbT7" in got.content
    assert oka.get(f"/api/inbox/{inbox[0]['id']}/files/..%2Fx").status_code == 404

    # Third-party warning: a mail finding needs an acknowledgement.
    # The "Re:" subject is the other person's text, so the title is the file name.
    mail = next(d for d in chen.get("/api/drafts").json() if d["title"] == "Collaborator thread")
    assert mail["third_party"]
    m = chen.post(
        "/api/findings",
        json={
            "draft_id": mail["id"],
            "claim": None,
            "keys": [i["key"] for i in mail["items"] if i["selectable"]],
        },
        headers=ORIGIN,
    ).json()
    r = chen.post(
        f"/api/findings/{m['root']}/share", json={"ring": "Collaborators"}, headers=ORIGIN
    )
    assert r.status_code == 409 and r.json()["third_party"]
    r = chen.post(
        f"/api/findings/{m['root']}/share",
        json={"ring": "Collaborators", "ack_third_party": True},
        headers=ORIGIN,
    )
    assert r.status_code == 200 and r.json()["shared"] == 1

    # Revoke: a new version for the inner ring only; old access stays.
    rv = chen.post(
        f"/api/findings/{f['root']}/revoke", json={"ring": "My lab"}, headers=ORIGIN
    ).json()
    assert [v["version"] for v in rv["finding"]["versions"]] == [2, 1]
    assert len(oka.get("/api/inbox").json()) == 2  # the old grants are still there

    # Lab search (network matching runs in the enclave: test_enclave_services.py).
    labs = chen.get("/api/labs", params={"q": "okafor"}).json()
    assert labs[0]["label"] == "Okafor Lab"

    # Account and safety.
    acc = chen.get("/api/account").json()
    assert acc["devices"][0]["label"] == "This computer" and not acc["alerts"]
    assert acc["kit_saved"] and acc["guardians"] is None
    assert chen.post("/api/recovery-kit/new", headers=ORIGIN).json()["code"]

    # Model provider: off by default; opt-in needs the acknowledgement.
    s = chen.get("/api/settings").json()
    assert s["model"] == {"enabled": False, "provider": None}
    d0 = chen.get("/api/drafts").json()[0]
    assert chen.post(f"/api/drafts/{d0['id']}/model", headers=ORIGIN).status_code == 400
    r = chen.put("/api/settings/model", json={"enabled": True, "provider": "fake"}, headers=ORIGIN)
    assert r.status_code == 400
    r = chen.put(
        "/api/settings/model",
        json={"enabled": True, "provider": "fake", "acknowledged": True},
        headers=ORIGIN,
    )
    assert r.json()["model"]["enabled"]
    fake = chen_svc.drafters["fake"]
    assert fake.seen == []  # nothing read before a draft is chosen
    prose = next(d for d in chen.get("/api/drafts").json() if d["claim_suggestion"])
    md = chen.post(f"/api/drafts/{prose['id']}/model", headers=ORIGIN).json()
    assert md["drafted_by"] == "fake-model" and fake.seen

    # Sign out: the session ends; the Join screen signs in again.
    assert chen.post("/api/logout", headers=ORIGIN).json() == {"signed_out": True}
    ov = chen.get("/api/overview").json()
    assert not ov["joined"] and ov["signed_in_before"]
    assert chen.get("/api/findings").status_code == 409
    # Sign in again with the stored invite. Findings stay; no second kit on disk.
    chen.post("/api/recovery-kit/saved", headers=ORIGIN)
    join_via_ui(net, chen_svc, chen, None, None, prepare=False)
    assert chen.get("/api/overview").json()["setup_done"]
    assert len(chen.get("/api/findings").json()) == 2
    assert not chen.get("/api/recovery-kit").json()["available"]


def test_sign_in_again_without_an_invite(ui):
    """After the session and the invite expire, a member signs in again with
    ORCID only. The UI does not ask for an invite."""
    net, svc, tc = ui
    launched(tc)
    # No identity on this computer: there is nothing to sign in again to.
    r = tc.post("/api/signin", json={}, headers=ORIGIN)
    assert r.status_code == 409 and "invite" in r.json()["error"]
    svc.join.prepare(net.invite(days=7), login_hint="fake-ui-alice", name="Alice")
    join_via_ui(net, svc, tc, None, None, prepare=False)
    assert tc.post("/api/recovery-kit/saved", headers=ORIGIN).json() == {"saved": True}
    net.clock.t += 8 * 86400
    r = tc.get("/api/account")
    assert r.status_code == 401 and r.json()["signin"]
    ov = tc.get("/api/overview").json()
    assert not ov["joined"] and ov["signed_in_before"] and ov["can_sign_in_again"]
    # The stored invite has expired: the invite path fails.
    tc.post("/api/join", json={}, headers=ORIGIN)
    svc.join.task.thread.join(30)
    st = tc.get("/api/join").json()["status"]
    assert st["state"] == "error" and "expired" in st["error"]
    # R8: sign in again with the key of this computer (no ORCID, no invite).
    assert tc.post("/api/signin", json={}, headers=ORIGIN).status_code == 200
    svc.join.task.thread.join(30)
    assert tc.get("/api/join").json()["status"]["state"] == "joined"
    ov = tc.get("/api/overview").json()
    assert ov["joined"] and ov["kit_saved"]
    assert tc.get("/api/account").status_code == 200
    assert not tc.get("/api/recovery-kit").json()["available"]  # no new kit
