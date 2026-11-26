"""Public verify page and published proofs (R5 step 13). No network: the
in-process node of `conftest`, with the verify service attached.

The file drop and the digest in the browser are in
`test_verify_page_browser.py`.
"""

from __future__ import annotations

import json

import pytest
from conftest import NODE_URL, make_net
from fastapi.testclient import TestClient

from anagram.proofs.certificate import certificate_bundle, make_certificate
from anagram.proofs.node.verify_page import VerifyPages
from anagram.shell.client import Client
from anagram.shell.node.app import create_app


@pytest.fixture
def vnet(tmp_path):
    """The test node with the verify page, and one member with a finding."""
    net = make_net(tmp_path)
    verify = VerifyPages(
        tmp_path / "proofs.sqlite",
        net.identity,
        net.home.trust_info(),
        public_url=NODE_URL,
        clock=net.clock,
        per_minute=5,
    )
    app = create_app(
        net.service,
        net.home.trust_info(),
        net.identity,
        vault=net.vault,
        store=net.store,
        labs=net.labs,
        verify=verify,
        admission=net.admission,
    )
    net.tc = TestClient(app, base_url=NODE_URL)
    client = net.join(tmp_path / "m", "0000-0002-1825-0097", "Adaeze Okafor").client
    data = tmp_path / "data.csv"
    data.write_text("x\n1\n")
    root = client.findings.commit_finding([data], claim="A claim").subject.root.hex()
    return net, client, root, verify


def test_page_has_the_brand_headers_and_no_inline_script(vnet):
    net, *_ = vnet
    r = net.tc.get("/verify")
    assert r.status_code == 200
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert '<script type="module" src="/verify/assets/verify.js">' in r.text
    assert "<script>" not in r.text
    assert (
        net.tc.get("/verify/assets/verify.js").headers["content-type"].startswith("text/javascript")
    )
    assert net.tc.get("/verify/assets/anagram-crypto.js").status_code == 200
    assert net.tc.get("/verify/assets/index.html").status_code == 404
    assert net.tc.get("/verify/assets/..%2Fverify_page.py").status_code == 404
    assert net.tc.get("/verify/" + "a" * 64).status_code == 200
    assert net.tc.get("/verify/not-a-root").status_code == 404


def test_check_a_certificate_and_a_bundle(vnet):
    net, client, root, _ = vnet
    _, text, _ = make_certificate(client, root)
    out = net.tc.post("/verify", json={"text": text}).json()
    assert out["ok"] and out["root"] == root and out["title"] == "A claim"
    assert out["not_after"] and out["evidence"]["0"]["name"] == "data.csv"
    assert out["evidence"]["0"]["content"]["alg"] == "anagram-chunked-sha256-v1"
    assert all(c["ok"] for c in out["checks"])
    out = net.tc.post("/verify", json={"bundle": client.findings.bundle(root).to_json()}).json()
    assert out["ok"] and out["evidence"] == {}  # the plain bundle opens nothing
    assert net.tc.post("/verify", json={"text": "<html>no proof</html>"}).status_code == 400
    assert net.tc.post("/verify", json={"other": 1}).status_code == 400


def test_a_proof_of_another_node_is_named(vnet, tmp_path):
    net, *_ = vnet
    other = Client.init(tmp_path / "other", origin="other.example/log")
    root = other.findings.commit_finding([], claim="elsewhere").subject.root.hex()
    out = net.tc.post("/verify", json={"bundle": other.findings.bundle(root).to_json()}).json()
    assert out == {"ok": False, "other_node": "other.example/log", "root": root}


def test_check_is_rate_limited_by_address(vnet):
    net, client, root, _ = vnet
    body = {"bundle": client.findings.bundle(root).to_json()}
    codes = [net.tc.post("/verify", json=body).status_code for _ in range(6)]
    assert codes == [200] * 5 + [429]
    net.clock.t += 61
    assert net.tc.post("/verify", json=body).status_code == 200


def test_publish_get_and_remove(vnet, tmp_path):
    net, client, root, _ = vnet
    bundle = certificate_bundle(client, root)
    assert net.tc.get(f"/proofs/{root}").status_code == 404
    assert net.tc.post("/proofs", json={"bundle": bundle.to_json()}).status_code == 401
    out = client.device.http.call("POST", "/proofs", {"bundle": bundle.to_json()}, auth=True)
    assert out == {"root": root, "url": f"{NODE_URL}/verify/{root}"}
    got = net.tc.get(f"/proofs/{root}").json()["bundle"]
    assert got["subject"]["root"] == root
    assert net.tc.post("/verify", json={"bundle": got}).json()["ok"]

    # Another member cannot publish the proof of this member, or remove it.
    other = net.join(tmp_path / "o", "0000-0001-5109-3700", "Other Person").client
    with pytest.raises(Exception, match="403"):
        other.device.http.call("POST", "/proofs", {"bundle": bundle.to_json()}, auth=True)
    with pytest.raises(Exception, match="404"):
        other.device.http.call("DELETE", f"/proofs/{root}", auth=True)

    client.device.http.call("DELETE", f"/proofs/{root}", auth=True)
    assert net.tc.get(f"/proofs/{root}").status_code == 404


def test_publish_refuses_a_sealed_or_broken_bundle(vnet):
    net, client, root, _ = vnet
    full = client.findings.bundle(root)
    sealed = full.to_json() | {"sealed_opening": {"x": 1}}
    with pytest.raises(Exception, match="40"):
        client.device.http.call("POST", "/proofs", {"bundle": sealed}, auth=True)
    broken = certificate_bundle(client, root).to_json()
    broken["log"]["leaf_index"] = broken["log"]["leaf_index"] + 7
    with pytest.raises(Exception, match="400"):
        client.device.http.call("POST", "/proofs", {"bundle": broken}, auth=True)


def test_ui_routes_publish_and_remove(vnet):
    from anagram.shell.ui.server import create_ui_app
    from anagram.shell.ui.service import UIService

    net, client, root, _ = vnet
    client.vault.close()
    port, token = 41995, "launch-token-for-tests"  # a test value
    svc = UIService(client.home, transport=net.transport, clock=net.clock)
    tc = TestClient(create_ui_app(svc, port=port, token=token), base_url=f"http://127.0.0.1:{port}")
    tc.get(f"/open/{token}", follow_redirects=False)
    path = f"/api/findings/{root}/public-proof"
    assert tc.get(path).json() == {"available": True, "url": None}
    origin = {"Origin": f"http://127.0.0.1:{port}"}
    r = tc.post(path, json={"claim": False}, headers=origin)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["url"] == f"{NODE_URL}/verify/{root}"
    assert tc.get(path).json() == {**out, "available": True}
    published = net.tc.get(f"/proofs/{root}").json()["bundle"]
    assert "claim" not in {o["name"] for o in published["openings"]["finding"]}
    assert tc.delete(path, headers=origin).json() == {"url": None}
    assert tc.get(path).json() == {"available": True, "url": None}


def test_a_node_with_no_proof_page_offers_no_public_link(tmp_path):
    """R7 step 10: "Make a public link" shows only when the node has the page."""
    from conftest import make_net

    from anagram.shell.ui.server import create_ui_app
    from anagram.shell.ui.service import UIService

    net = make_net(tmp_path)  # a node with no verify page
    client = net.join(tmp_path / "m", "0000-0002-1825-0097", "Adaeze Okafor").client
    data = tmp_path / "data.csv"
    data.write_text("x\n1\n")
    root = client.findings.commit_finding([data], claim="A claim").subject.root.hex()
    client.vault.close()
    port, token = 41996, "launch-token-for-tests"  # a test value
    svc = UIService(client.home, transport=net.transport, clock=net.clock)
    tc = TestClient(create_ui_app(svc, port=port, token=token), base_url=f"http://127.0.0.1:{port}")
    tc.get(f"/open/{token}", follow_redirects=False)
    got = tc.get(f"/api/findings/{root}/public-proof").json()
    assert got == {"available": False, "url": None}


def test_a_node_can_turn_the_page_off(tmp_path):
    from anagram.shell.node.home import NodeHome

    nh = NodeHome(tmp_path / "node")
    nh.create(origin="node.test/log")
    service = nh.service()
    identity = nh.identity(service)
    assert nh.verify(identity) is not None
    raw = json.loads(nh.config_path.read_text())
    raw["verify"] = {"public_page": False}
    nh.config_path.write_text(json.dumps(raw))
    assert nh.verify(identity) is None
