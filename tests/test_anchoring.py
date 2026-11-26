"""Background anchoring: batches, retry, OTS upgrade, client refresh, policy.

All anchors here are local fakes (LocalTSA transport, in-memory OTS). No network.
"""

from __future__ import annotations

import base64
import json

import pytest
from conftest import NODE_URL, Clock
from fastapi.testclient import TestClient
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation

from anagram.identity.node.mailer import FakeMailer
from anagram.proofs.anchors.base import Anchor
from anagram.proofs.anchors.defaults import DEFAULT_ANCHORS
from anagram.proofs.anchors.local_tsa import LocalTSA
from anagram.proofs.anchors.ots import deserialize, is_complete, new_detached, record_from_detached
from anagram.proofs.anchors.rfc3161 import RFC3161Anchor
from anagram.proofs.node.anchoring import AnchorScheduler
from anagram.proofs.proof import verify_bundle
from anagram.proofs.records import LOG_ENTRY_SCHEMA
from anagram.shell.client import Client
from anagram.shell.node.home import NodeHome

TSA_SPEC = "rfc3161:https://tsa.test/tsr"


def entry(i: int) -> dict:
    return {"commitment": f"{i:064x}", "kind": "finding", "schema": LOG_ENTRY_SCHEMA}


class Flaky(Anchor):
    """Fails `fails` times, then stamps with the inner anchor."""

    type = "rfc3161"

    def __init__(self, inner: Anchor, fails: int) -> None:
        self.inner, self.fails, self.calls = inner, fails, 0

    def stamp(self, digest: bytes) -> dict:
        self.calls += 1
        if self.calls <= self.fails:
            raise ConnectionError("TSA down")
        return self.inner.stamp(digest)


class FakeOts(Anchor):
    """Pending at stamp; complete after `upgrade` once `ready` is set."""

    type = "opentimestamps"

    def __init__(self) -> None:
        self.ready = False

    def stamp(self, digest: bytes) -> dict:
        detached, leaf = new_detached(digest)
        leaf.attestations.add(PendingAttestation("https://calendar.test"))
        return record_from_detached(detached)

    def upgrade(self, record: dict) -> dict:
        if not self.ready:
            return record
        detached = deserialize(base64.b64decode(record["ots"]))
        leaf = next(
            ts
            for ts in _walk(detached.timestamp)
            if any(isinstance(a, PendingAttestation) for a in ts.attestations)
        )
        leaf.attestations.add(BitcoinBlockHeaderAttestation(900000))
        return record_from_detached(detached)


def _walk(ts):
    yield ts
    for sub in ts.ops.values():
        yield from _walk(sub)


@pytest.fixture
def node(tmp_path):
    nh = NodeHome(tmp_path / "node")
    nh.create(
        origin="node.test/log",
        public_url=NODE_URL,
        anchors=[TSA_SPEC],
        anchor_mode="background",
        anchor_batch_seconds=60,
    )
    return nh


def test_commit_never_waits_for_network_anchors(node, no_network):
    service = node.service()
    assert service.anchors == []  # only inline (fake) anchors run during a commit
    out = service.submit(entry(1))
    assert out["anchors"] == [] and out["tree_size"] == 1
    assert set(node.background_anchors()) == {TSA_SPEC}


def test_batch_retry_and_supersede(node, tmp_path, no_network):
    service = node.service()
    tsa = LocalTSA()
    flaky = Flaky(RFC3161Anchor("https://tsa.test/tsr", transport=tsa.transport), fails=2)
    clock = Clock()
    sched = AnchorScheduler(
        service.store,
        service.origin,
        {TSA_SPEC: flaky},
        tmp_path / "anchors.sqlite",
        batch_seconds=60,
        retry_base=10,
        retry_max=40,
        clock=clock,
    )
    assert sched.anchored(1) is None
    service.submit(entry(1))
    sched.run_once()  # batch at size 1; first try fails
    assert flaky.calls == 1 and sched.status()["counts"] == {"open": 1}
    assert "TSA down" in sched.status()["last_error"]
    service.submit(entry(2))
    sched.run_once()  # not due (backoff 10 s), no new batch (60 s)
    assert flaky.calls == 1
    clock.t += 10
    sched.run_once()  # second failure; backoff 20 s
    assert flaky.calls == 2
    clock.t += 60
    sched.run_once()  # new batch at size 2; size 1 retried first (ok), size 2 ok
    assert flaky.calls == 4
    got = sched.anchored(1)
    assert got["tree_size"] == 1 and got["anchors"][0]["type"] == "rfc3161"
    assert sched.anchored(2)["tree_size"] == 2
    assert sched.anchored(3) is None
    assert json.loads(service.store.checkpoint_at(1)[1])[0]["tsa"] == "https://tsa.test/tsr"
    assert sched.status()["last_anchored_size"] == 2 and sched.status()["last_error"] is None


def test_newer_success_supersedes_open_job(node, tmp_path, no_network):
    service = node.service()
    tsa = LocalTSA()
    flaky = Flaky(RFC3161Anchor("https://tsa.test/tsr", transport=tsa.transport), fails=1)
    clock = Clock()
    sched = AnchorScheduler(
        service.store,
        service.origin,
        {TSA_SPEC: flaky},
        tmp_path / "a.sqlite",
        batch_seconds=1,
        retry_base=1000,
        clock=clock,
    )
    service.submit(entry(1))
    sched.run_once()  # fails; retry in 1000 s
    service.submit(entry(2))
    clock.t += 5
    sched.run_once()  # batch at 2 succeeds; job at 1 is superseded
    assert sched.status()["counts"] == {"done": 1, "superseded": 1}
    assert sched.anchored(1)["tree_size"] == 2


def test_ots_pending_then_upgraded(node, tmp_path, no_network):
    service = node.service()
    ots = FakeOts()
    clock = Clock()
    sched = AnchorScheduler(
        service.store,
        service.origin,
        {"opentimestamps": ots},
        tmp_path / "a.sqlite",
        upgrade_seconds=100,
        clock=clock,
    )
    service.submit(entry(1))
    sched.run_once()
    rec = sched.anchored(1)["anchors"][0]
    assert rec["type"] == "opentimestamps" and not is_complete(rec)
    assert sched.status()["counts"] == {"upgrading": 1}
    ots.ready = True
    sched.run_once()  # not due yet
    assert not is_complete(sched.anchored(1)["anchors"][0])
    clock.t += 100
    sched.run_once()
    assert is_complete(sched.anchored(1)["anchors"][0])
    assert sched.status()["counts"] == {"done": 1}


def test_client_refresh_moves_bundle_to_anchored_checkpoint(node, tmp_path, no_network):
    from anagram.admission.app.join import join
    from anagram.core.nodeapi import NodeHTTPError
    from anagram.identity.app.browsers import HeadlessBrowser
    from anagram.shell.node.app import create_app

    clock = Clock()
    service = node.service()
    identity = node.identity(service, mailer=FakeMailer(), clock=clock)
    tsa = LocalTSA()
    sched = AnchorScheduler(
        service.store,
        service.origin,
        {TSA_SPEC: RFC3161Anchor("https://tsa.test/tsr", transport=tsa.transport)},
        tmp_path / "a.sqlite",
        batch_seconds=0,
        clock=clock,
    )
    admission = node.admission(identity)
    app = create_app(service, node.trust_info(), identity, anchoring=sched, admission=admission)
    tc = TestClient(app, base_url=NODE_URL)

    def transport(method, path, body, headers=None):
        r = tc.request(method, path, json=body, headers=headers or {})
        if r.status_code >= 400:
            raise NodeHTTPError(r.status_code, r.json().get("detail", ""))
        return r.json()

    def fetch(url):
        r = tc.get(url, follow_redirects=False)
        return r.status_code, r.headers.get("location")

    invite = admission.create_invite(None, 7)["invite_url"]
    c = join(
        tmp_path / "c",
        invite,
        transport=transport,
        browser=HeadlessBrowser(fetch),
        login_hint="0000-0002-1825-0097",
        display_name="A",
        clock=clock,
        open_home=Client.open,
    ).client
    (tmp_path / "f.txt").write_text("result")
    b1 = c.findings.commit_finding([tmp_path / "f.txt"], claim="one")
    assert b1.anchors == ()
    assert tc.get("/log/anchored", params={"size": 1}).status_code == 404
    assert c.findings.refresh_anchors() == [{"root": b1.subject.root.hex(), "status": "waiting"}]
    sched.run_once()
    b2 = c.findings.commit_finding([tmp_path / "f.txt"], claim="two")  # client now saw a newer size
    out = {r["root"]: r["status"] for r in c.findings.refresh_anchors()}
    assert out[b1.subject.root.hex()] == "updated"
    assert out[b2.subject.root.hex()] == "waiting"
    bundle = c.findings.bundle(b1.subject.root.hex())
    assert bundle.log.tree_size >= b1.log.tree_size and len(bundle.anchors) == 1
    trust = c.device.trust()
    trust.anchors.tsa_roots.append(tsa.root_cert)
    trust.min_anchors = 1
    report = verify_bundle(bundle, trust)
    assert report.ok, report.summary()
    assert "RFC 3161 timestamp from tsa.test: valid" in report.summary()
    # Nothing more to do for b1.
    assert b1.subject.root.hex() not in {r["root"] for r in c.findings.refresh_anchors()}


# ------------------------------------------------------------------ policy


def test_real_node_never_selects_fake_anchor(tmp_path):
    nh = NodeHome(tmp_path / "n")
    nh.create(orcid_mode="production", orcid_client_id="APP-X", orcid_client_secret="s")  # noqa: S106
    cfg = nh.config()
    assert cfg["anchors"] == list(DEFAULT_ANCHORS) and "fake" not in cfg["anchors"]
    assert nh.trust_info()["fake_anchor_keys"] == []
    assert nh.trust_document()["fake_anchor_keys"] == []
    with pytest.raises(ValueError, match="fake anchor"):
        NodeHome(tmp_path / "m").create(
            orcid_mode="sandbox",
            orcid_client_id="APP-X",
            orcid_client_secret="s",  # noqa: S106,
            anchors=["fake", *DEFAULT_ANCHORS],
        )
    # A hand-edited config with the fake anchor does not start.
    raw = json.loads(nh.config_path.read_text())
    raw["anchors"].append("fake")
    nh.config_path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="fake anchor"):
        nh.anchors()


def test_dev_node_keeps_fake_inline(tmp_path):
    nh = NodeHome(tmp_path / "n")
    nh.create(anchor_mode="background")
    assert nh.config()["anchors"] == ["fake"]
    assert [a.type for a in nh.anchors()] == ["fake"]
    assert nh.anchoring(nh.service()) is None
