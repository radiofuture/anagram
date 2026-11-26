"""Proof certificate (R5 step 12): render, load, verify, CLI, UI route.

The print layout (one page) is checked in `test_certificate_browser.py`.
No network: a local node, or the in-process node of `conftest.net`.
"""

from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient

from anagram.core.errors import FormatError
from anagram.proofs.certificate import (
    PROOF_ID,
    certificate_bundle,
    load_proof,
    make_certificate,
    node_facts,
    proof_from_text,
    render_certificate,
)
from anagram.proofs.proof import Trust, verify_bundle
from anagram.shell.cli.main import main
from anagram.shell.client import Client


@pytest.fixture
def local(tmp_path):
    client = Client.init(tmp_path / "home")
    files = []
    for name, data in (("result.csv", b"sample,value\na,1\n"), ("figure.png", b"\x89PNG fake")):
        p = tmp_path / name
        p.write_bytes(data)
        files.append(p)
    b = client.findings.commit_finding(files, claim="Compound X lowers Y in mice\nMore words")
    return client, b.subject.root.hex(), files


def visible(text: str) -> str:
    """The page without the embedded proof."""
    return re.sub(r"<script.*?</script>", "", text, flags=re.DOTALL)


def scripts(text: str) -> list[str]:
    return re.findall(r"<script[^>]*>", text)


def test_certificate_holds_the_proof_and_verifies(local, tmp_path):
    client, root, files = local
    name, text, report = make_certificate(client, root)
    assert report.ok
    assert name == f"anagram-certificate-{root[:12]}.html"
    # One script element, and it is data: nothing runs.
    assert scripts(text) == [f'<script type="application/json" id="{PROOF_ID}">']
    assert "default-src 'none'" in text and "http://" not in text and "https://" not in text
    page = visible(text)
    assert "Compound X lowers Y in mice" in page and "More words" not in page  # first line only
    assert "This record existed no later than" in text
    assert "result.csv" in text and "figure.png" in text
    # The page says what it does not prove (spec/proof-bundle.md section 4).
    assert "That the owner made the work." in text and "What the files mean." in text

    path = tmp_path / name
    path.write_text(text)
    bundle = load_proof(path)
    assert bundle.subject.root.hex() == root
    again = verify_bundle(bundle, client.device.trust(), files=files)
    assert again.ok and len(again.matched_files) == 2


def test_cli_verify_reads_a_certificate(local, tmp_path, capsys):
    client, root, files = local
    out = tmp_path / "cert.html"
    assert main(["--home", str(client.home), "certificate", root[:10], "--out", str(out)]) == 0
    assert "Certificate:" in capsys.readouterr().out
    code = main(["--home", str(client.home), "verify", str(out), "--file", str(files[0])])
    text = capsys.readouterr().out
    assert code == 0 and text.startswith("VALID") and "equals evidence.0" in text
    files[0].write_bytes(b"changed")
    assert main(["--home", str(client.home), "verify", str(out), "--file", str(files[0])]) == 1


def test_owner_chooses_what_opens(local):
    client, root, _ = local
    _, text, report = make_certificate(client, root, claim=False, files=False, digests=False)
    assert report.ok
    assert "Compound X" not in text and "result.csv" not in text
    assert "The owner did not show the claim." in text
    assert "The owner did not show the files." in text
    bundle = proof_from_text(text)
    names = {fp.name for fp in bundle.finding_openings}
    assert names == {"finding_id", "version"}
    assert bundle.evidence_openings == ()

    _, text, report = make_certificate(client, root, files=False)
    assert "result.csv" not in text and "File 1" in text  # digest without the name
    opened = {fp.name for ev in proof_from_text(text).evidence_openings for fp in ev.fields}
    assert opened == {"content"}


def test_a_hostile_claim_stays_text(tmp_path):
    client = Client.init(tmp_path / "home")
    claim = '</script><script>alert(1)</script><img src=x onerror=alert(2)> & "q"'
    root = client.findings.commit_finding([], claim=claim).subject.root.hex()
    _, text, report = make_certificate(client, root)
    assert report.ok
    assert "<img" not in text and "alert(1)</script>" not in text
    assert len(scripts(text)) == 1
    assert proof_from_text(text).subject.root.hex() == root
    opened = {fp.name: fp.value for fp in proof_from_text(text).finding_openings}
    assert opened["claim"] == claim


def test_load_proof_refuses_a_page_with_no_proof_or_two(local, tmp_path):
    client, root, _ = local
    _, text, _ = make_certificate(client, root)
    with pytest.raises(FormatError, match="no proof"):
        proof_from_text("<html><body>nothing</body></html>")
    block = re.search(r'<script type="application/json".*?</script>', text, re.DOTALL).group(0)
    with pytest.raises(FormatError, match="more than one"):
        proof_from_text(text.replace("</body>", block + "</body>"))
    # A .json bundle loads too.
    p = tmp_path / "b.json"
    p.write_text(client.findings.bundle(root).dumps())
    assert load_proof(p).subject.root.hex() == root


def test_failed_check_and_test_anchor_are_said_plainly(local):
    client, root, _ = local
    bundle = certificate_bundle(client, root)
    ok = verify_bundle(bundle, client.device.trust())
    text = render_certificate(bundle, ok, owner=None, verify_url=None, node=node_facts(bundle))
    assert "A test anchor is in this proof. It proves no time." in text
    bad = verify_bundle(bundle, Trust(log_keys=[]))
    assert not bad.ok
    text = render_certificate(bundle, bad, owner=None, verify_url=None, node=node_facts(bundle))
    assert "did not pass all checks" in text and "existed no later than" not in text


def test_member_certificate_has_the_stated_name_and_the_verify_page(net, tmp_path):
    joined = net.join(tmp_path / "a", "0000-0002-1825-0097", "Adaeze Okafor")
    client = joined.client
    p = tmp_path / "data.csv"
    p.write_text("x\n1\n")
    root = client.findings.commit_finding([p], claim="A claim").subject.root.hex()
    _, text, report = make_certificate(client, root)
    assert report.ok
    assert "Stated by the owner" in text and "Adaeze Okafor" in text
    assert "0000-0002-1825-0097" in text
    assert "The name and ORCID iD. The owner states them." in text
    assert client.config["node"]["url"].rstrip("/") + "/verify" in text
    _, text, _ = make_certificate(client, root, name=False)
    assert "Adaeze Okafor" not in text and "Stated by the owner" not in text


PORT, TOKEN = 41997, "launch-token-for-tests"  # a test value


@pytest.fixture
def member_ui(net, tmp_path):
    """A joined member with one finding, and the local UI of that member."""
    from anagram.shell.ui.server import create_ui_app
    from anagram.shell.ui.service import UIService

    client = net.join(tmp_path / "m", "0000-0002-1825-0097", "Adaeze Okafor").client
    p = tmp_path / "result.csv"
    p.write_text("sample,value\na,1\n")
    root = client.findings.commit_finding(
        [p], claim="Compound X lowers Y in mice"
    ).subject.root.hex()
    client.vault.close()
    svc = UIService(client.home, transport=net.transport, clock=net.clock)
    tc = TestClient(create_ui_app(svc, port=PORT, token=TOKEN), base_url=f"http://127.0.0.1:{PORT}")
    return tc, root


def test_ui_route_gives_the_certificate(member_ui):
    tc, root = member_ui
    assert tc.get(f"/api/findings/{root}/certificate").status_code == 401  # no cookie
    tc.get(f"/open/{TOKEN}", follow_redirects=False)
    r = tc.get(f"/api/findings/{root}/certificate?claim=0&name=0")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/html")
    assert f'filename="anagram-certificate-{root[:12]}.html"' in r.headers["content-disposition"]
    assert "Compound X" not in r.text and "result.csv" in r.text and "Adaeze" not in r.text
    r = tc.get(f"/api/findings/{root}/certificate")
    assert "Compound X" in r.text and "Adaeze Okafor" in r.text
    r = tc.get("/api/findings/" + "0" * 64 + "/certificate")
    assert r.status_code >= 400 and "error" in r.json()


def test_route_refuses_a_proof_that_is_not_complete(member_ui, monkeypatch):
    import anagram.proofs.certificate as cert

    tc, root = member_ui
    real = cert.verify_bundle
    monkeypatch.setattr(cert, "verify_bundle", lambda b, t, files=(): real(b, Trust(log_keys=[])))
    tc.get(f"/open/{TOKEN}", follow_redirects=False)
    r = tc.get(f"/api/findings/{root}/certificate")
    assert r.status_code == 409 and "not complete" in json.loads(r.text)["error"]
