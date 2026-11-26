"""Preprint draft (R5 step 14): a zip from a set of three findings has all
parts, the proofs inside it verify, and the TeX file passes a syntax check
that needs no TeX install. No network, no model call."""

from __future__ import annotations

import io
import json
import re
import zipfile

import pytest
from fastapi.testclient import TestClient

from anagram.core.errors import ClientError
from anagram.proofs.certificate import load_proof, proof_from_text
from anagram.proofs.preprint import build_preprint, tex_escape
from anagram.proofs.proof import verify_bundle
from anagram.proofs.records import LINK_INCLUDES, Link
from anagram.shell.cli.main import main
from anagram.shell.client import Client

HOSTILE = "Dose 50% of #1 & x_2 cost $5 {a} ~b^c \\end{document} <b>"


def make_set(client: Client, tmp_path):
    fig = tmp_path / "dose response.png"
    fig.write_bytes(b"\x89PNG\r\n\x1a\nfake image")
    table = tmp_path / "results.csv"
    table.write_text("dose,y\n1,2\n")
    notes = tmp_path / "notes.txt"
    notes.write_text("lab notes")
    a = client.findings.commit_finding(
        [fig, table], claim="Compound X lowers Y\nIn mice, at 3 doses."
    )
    b = client.findings.commit_finding([notes], claim=HOSTILE)
    links = [Link(LINK_INCLUDES, a.subject.root), Link(LINK_INCLUDES, b.subject.root)]
    parent = client.findings.commit_finding(
        [], claim="A mechanism for Y\nThree results.", links=links
    )
    return parent.subject.root.hex(), a.subject.root.hex(), b.subject.root.hex(), notes


def tex_problems(tex: str) -> list[str]:
    """A syntax check with no TeX install: environments are balanced and in
    order, braces are balanced, and no special character is unescaped."""
    problems = []
    stack = []
    for kind, env in re.findall(r"\\(begin|end)\{([a-z*]+)\}", tex):
        if kind == "begin":
            stack.append(env)
        elif not stack or stack.pop() != env:
            problems.append(f"\\end{{{env}}} does not close the open environment")
    if stack:
        problems.append(f"open environments: {stack}")
    body = re.sub(r"\\[{}%$#&_]", "", tex)  # escaped characters
    depth = 0
    for ch in body:
        depth += {"{": 1, "}": -1}.get(ch, 0)
        if depth < 0:
            problems.append("a } with no {")
            break
    if depth > 0:
        problems.append("a { with no }")
    for line in body.splitlines():
        if re.search(r"(?<!\\)[%$#&]", line):
            problems.append(f"unescaped special character: {line}")
    if tex.count(r"\begin{document}") != 1 or tex.count(r"\end{document}") != 1:
        problems.append("one document environment")
    return problems


def test_set_of_three_has_all_parts(tmp_path):
    client = Client.init(tmp_path / "home")
    parent, a, b, _ = make_set(client, tmp_path)
    out = build_preprint(client, parent, tmp_path / "draft.zip")
    z = zipfile.ZipFile(out)
    names = set(z.namelist())
    for need in (
        "manuscript.md",
        "manuscript.tex",
        "manuscript.html",
        "metadata.json",
        "CITATION.cff",
        "proof/VERIFY.txt",
        "figures/fig-1-dose-response.png",
        "supplement/results.csv",
        "supplement/notes.txt",
    ):
        assert need in names, need
    for root in (parent, a, b):
        assert f"proof/certificate-{root[:12]}.html" in names
        assert f"proof/{root[:12]}.proof.json" in names
        bundle = proof_from_text(z.read(f"proof/{root[:12]}.proof.json").decode())
        assert verify_bundle(bundle, client.device.trust()).ok
        cert = proof_from_text(z.read(f"proof/certificate-{root[:12]}.html").decode())
        assert cert.subject.root.hex() == root
    assert "MISSING.txt" not in names

    md = z.read("manuscript.md").decode()
    assert md.startswith("# A mechanism for Y\n")
    assert (
        "## 1. Compound X lowers Y" in md
        and "## 2. Dose 50%" in md
        and md.count("Three results.") == 1
    )
    assert "![Figure 1](figures/fig-1-dose-response.png)" in md
    assert (
        "## Priority record" in md and md.count("A cryptographic record of this work existed") == 3
    )
    assert parent in md

    meta = json.loads(z.read("metadata.json"))
    assert meta["title"] == "A mechanism for Y" and meta["abstract"] == "Three results."
    assert [f["root"] for f in meta["findings"]] == [parent, a, b]
    assert set(meta["target_hints"]) == {"arxiv", "biorxiv"}

    tex = z.read("manuscript.tex").decode()
    assert tex_problems(tex) == [], tex_problems(tex)
    assert r"\includegraphics[width=0.8\linewidth]{figures/fig-1-dose-response.png}" in tex
    assert tex_escape(HOSTILE) in tex
    html = z.read("manuscript.html").decode()
    assert "&lt;b&gt;" in html and '<img src="figures/fig-1-dose-response.png"' in html
    assert "cff-version: 1.2.0" in z.read("CITATION.cff").decode()


def test_tex_check_finds_errors():
    assert tex_problems(r"\begin{document}50% \end{document}")
    assert tex_problems(r"\begin{document}\begin{itemize}\end{document}")
    assert tex_problems(r"\begin{document}{\end{document}")
    assert tex_problems(r"\begin{document}" + tex_escape("50% {x}") + r"\end{document}") == []


def test_options_and_missing_files(tmp_path):
    client = Client.init(tmp_path / "home")
    parent, _, _, notes = make_set(client, tmp_path)
    notes.unlink()
    out = build_preprint(
        client,
        parent,
        tmp_path / "d.zip",
        include_files=False,
        abstract="Our abstract.",
        authors=[{"name": "Ada Lovelace", "orcid": "0000-0002-1825-0097", "affiliation": "Lab"}],
    )
    z = zipfile.ZipFile(out)
    names = z.namelist()
    assert not [n for n in names if n.startswith("supplement/")]
    assert "figures/fig-1-dose-response.png" in names  # figures stay
    assert "notes.txt" in z.read("MISSING.txt").decode()
    md = z.read("manuscript.md").decode()
    assert "Our abstract." in md and "Ada Lovelace, ORCID 0000-0002-1825-0097, Lab" in md
    cff = z.read("CITATION.cff").decode()
    assert 'family-names: "Lovelace"' in cff and "https://orcid.org/0000-0002-1825-0097" in cff


def test_refuses_an_incomplete_proof(tmp_path, monkeypatch):
    import anagram.proofs.certificate as cert
    from anagram.proofs.proof import Trust

    client = Client.init(tmp_path / "home")
    root = client.findings.commit_finding([], claim="x").subject.root.hex()
    real = cert.verify_bundle
    monkeypatch.setattr(cert, "verify_bundle", lambda b, t, files=(): real(b, Trust(log_keys=[])))
    with pytest.raises(ClientError, match="not complete"):
        build_preprint(client, root, tmp_path / "x.zip")


def test_cli_preprint(tmp_path, capsys):
    client = Client.init(tmp_path / "home")
    parent, *_ = make_set(client, tmp_path)
    client.vault.close()
    out = tmp_path / "p.zip"
    assert main(["--home", str(client.home), "preprint", parent[:10], "--out", str(out)]) == 0
    assert "Preprint draft:" in capsys.readouterr().out
    assert "manuscript.tex" in zipfile.ZipFile(out).namelist()
    assert (
        main(["--home", str(client.home), "preprint", parent[:10], "--out", str(out), "--no-files"])
        == 0
    )
    assert not [n for n in zipfile.ZipFile(out).namelist() if n.startswith("supplement/")]
    # The certificate of the zip verifies with the CLI too.
    zipfile.ZipFile(out).extract(f"proof/certificate-{parent[:12]}.html", tmp_path)
    assert (
        load_proof(tmp_path / "proof" / f"certificate-{parent[:12]}.html").subject.root.hex()
        == parent
    )


def test_ui_route_gives_the_zip(net, tmp_path):
    from anagram.shell.ui.server import create_ui_app
    from anagram.shell.ui.service import UIService

    client = net.join(tmp_path / "m", "0000-0002-1825-0097", "Adaeze Okafor").client
    parent, *_ = make_set(client, tmp_path)
    client.vault.close()
    port, token = 41994, "launch-token-for-tests"  # a test value
    svc = UIService(client.home, transport=net.transport, clock=net.clock)
    tc = TestClient(create_ui_app(svc, port=port, token=token), base_url=f"http://127.0.0.1:{port}")
    tc.get(f"/open/{token}", follow_redirects=False)
    origin = {"Origin": f"http://127.0.0.1:{port}"}
    r = tc.post(f"/api/findings/{parent}/preprint", json={"include_files": False}, headers=origin)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/zip"
    assert f'filename="anagram-preprint-{parent[:12]}.zip"' in r.headers["content-disposition"]
    z = zipfile.ZipFile(io.BytesIO(r.content))
    assert "manuscript.md" in z.namelist()
    assert not [n for n in z.namelist() if n.startswith("supplement/")]
    assert "Adaeze Okafor" in z.read("manuscript.md").decode()

    # The page sends the authors and the abstract (R7 step 10).
    body = {
        "include_files": False,
        "abstract": "We show that the pocket binds the ligand.",
        "authors": [
            {"name": "Adaeze Okafor", "orcid": "0000-0002-1825-0097"},
            {"name": "Tomas Reyes", "orcid": None},
        ],
    }
    r = tc.post(f"/api/findings/{parent}/preprint", json=body, headers=origin)
    assert r.status_code == 200, r.text
    text = zipfile.ZipFile(io.BytesIO(r.content)).read("manuscript.md").decode()
    assert "Tomas Reyes" in text and "ORCID 0000-0002-1825-0097" in text
    assert "We show that the pocket binds the ligand." in text
    for bad in ([], [{"name": " "}], [{"name": "A", "orcid": 7}], "Adaeze"):
        r = tc.post(f"/api/findings/{parent}/preprint", json={"authors": bad}, headers=origin)
        assert r.status_code == 400, bad
