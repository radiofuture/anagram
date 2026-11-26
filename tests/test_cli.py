import json
import shutil

from anagram.shell.cli.main import main


def run(capsys, *argv):
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_no_args_opens_the_ui(capsys, monkeypatch, tmp_path):
    import anagram.shell.ui.server as server

    called = {}
    monkeypatch.setattr(
        server, "run_ui", lambda home, port=0, open_browser=True: called.update(home=home) or 0
    )
    code, _, _ = run(capsys, "--home", str(tmp_path))
    assert code == 0 and called["home"] == str(tmp_path)
    try:
        main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
    out = capsys.readouterr().out
    assert "usage: anagram" in out and "prove-file" in out and "demo" in out


def test_cli_flow(tmp_path, capsys, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.chdir(tmp_path)
    code, out, _ = run(capsys, "--home", str(home), "init")
    assert code == 0 and "Pinned log key" in out

    data = tmp_path / "result.csv"
    data.write_text("sample,value\na,1\n")
    proof = tmp_path / "p.json"
    code, out, err = run(
        capsys, "--home", str(home), "commit", str(data), "--claim", "a=1", "--out", str(proof)
    )
    assert code == 0, err
    root = json.loads(proof.read_text())["subject"]["root"]

    code, out, _ = run(capsys, "--home", str(home), "verify", str(proof))
    assert code == 0 and out.startswith("VALID")

    code, out, _ = run(capsys, "--home", str(home), "list")
    assert root in out

    fproof = tmp_path / "file-proof.json"
    code, out, err = run(
        capsys, "--home", str(home), "prove-file", root[:10], str(data), "--out", str(fproof)
    )
    assert code == 0, err

    # A third party verifies with only the pinned keys, after the node is gone.
    cfg = json.loads((home / "config.json").read_text())["trust"]
    shutil.rmtree(home / "node")
    args = ["--home", str(tmp_path / "nobody"), "verify", str(fproof), "--file", str(data)]
    for k in cfg["log_keys"]:
        args += ["--log-key", k]
    for k in cfg["witness_keys"]:
        args += ["--witness-key", k]
    for k in cfg["fake_anchor_keys"]:
        args += ["--fake-anchor-key", k]
    code, out, _ = run(capsys, *args)
    assert code == 0, out
    assert "equals evidence.0" in out

    data.write_text("sample,value\na,2\n")
    code, out, _ = run(capsys, *args)
    assert code == 1 and out.startswith("INVALID")

    code, _, err = run(capsys, "--home", str(home), "prove-file", root[:10], str(data))
    assert code == 1 and "does not equal" in err


def test_verify_without_keys_fails(tmp_path, capsys):
    p = tmp_path / "x.json"
    p.write_text("{}")
    code, _, err = run(capsys, "--home", str(tmp_path / "none"), "verify", str(p))
    assert code == 1 and "error" in err


def test_verify_with_bitcoin_headers(tmp_path, capsys, monkeypatch):
    import struct

    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.op import OpSHA256

    from anagram.proofs.anchors.ots import new_detached, record_from_detached
    from anagram.proofs.log.checkpoint import Checkpoint
    from anagram.proofs.log.note import parse_note

    home = tmp_path / "home"
    monkeypatch.chdir(tmp_path)
    assert run(capsys, "--home", str(home), "init")[0] == 0
    data = tmp_path / "result.csv"
    data.write_text("a,1\n")
    proof = tmp_path / "p.json"
    assert run(capsys, "--home", str(home), "commit", str(data), "--out", str(proof))[0] == 0

    # Add an OpenTimestamps anchor (Bitcoin block 900000) over the checkpoint.
    bundle = json.loads(proof.read_text())
    digest = Checkpoint.parse_text(parse_note(bundle["log"]["checkpoint"]).text).digest()
    detached, leaf = new_detached(digest)
    block_root = leaf.ops.add(OpSHA256())
    block_root.attestations.add(BitcoinBlockHeaderAttestation(900_000))
    bundle["anchors"].append(record_from_detached(detached))
    proof.write_text(json.dumps(bundle))
    # An 80-byte block header: version, prev hash, merkle root, time, bits, nonce.
    header = struct.pack("<I", 1) + bytes(32) + block_root.msg + struct.pack("<III", 1, 0, 0)
    headers = tmp_path / "headers.json"
    headers.write_text(json.dumps({"900000": header.hex()}))

    cfg = json.loads((home / "config.json").read_text())["trust"]
    args = ["--home", str(tmp_path / "nobody"), "verify", str(proof), "--min-anchors", "2"]
    for k in cfg["log_keys"]:
        args += ["--log-key", k]
    for k in cfg["witness_keys"]:
        args += ["--witness-key", k]
    for k in cfg["fake_anchor_keys"]:
        args += ["--fake-anchor-key", k]
    code, out, _ = run(capsys, *args)
    assert code == 1 and "needs Bitcoin block headers" in out
    code, out, _ = run(capsys, *args, "--bitcoin-headers", str(headers))
    assert code == 0, out
    assert "2 valid distinct sources" in out
    # The same flag works with the keys from the config.
    cfg_args = ["--home", str(home), "verify", str(proof), "--min-anchors", "2"]
    code, out, _ = run(capsys, *cfg_args, "--bitcoin-headers", str(headers))
    assert code == 0, out

    headers.write_text(json.dumps({"900000": "zz"}))
    code, _, err = run(capsys, *args, "--bitcoin-headers", str(headers))
    assert code == 1 and "bitcoin" in err.lower()
