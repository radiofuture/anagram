"""CLI commands for findings and their proofs.

`register(sub)` adds the commands to the `anagram` parser (one call in
`anagram.shell.cli.main`).

    anagram init [--node-url URL --log-key VKEY ...]
    anagram commit PATH... [--claim TEXT] [--supersedes ROOT] [--builds-on ROOT] [--includes ROOT]
    anagram verify PROOF.json [--file PATH] [--log-key VKEY] [--bitcoin-headers FILE] ...
    anagram prove-file FINDING_ID PATH [--out FILE]
    anagram list
    anagram anchors refresh [FINDING]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography import x509

from anagram.core.errors import ClientError
from anagram.identity.api import trust_from_config
from anagram.proofs.log.note import NoteVerifier
from anagram.proofs.proof import Trust, verify_bundle
from anagram.proofs.records import LINK_BUILDS_ON, LINK_INCLUDES, LINK_SUPERSEDES, Link
from anagram.shell.client import Client


def _write(path: Path, text: str) -> None:
    path.write_text(text + "\n")


def _root_arg(value: str) -> bytes:
    b = bytes.fromhex(value)
    if len(b) != 32:
        raise argparse.ArgumentTypeError("expected a 64-char hex root")
    return b


def cmd_init(args) -> int:
    trust = None
    if args.node_url:
        trust = {
            "bundled_tsa_roots": not args.no_bundled_tsa_roots,
            "fake_anchor_keys": args.fake_anchor_key or [],
            "log_keys": args.log_key or [],
            "min_anchors": args.min_anchors,
            "tsa_roots": [Path(p).read_text() for p in args.tsa_root or []],
            "witness_keys": args.witness_key or [],
        }
    anchors = args.anchor or None
    client = Client.init(args.home, node_url=args.node_url, trust=trust, anchors=anchors)
    print(f"Anagram data directory: {client.home}")
    print(f"Device key: {client.device.device_key().public_bytes().hex()}")
    for v in client.config["trust"]["log_keys"]:
        print(f"Pinned log key: {v}")
    for v in client.config["trust"].get("witness_keys", []):
        print(f"Pinned witness key: {v}")
    return 0


def cmd_commit(args) -> int:
    client = Client(args.home)
    links = [Link(LINK_SUPERSEDES, r) for r in args.supersedes or []]
    links += [Link(LINK_BUILDS_ON, r) for r in args.builds_on or []]
    links += [Link(LINK_INCLUDES, r) for r in args.includes or []]
    bundle = client.findings.commit_finding(args.paths, claim=args.claim, links=links)
    out = Path(args.out or f"anagram-{bundle.subject.root.hex()[:16]}.proof.json")
    _write(out, json.dumps(bundle.to_json(), indent=2, sort_keys=True))
    row = client.vault.get(bundle.subject.root.hex())
    print(f"Committed finding {row.finding_id} version {row.version}")
    print(f"Root: {bundle.subject.root.hex()}")
    print(f"Log entry {bundle.log.leaf_index} of {bundle.log.tree_size}")
    print(f"Proof bundle: {out}")
    return 0


def load_bitcoin_headers(path: str | Path) -> dict[int, tuple[bytes, int]]:
    """Read a JSON map from Bitcoin block height to the 80-byte block header
    (hex, as a node or block explorer shows it). Return height -> (merkle root
    in internal byte order, block time). Get the headers from a source that you
    trust: the verifier takes them as true."""
    try:
        obj = json.loads(Path(path).read_text())
        out = {}
        for height, header_hex in obj.items():
            header = bytes.fromhex(header_hex)
            if len(header) != 80:
                raise ValueError(f"height {height}: a header is 80 bytes")
            out[int(height)] = (header[36:68], int.from_bytes(header[68:72], "little"))
        return out
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"bad Bitcoin headers file {path}: {exc}") from exc


def _trust_from_args(args) -> Trust:
    trust = _base_trust_from_args(args)
    if getattr(args, "bitcoin_headers", None):
        trust.anchors.bitcoin_headers.update(load_bitcoin_headers(args.bitcoin_headers))
    return trust


def _base_trust_from_args(args) -> Trust:
    if args.log_key:
        return Trust(
            log_keys=[NoteVerifier.parse(v) for v in args.log_key],
            witness_keys=[NoteVerifier.parse(v) for v in args.witness_key or []],
            anchors=trust_from_config(
                {
                    "trust": {
                        "bundled_tsa_roots": not args.no_bundled_tsa_roots,
                        "fake_anchor_keys": args.fake_anchor_key or [],
                        "log_keys": [],
                        "tsa_roots": [Path(p).read_text() for p in args.tsa_root or []],
                    }
                }
            ).anchors,
            min_anchors=1 if args.min_anchors is None else args.min_anchors,
        )
    cfg_path = Path(args.home) / "config.json"
    if not cfg_path.exists():
        raise ClientError("no pinned keys: pass --log-key, or run `anagram init` first")
    cfg = json.loads(cfg_path.read_text())
    if args.no_bundled_tsa_roots:
        cfg["trust"]["bundled_tsa_roots"] = False
    trust = trust_from_config(cfg)
    for p in args.tsa_root or []:
        trust.anchors.tsa_roots.append(x509.load_pem_x509_certificate(Path(p).read_bytes()))
    if args.min_anchors is not None:
        trust.min_anchors = args.min_anchors
    return trust


def cmd_verify(args) -> int:
    from anagram.proofs.certificate import load_proof

    bundle = load_proof(args.proof)  # a bundle .json, or a certificate .html
    report = verify_bundle(bundle, _trust_from_args(args), files=args.file or [])
    print(report.summary())
    return 0 if report.ok else 1


def cmd_prove_file(args) -> int:
    client = Client(args.home)
    bundle = client.findings.prove_file(args.finding, args.path)
    out = Path(args.out or f"{Path(args.path).name}.anagram-proof.json")
    _write(out, json.dumps(bundle.to_json(), indent=2, sort_keys=True))
    print(f"File proof: {out}")
    print("It opens only the salt and content digest of this one file.")
    return 0


def cmd_list(args) -> int:
    for f in Client(args.home).findings.list_findings():
        print(f"{f['created_at']}  {f['finding_id']}  v{f['version']}  {f['root']}")
    return 0


def cmd_anchors_refresh(args) -> int:
    results = Client(args.home).findings.refresh_anchors(args.finding)
    words = {
        "updated": "anchors added",
        "waiting": "no anchor yet (the node anchors in batches; try again later)",
        "unchanged": "no new anchor yet",
    }
    for r in results:
        print(f"{r['root'][:16]}  {words[r['status']]}")
    if not results:
        print("All logged findings have complete anchors.")
    return 0


def _trust_flags(p: argparse.ArgumentParser, default_min: int | None) -> None:
    p.add_argument("--log-key", action="append", help="pinned log verifier key (vkey)")
    p.add_argument("--witness-key", action="append", help="pinned witness verifier key")
    p.add_argument("--fake-anchor-key", action="append", help="pinned fake anchor key (hex)")
    p.add_argument("--tsa-root", action="append", help="pinned TSA root certificate (PEM file)")
    p.add_argument("--min-anchors", type=int, default=default_min)
    p.add_argument(
        "--no-bundled-tsa-roots",
        action="store_true",
        help="do not trust the bundled roots of the default TSAs",
    )


def register(sub) -> None:
    """Add init, commit, verify, prove-file, list, and anchors."""
    p = sub.add_parser("init", help="create keys, vault, and (default) a local node")
    p.add_argument("--node-url", help="use a remote node instead of a local one")
    p.add_argument("--anchor", action="append", help="local node anchor: fake, rfc3161:URL")
    _trust_flags(p, 1)
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("commit", help="commit files (and a claim) as a finding")
    p.add_argument("paths", nargs="*")
    p.add_argument("--claim")
    p.add_argument("--supersedes", action="append", type=_root_arg)
    p.add_argument("--builds-on", action="append", type=_root_arg)
    p.add_argument("--includes", action="append", type=_root_arg)
    p.add_argument("--out")
    p.set_defaults(func=cmd_commit)

    p = sub.add_parser("verify", help="verify a proof bundle offline")
    p.add_argument("proof")
    p.add_argument("--file", action="append", help="check that this file equals opened evidence")
    p.add_argument(
        "--bitcoin-headers",
        metavar="FILE",
        help="JSON map: Bitcoin block height -> 80-byte block header (hex), for OpenTimestamps",
    )
    _trust_flags(p, None)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("prove-file", help="prove that a file equals committed evidence")
    p.add_argument("finding", help="finding ID or root (hex prefix)")
    p.add_argument("path")
    p.add_argument("--out")
    p.set_defaults(func=cmd_prove_file)

    p = sub.add_parser("list", help="list findings in the vault")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("anchors", help="independent time anchors of your proofs")
    asub = p.add_subparsers(dest="anchors_command", required=True)
    s = asub.add_parser("refresh", help="get background anchors from the node")
    s.add_argument("finding", nargs="?", help="finding ID or root (default: all)")
    s.set_defaults(func=cmd_anchors_refresh)
