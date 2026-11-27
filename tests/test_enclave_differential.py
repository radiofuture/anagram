"""Differential tests (plan scenario 3): the same evidence through Anagram's
verifiers and Google's reference verifiers (go-sev-guest, go-tdx-guest, run
by `tests/differential/refverify`). The real evidence passes both; and over
thousands of changed copies, the two give the same verdict, except where
Anagram is stricter by design (`stricter_by_design`): a byte after the end,
a letter in another case in the unsigned part of Intel's JSON, or a changed AMD ARK (the reference
does not check each byte of it; Anagram pins its hash). Anagram
never accepts what the reference refuses.

The tests run when `ANAGRAM_REFVERIFY` names the built reference program
(CI builds it); otherwise they are skipped."""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import random
import struct
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from anagram.network.formats.strict import Refused
from anagram.network.matching.trust.profiles import intel, tdx
from anagram.network.matching.trust.profiles.snp import snp_claims
from anagram.network.matching.trust.profiles.tdx import tdx_claims
from anagram.network.matching.trust.roots import AMD_ARK_SHA256, INTEL_ROOT_SHA256

REFVERIFY = os.environ.get("ANAGRAM_REFVERIFY", "")
pytestmark = pytest.mark.skipif(
    not REFVERIFY or not Path(REFVERIFY).is_file(),
    reason="set ANAGRAM_REFVERIFY to the built tests/differential/refverify program",
)

FIX = Path(__file__).parent / "fixtures"
# The time the fixtures were fetched: every certificate and collateral is
# valid then, so the reference's time checks do not change the verdict.
NOW = int(dt.datetime(2026, 11, 27, 20, 0, tzinfo=dt.UTC).timestamp())
MUTATIONS = int(os.environ.get("ANAGRAM_DIFFERENTIAL_N", "1500"))


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def reference(requests: list[dict]) -> dict[str, dict]:
    lines = "".join(json.dumps(r) + "\n" for r in requests)
    out = subprocess.run(  # noqa: S603 - the program that CI built
        [REFVERIFY], input=lines, capture_output=True, text=True, check=True, timeout=600
    ).stdout
    verdicts = [json.loads(line) for line in out.splitlines()]
    return {v["id"]: v for v in verdicts}


# --- AMD SEV-SNP -------------------------------------------------------------------


def _snp_files() -> dict[str, bytes]:
    f = FIX / "snp"
    return {
        "report": (f / "milan_report.bin").read_bytes(),
        "leaf": (f / "milan_vcek.der").read_bytes(),
        "ask": (f / "milan_ask.der").read_bytes(),
        "ark": (f / "milan_ark.der").read_bytes(),
        "crl": (f / "milan_ark.crl").read_bytes(),
    }


def _snp_ours(parts: dict[str, bytes]) -> bool:
    ev = {k: _b64(v) for k, v in parts.items()}
    try:
        snp_claims(ev, None, SimpleNamespace(amd_arks=AMD_ARK_SHA256))  # type: ignore[arg-type]
    except Refused:
        return False
    return True


def _snp_request(rid: str, parts: dict[str, bytes]) -> dict:
    """The reference trusts the roots it is given: give it the evidence's own
    ASK and ARK, so that it checks them (the ARK pin is Anagram's own check)."""
    return {
        "id": rid,
        "kind": "snp",
        "now": NOW,
        "product": "Milan",
        "stepping": 0,  # the fixture chip (its VCEK says so)
        **{k: _b64(v) for k, v in parts.items()},
        "pin_ask": _b64(parts["ask"]),
        "pin_ark": _b64(parts["ark"]),
    }


def _mutate(rng: random.Random, files: dict[str, bytes]) -> tuple[str, dict[str, bytes]]:
    name = rng.choice(sorted(files))
    raw = bytearray(files[name])
    kind = rng.random()
    if kind < 0.8:
        at = rng.randrange(len(raw))
        raw[at] ^= 1 << rng.randrange(8)
    elif kind < 0.9:
        raw = raw[: rng.randrange(len(raw))]
    else:
        raw += bytes([rng.randrange(256)])
    return name, {**files, name: bytes(raw)}


def stricter_by_design(name: str, before: bytes, after: bytes) -> bool:
    if len(after) == len(before) + 1 and after.startswith(before):
        return True  # one byte after the end: Anagram parses exactly
    if name == "ark":
        return True  # the reference does not check each ARK byte; Anagram pins its hash
    if name not in ("qe_identity", "tcb_info") or len(after) != len(before):
        return False
    diff = [i for i in range(len(before)) if before[i] != after[i]]
    # One letter in another case, outside the signed body: Go reads JSON names
    # and hex digits in any case; Anagram reads the exact bytes Intel sends.
    body = range(before.index(b":") + 1, before.rindex(b',"signature"'))
    return (
        len(diff) == 1
        and diff[0] not in body
        and chr(after[diff[0]]).swapcase() == chr(before[diff[0]])
    )


def check_same_verdicts(files: dict[str, bytes], cases: dict, ours, ref: dict) -> None:
    refused = 0
    for rid, (name, parts) in cases.items():
        mine, theirs = ours(parts), ref[rid]["ok"]
        refused += not theirs
        assert not (mine and not theirs), (rid, name, ref[rid]["err"])
        if theirs and not mine:
            assert stricter_by_design(name, files[name], parts[name]), (rid, name)
    assert refused > len(cases) // 2  # the reference really checks the changes


def test_real_snp_evidence_passes_both() -> None:
    files = _snp_files()
    got = reference([_snp_request("real", files)])["real"]
    assert got["ok"], got["err"]
    assert _snp_ours(files)


def test_snp_verdicts_match_the_reference() -> None:
    files = _snp_files()
    rng = random.Random(23)  # noqa: S311 - a fixed seed, not a secret
    cases = {f"m{i}": _mutate(rng, files) for i in range(MUTATIONS)}
    ref = reference([_snp_request(rid, parts) for rid, (_, parts) in cases.items()])
    check_same_verdicts(files, cases, _snp_ours, ref)


# --- Intel TDX ---------------------------------------------------------------------


def _trimmed(raw: bytes) -> bytes:
    end = 0x30 + 0x248 + 4 + struct.unpack_from("<I", raw, 0x30 + 0x248)[0]
    return raw[:end]


def _tdx_files() -> dict[str, bytes]:
    f = FIX / "tdx"
    return {
        "quote": _trimmed((f / "spr_quote.dat").read_bytes()),
        "tcb_info": (f / "tcb_info_50806f000000.json").read_bytes(),
        "qe_identity": (f / "qe_identity.json").read_bytes(),
        "tcb_signing": (f / "tcb_signing.der").read_bytes(),
        "root_crl": (f / "root.crl").read_bytes(),
        "pck_crl": (f / "pck_platform.crl").read_bytes(),
    }


def _pck_ca(quote: bytes) -> bytes:
    qe = tdx.parse_qe_cert_data(tdx.parse_quote(quote))
    return intel.pem_chain(qe.pck_chain)[1]


def _tdx_ours(parts: dict[str, bytes]) -> bool:
    ev = {k: _b64(v) for k, v in parts.items()}
    try:
        tdx_claims(ev, None, SimpleNamespace(intel_root=INTEL_ROOT_SHA256))  # type: ignore[arg-type]
    except Refused:
        return False
    return True


def _tdx_request(rid: str, parts: dict[str, bytes], pck_ca: bytes) -> dict:
    return {
        "id": rid,
        "kind": "tdx",
        "now": NOW,
        **{k: _b64(v) for k, v in parts.items()},
        "root": _b64((FIX / "tdx" / "intel_root.der").read_bytes()),
        "pck_ca": _b64(pck_ca),
    }


def test_real_tdx_evidence_passes_both() -> None:
    files = _tdx_files()
    got = reference([_tdx_request("real", files, _pck_ca(files["quote"]))])["real"]
    assert got["ok"], got["err"]
    assert _tdx_ours(files)


def test_tdx_verdicts_match_the_reference() -> None:
    files = _tdx_files()
    pck_ca = _pck_ca(files["quote"])
    rng = random.Random(29)  # noqa: S311 - a fixed seed, not a secret
    cases = {f"m{i}": _mutate(rng, files) for i in range(MUTATIONS)}
    ref = reference([_tdx_request(rid, parts, pck_ca) for rid, (_, parts) in cases.items()])
    check_same_verdicts(files, cases, _tdx_ours, ref)
