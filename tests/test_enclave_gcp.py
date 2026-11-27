"""The `gcp-cs` evidence step (spec/enclave-trust.md 4.5, rule 8): a PKI
Confidential Space token chained to the pinned root passes, and each
tampered or wrong part is refused with its spec code. Google publishes no
signed sample token, so the tokens come from `gcpkit`; the pin is checked
against Google's real root."""

from __future__ import annotations

import base64
import hashlib
import json
import random
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from gcpkit import REPORT_DATA, T0, FakeGoogle, b64url, changed, gpu_submod, key

from anagram.network.formats.strict import Refused
from anagram.network.matching.trust.attestation import (
    _check_binding,
    _check_collateral,
    _check_floor,
)
from anagram.network.matching.trust.profiles.gcp import gcp_claims
from anagram.network.matching.trust.roots import GCP_CS_ROOT_SHA256

FIX = Path(__file__).parent / "fixtures" / "gcp"


@pytest.fixture(scope="module")
def g() -> FakeGoogle:
    return FakeGoogle()


def roots(f: FakeGoogle) -> SimpleNamespace:
    return SimpleNamespace(gcp_cs_root=f.pin())


def claims(f: FakeGoogle, token: str, gpu: object = None):  # type: ignore[no-untyped-def]
    return gcp_claims({"token": token}, gpu, roots(f))  # type: ignore[arg-type]


def refused(f: FakeGoogle, token: object, evidence: object = None, gpu: object = None) -> Refused:
    with pytest.raises(Refused) as exc:
        gcp_claims(evidence if evidence is not None else {"token": token}, gpu, roots(f))  # type: ignore[arg-type]
    return exc.value


def test_the_pin_is_the_root_that_google_serves() -> None:
    pem = (FIX / "confidential_space_root.crt").read_bytes()
    cert = x509.load_pem_x509_certificate(pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    assert hashlib.sha256(der).hexdigest() == GCP_CS_ROOT_SHA256
    assert hashlib.sha1(der).hexdigest().upper() == "B95120742C24E3AA34042E1C3BA3AAD28B212321"  # noqa: S324 - Google's page gives SHA-1


def test_a_good_token_gives_its_claims(g: FakeGoogle) -> None:
    c = claims(g, g.token())
    cpu = c.cpu
    assert c.gpu is None
    assert cpu["debug"] is False and cpu["migratable"] is False and cpu["secboot"] is True
    assert cpu["report_data"] == REPORT_DATA
    assert cpu["tcb"] == {
        "swversion": 251100,
        "tcb_evaluation_data_number": 20,
        "tcb_status": "UpToDate",
    }
    assert cpu["tcb_required"] == sorted(cpu["tcb"])
    assert cpu["reference"] == {
        "args": ["/anagram-enclave"],
        "env": {"HOSTNAME": "enclave"},
        "gpu": False,
        "hwmodel": "GCP_INTEL_TDX",
        "image_digest": "sha256:" + "12" * 32,
        "restart_policy": "Never",
        "swname": "CONFIDENTIAL_SPACE",
    }
    assert cpu["support_attributes"] == ["LATEST", "STABLE", "USABLE"]
    assert cpu["cmd_override"] == [] and cpu["env_override"] == {}
    assert cpu["valid_from"] == T0 and cpu["valid_until"] == T0 + 3600


def test_a_nonce_may_be_a_string(g: FakeGoogle) -> None:
    assert claims(g, g.token(changed(eat_nonce=REPORT_DATA))).cpu["report_data"] == REPORT_DATA


def test_a_debug_image_claims_debug(g: FakeGoogle) -> None:
    assert claims(g, g.token(changed(dbgstat="enabled"))).cpu["debug"] is True


def test_an_amd_sev_token_has_no_tdx_floor_items(g: FakeGoogle) -> None:
    cpu = claims(g, g.token(changed(hwmodel="GCP_AMD_SEV", tdx=...))).cpu
    assert cpu["tcb"] == {"swversion": 251100}
    with pytest.raises(Refused) as exc:
        _check_floor(
            {"swversion": 1, "tcb_evaluation_data_number": 1, "tcb_status": ["UpToDate"]}, cpu, None
        )
    assert exc.value.code == "tcb_below_floor"


def test_gpu_claims_are_bound_by_the_token(g: FakeGoogle) -> None:
    p = changed(
        submods__nvidia_gpu=gpu_submod(
            ("590.48.01", "96.00.CF.00.01"), ("580.10.02", "96.00.D0.00.01")
        )
    )
    c = claims(g, g.token(p))
    assert c.gpu == {
        "bound_by_cpu_evidence": True,
        "cc_feature": "SPT",
        "cc_mode": "ON",
        "count": 2,
        "dbgstat": "disabled",
        "driver_version": "580.10.02",
        "hwmodels": ["GCP_NVIDIA_H100"],
        "vbios_version": "96.00.CF.00.01",
    }
    assert c.cpu["reference"]["gpu"] is True
    devtools = claims(
        g, g.token(changed(submods__nvidia_gpu=gpu_submod(("1.0", "1.0"), cc_mode="DEVTOOLS")))
    )
    assert devtools.gpu["dbgstat"] == "enabled"  # type: ignore[index]


def test_the_binding_of_a_token_gpu_is_the_plain_form() -> None:
    from anagram.network.matching.trust import binding as b

    bind = b"\x01" * 32
    plain = b.report_data(bind).hex()
    gpu = {"bound_by_cpu_evidence": True}
    _check_binding({"gpu_evidence": None}, {"report_data": plain}, gpu, bind, True)
    with pytest.raises(Refused, match="binding_mismatch"):
        _check_binding({"gpu_evidence": None}, {"report_data": "00" * 32}, gpu, bind, True)
    with pytest.raises(Refused, match="binding_mismatch"):
        _check_binding({"gpu_evidence": {}}, {"report_data": plain}, gpu, bind, True)


def test_a_token_not_yet_valid_or_expired_is_refused() -> None:
    _check_collateral({"valid_from": T0, "valid_until": T0 + 3600}, T0)
    _check_collateral({"valid_from": T0, "valid_until": T0 + 3600}, T0 - 300)  # skew
    for now in (T0 - 301, T0 + 3600):
        with pytest.raises(Refused, match="evidence_expired"):
            _check_collateral({"valid_from": T0, "valid_until": T0 + 3600}, now)
    with pytest.raises(Refused, match="evidence_expired"):
        _check_collateral({"valid_from": "0"}, T0)


def test_the_validity_includes_the_chain(g: FakeGoogle) -> None:
    short = FakeGoogle(leaf_days=0)
    cpu = claims(short, short.token()).cpu
    assert cpu["valid_until"] == T0  # the leaf expires before the token


# --- refusals -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("payload", "code", "detail"),
    [
        (changed(iss="https://evil.example"), "untrusted_root", "token issuer"),
        (changed(aud="https://sts.googleapis.com"), "bad_attestation", "token audience"),
        (changed(aud=["anagram/v1/enclave"]), "bad_attestation", "token audience"),
        (changed(exp="soon"), "bad_attestation", "token exp"),
        (changed(nbf=True), "bad_attestation", "token nbf"),
        (changed(iat=...), "bad_attestation", "token iat"),
        (changed(exp=T0), "bad_attestation", "token times"),
        (changed(nbf=T0 + 1), "bad_attestation", "token times"),
        (changed(eat_nonce=["a", "b"]), "bad_attestation", "token claim eat_nonce (one nonce)"),
        (changed(eat_nonce=...), "bad_attestation", "token claim eat_nonce (one nonce)"),
        (changed(swversion=["2511", "2512"]), "bad_attestation", "token claim swversion"),
        (changed(swversion=["25x1"]), "bad_attestation", "token claim swversion"),
        (changed(tdx=[]), "bad_attestation", "token claim tdx"),
        (changed(tdx=[{"gcp_attester_tcb_status": "UpToDate"}]), "bad_attestation", "token claim tcb_evaluation_data_number"),
        (changed(tdx=[{"tcb_evaluation_data_number": -1, "gcp_attester_tcb_status": "x"}]), "bad_attestation", "token claim tdx.tcb_evaluation_data_number"),
        (changed(dbgstat=...), "bad_attestation", "token claim dbgstat"),
        (changed(secboot="true"), "bad_attestation", "token claim secboot"),
        (changed(submods__container=...), "bad_attestation", "token claim submods.container"),
        (changed(submods__container__args="x"), "bad_attestation", "token claim args"),
        (changed(submods__container__env={"A": 1}), "bad_attestation", "token claim submods.container.env"),
        (changed(submods__container__cmd_override=[1]), "bad_attestation", "token claim cmd_override"),
        (changed(submods__container__env_override=[]), "bad_attestation", "token claim env_override"),
        (changed(submods__confidential_space__support_attributes="STABLE"), "bad_attestation", "token claim submods.confidential_space.support_attributes"),
        (changed(submods__nvidia_gpu={"gpus": [], "cc_mode": "ON", "cc_feature": "SPT"}), "bad_attestation", "token claim submods.nvidia_gpu.gpus"),
        (changed(submods__nvidia_gpu=gpu_submod(("5 9 0", "1.0"))), "bad_attestation", "token claim gpus.driver_version"),
    ],
)  # fmt: skip
def test_each_bad_claim_is_refused(g: FakeGoogle, payload: dict, code: str, detail: str) -> None:
    got = refused(g, g.token(payload))
    assert (got.code, got.detail) == (code, detail)


def _hdr(g: FakeGoogle, **changes: object) -> dict:
    h = {
        "alg": "RS256",
        "kid": "1",
        "typ": "JWT",
        "x5c": [base64.b64encode(c).decode() for c in g.chain()],
    }
    for k, v in changes.items():
        if v is ...:
            del h[k]
        else:
            h[k] = v
    return h


@pytest.mark.parametrize(
    ("changes", "code", "detail"),
    [
        ({"alg": "HS256"}, "bad_attestation", "token header (alg must be RS256)"),
        ({"alg": "none"}, "bad_attestation", "token header (alg must be RS256)"),
        ({"alg": "PS256"}, "bad_attestation", "token header (alg must be RS256)"),
        ({"jku": "https://evil.example"}, "bad_attestation", "token header (alg must be RS256)"),
        ({"typ": "JOSE"}, "bad_attestation", "token header typ"),
        ({"x5c": ...}, "untrusted_root", "x5c is not leaf, intermediate, root"),
        ({"x5c": "abc"}, "untrusted_root", "x5c is not leaf, intermediate, root"),
        ({"x5c": ["a", "b"]}, "untrusted_root", "x5c is not leaf, intermediate, root"),
        ({"x5c": ["!", "b", "c"]}, "untrusted_root", "x5c[0] is not base64"),
    ],
)
def test_each_bad_header_is_refused(g: FakeGoogle, changes: dict, code: str, detail: str) -> None:
    got = refused(g, g.token(header=_hdr(g, **changes)))
    assert (got.code, got.detail) == (code, detail)


def test_a_token_signed_by_another_key_is_refused(g: FakeGoogle) -> None:
    got = refused(g, g.token(signer=key("other")))
    assert (got.code, got.detail) == ("untrusted_root", "token signature")


def test_a_changed_payload_breaks_the_signature(g: FakeGoogle) -> None:
    h, p, s = g.token().split(".")
    body = json.loads(base64.urlsafe_b64decode(p + "=="))
    body["eat_nonce"] = ["cd" * 32]
    got = refused(g, f"{h}.{b64url(json.dumps(body).encode())}.{s}")
    assert (got.code, got.detail) == ("untrusted_root", "token signature")


def test_another_root_is_refused(g: FakeGoogle) -> None:
    other = FakeGoogle()
    other.root_key = key("other-root")
    other._chain = None
    got = refused(g, other.token())
    assert (got.code, got.detail) == (
        "untrusted_root",
        "root is not the pinned Confidential Space root",
    )


def test_a_chain_in_the_wrong_order_is_refused(g: FakeGoogle) -> None:
    leaf, mid, root = g.chain()
    got = refused(g, g.token(x5c=[mid, leaf, root]))
    assert (got.code, got.detail) == ("untrusted_root", "intermediate: issuer name")


def test_a_wrongly_named_root_is_refused() -> None:
    f = FakeGoogle(root_cn="Some Root")
    got = refused(f, f.token())
    assert (got.code, got.detail) == ("untrusted_root", "root name")


def test_a_small_leaf_key_is_refused() -> None:
    f = FakeGoogle(leaf_bits=1024)
    got = refused(f, f.token())
    assert got.code == "untrusted_root" and "RSA key" in got.detail


def test_an_ec_leaf_is_refused(g: FakeGoogle) -> None:
    import datetime as dt

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    leaf = x509.load_der_x509_certificate(g.chain()[0])
    mid = x509.load_der_x509_certificate(g.chain()[1])
    ec_leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf.subject)
        .issuer_name(mid.subject)
        .public_key(ec.generate_private_key(ec.SECP256R1()).public_key())
        .serial_number(7)
        .not_valid_before(dt.datetime(2026, 1, 1, tzinfo=dt.UTC))
        .not_valid_after(dt.datetime(2027, 1, 1, tzinfo=dt.UTC))
        .sign(g.mid_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )
    got = refused(g, g.token(x5c=[ec_leaf, *g.chain()[1:]]))
    assert got.code == "untrusted_root" and "RSA key" in got.detail


@pytest.mark.parametrize(
    "token",
    [None, 5, "", "a.b", "a.b.c.d", "é.b.c", "x" * 70000, "!!!.e30.AA", "e30.e30.A", "W10.e30.AA"],
)
def test_bad_token_forms_are_bad_attestation(g: FakeGoogle, token: object) -> None:
    assert refused(g, token).code == "bad_attestation"


@pytest.mark.parametrize("evidence", [[], {"token": "x", "extra": 1}, {"jwt": "x"}])
def test_bad_evidence_forms_are_bad_attestation(g: FakeGoogle, evidence: object) -> None:
    assert refused(g, None, evidence=evidence).code == "bad_attestation"


def test_gcp_cs_has_no_separate_gpu_evidence(g: FakeGoogle) -> None:
    assert refused(g, g.token(), gpu={}).code == "bad_attestation"


@pytest.mark.parametrize("raw", [b'{"alg":"RS256","alg":"RS256"}', b'{"alg":NaN}', b"[1]", b"\xff"])
def test_a_bad_header_json_is_bad_attestation(g: FakeGoogle, raw: bytes) -> None:
    got = refused(g, b64url(raw) + ".e30.AA")
    assert got.code == "bad_attestation"


def test_flipped_characters_anywhere_give_only_refusals(g: FakeGoogle) -> None:
    rng = random.Random(5)  # noqa: S311 - a fixed seed, not a secret
    good = g.token(changed(submods__nvidia_gpu=gpu_submod(("590.48.01", "96.00.CF.00.01"))))
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.=+/"
    passed = []
    for _ in range(1500):
        t = list(good)
        at = rng.randrange(len(t))
        new = rng.choice(alphabet)
        if new == t[at]:
            continue
        t[at] = new
        try:
            claims(g, "".join(t))
        except Refused:
            continue
        passed.append(at)
    # Only the last character of a base64url part can change without
    # changing its bytes (its low bits are padding); nothing else passes.
    ends = {i - 1 for i, ch in enumerate(good) if ch == "."} | {len(good) - 1}
    assert set(passed) <= ends


@pytest.mark.parametrize("depth", [10_000, 20_000])  # both under the 64 KiB limit
def test_a_deeply_nested_header_is_refused_not_a_crash(g: FakeGoogle, depth: int) -> None:
    deep = ("[" * depth + "]" * depth).encode()
    for raw in (deep, b'{"alg":"RS256","kid":' + deep + b"}"):
        got = refused(g, b64url(raw) + ".e30.AA")
        assert (got.code, got.detail) == ("bad_attestation", "token header is not JSON")
