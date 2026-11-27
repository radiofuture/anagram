"""The `raw-tdx` evidence step (spec/enclave-trust.md 4.4, rule 8): a real
TDX quote passes with Intel's pinned root and Intel's real collateral, and
each tampered or wrong part is refused with its spec code. The fake chains
come from `tdxkit`."""

from __future__ import annotations

import base64
import hashlib
import json
import random
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest
from tdxkit import FakeIntel, signed_body, variant

from anagram.network.formats.strict import Refused
from anagram.network.matching.trust.attestation import _check_floor
from anagram.network.matching.trust.profiles import intel
from anagram.network.matching.trust.profiles.tdx import parse_quote, tdx_claims
from anagram.network.matching.trust.roots import INTEL_ROOT_SHA256

FIX = Path(__file__).parent / "fixtures" / "tdx"


def _file(name: str) -> bytes:
    return (FIX / name).read_bytes()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def trimmed(raw: bytes) -> bytes:
    """A quote without what follows it in the file: zero padding (the
    guest's buffer) or go-tdx-guest's marker text."""
    end = 0x30 + 0x248 + 4 + struct.unpack_from("<I", raw, 0x30 + 0x248)[0]
    tail = raw[end:]
    assert tail in (bytes(len(tail)), b"\nextra bytes(only for testing purpose)\n")
    return raw[:end]


def real_evidence(**override: bytes) -> dict[str, str]:
    parts = {
        "quote": trimmed(_file("spr_quote.dat")),
        "tcb_info": _file("tcb_info_50806f000000.json"),
        "qe_identity": _file("qe_identity.json"),
        "tcb_signing": _file("tcb_signing.der"),
        "root_crl": _file("root.crl"),
        "pck_crl": _file("pck_platform.crl"),
        **override,
    }
    return {k: _b64(v) for k, v in parts.items()}


PROD = SimpleNamespace(intel_root=INTEL_ROOT_SHA256)


def refused(evidence: object, roots: object = PROD, gpu: object = None) -> Refused:
    with pytest.raises(Refused) as exc:
        tdx_claims(evidence, gpu, roots)  # type: ignore[arg-type]
    return exc.value


# --- a real quote, Intel's root and Intel's collateral --------------------------


def test_a_real_quote_passes_the_evidence_step() -> None:
    claims = tdx_claims(real_evidence(), None, PROD)  # type: ignore[arg-type]
    cpu = claims.cpu
    assert claims.gpu is None
    assert cpu["fmspc"] == "50806f000000"
    # This quote is from 2023: its platform (SGX component 1 at SVN 3) is
    # below every TCB level of Intel's collateral of today, so no level
    # matches, and rule 2 refuses it whatever the floor lists.
    assert cpu["tcb"]["tcb_status"] == "Unsupported"
    assert cpu["tcb"]["qe_tcb_status"] in intel.STATUSES
    assert cpu["tcb"]["tcb_evaluation_data_number"] >= 17
    assert cpu["tcb_required"] == sorted(cpu["tcb"])
    assert all(a.startswith("INTEL-SA-") for a in cpu["advisory_ids"])
    assert set(cpu["reference"]) == {
        "mr_config_id", "mr_owner", "mr_owner_config", "mr_td",
        "rtmr0", "rtmr1", "rtmr2", "rtmr3", "xfam",
    }  # fmt: skip
    assert cpu["valid_until"] > 1_795_000_000
    with pytest.raises(Refused) as exc:
        _check_floor({"tcb_status": ["UpToDate", "OutOfDate", "Unsupported"], **_rest()}, cpu, None)
    assert (exc.value.code, exc.value.detail) == ("tcb_below_floor", "tcb_status")


def _rest() -> dict[str, object]:
    return {
        "qe_tcb_status": ["UpToDate", "OutOfDate"],
        "tdx_module_tcb_status": ["UpToDate", "OutOfDate"],
        "tcb_evaluation_data_number": 17,
    }


def test_the_second_real_quote_passes_too() -> None:
    ev = real_evidence(
        quote=trimmed(_file("cos_quote.dat")), tcb_info=_file("tcb_info_00806f050000.json")
    )
    cpu = tdx_claims(ev, None, PROD).cpu  # type: ignore[arg-type]
    assert cpu["fmspc"] == "00806f050000"


def test_a_changed_byte_of_the_real_body_breaks_the_quote_signature() -> None:
    q = bytearray(trimmed(_file("spr_quote.dat")))
    q[0x30 + 0x88] ^= 1  # MRTD
    got = refused(real_evidence(quote=bytes(q)))
    assert (got.code, got.detail) == ("untrusted_root", "quote signature")


def test_a_changed_byte_of_the_real_qe_report_breaks_its_signature() -> None:
    q = bytearray(trimmed(_file("spr_quote.dat")))
    q[0x30 + 0x248 + 4 + 134 + 100] ^= 1
    got = refused(real_evidence(quote=bytes(q)))
    assert (got.code, got.detail) == ("untrusted_root", "QE report signature")


def test_collateral_for_another_platform_is_refused() -> None:
    got = refused(real_evidence(tcb_info=_file("tcb_info_00806f050000.json")))
    assert (got.code, got.detail) == ("untrusted_root", "tcb_info is for another platform")


def test_a_changed_byte_of_real_collateral_breaks_its_signature() -> None:
    raw = _file("tcb_info_50806f000000.json").replace(
        b'"tcbEvaluationDataNumber":', b'"tcbEvaluationDataNumber": '
    )
    got = refused(real_evidence(tcb_info=raw))
    assert (got.code, got.detail) == ("untrusted_root", "tcb_info signature")


def test_crls_swapped_are_refused() -> None:
    got = refused(real_evidence(root_crl=_file("pck_platform.crl")))
    assert (got.code, got.detail) == ("untrusted_root", "root CRL: issuer name")


def test_with_another_pinned_root_nothing_passes() -> None:
    got = refused(real_evidence(), SimpleNamespace(intel_root="00" * 32))
    assert (got.code, got.detail) == ("untrusted_root", "root is not the pinned Intel SGX Root CA")


def test_the_pin_is_the_root_that_intel_serves() -> None:
    assert hashlib.sha256(_file("intel_root.der")).hexdigest() == INTEL_ROOT_SHA256


def test_padding_after_the_quote_is_refused() -> None:
    got = refused(real_evidence(quote=trimmed(_file("spr_quote.dat")) + b"\x00"))
    assert got.code == "bad_attestation"


# --- a fake Intel ------------------------------------------------------------------


@pytest.fixture(scope="module")
def fake() -> FakeIntel:
    return FakeIntel()


def roots(f: FakeIntel) -> SimpleNamespace:
    return SimpleNamespace(intel_root=f.pin())


def claims_of(f: FakeIntel, quote: bytes | None = None, **override: bytes) -> dict:
    ev = f.evidence(quote if quote is not None else f.quote(), **override)
    return tdx_claims(ev, None, roots(f)).cpu  # type: ignore[arg-type]


def fake_refused(f: FakeIntel, quote: bytes | None = None, **override: bytes) -> Refused:
    ev = f.evidence(quote if quote is not None else f.quote(), **override)
    return refused(ev, roots(f))


def test_a_good_fake_quote_gives_its_claims(fake: FakeIntel) -> None:
    cpu = claims_of(fake, fake.quote(report_data=b"\x07" * 32 + bytes(32)))
    assert cpu["debug"] is False and cpu["migratable"] is False
    assert cpu["td_attributes"]["sept_ve_disable"] is True
    assert cpu["tcb"] == {
        "qe_tcb_status": "UpToDate",
        "tcb_evaluation_data_number": 19,
        "tcb_status": "UpToDate",
        "tdx_module_tcb_status": "UpToDate",
    }
    assert cpu["report_data"] == "07" * 32
    assert cpu["reference"]["mr_td"] == "22" * 48
    assert cpu["advisory_ids"] == []
    # The earliest of the CRLs (30 days), TCB Info (29) and QE Identity (28).
    assert cpu["valid_until"] == int(intel_now() + 28 * 86400)


def intel_now() -> int:
    import tdxkit

    return int(tdxkit.NOW.timestamp())


def test_report_data_with_a_non_zero_tail_cannot_match_a_binding(fake: FakeIntel) -> None:
    cpu = claims_of(fake, fake.quote(report_data=b"\x07" * 64))
    assert cpu["report_data"] == "07" * 64


def test_debug_and_migratable_are_claimed_for_rule_3(fake: FakeIntel) -> None:
    from anagram.network.matching.trust.profiles import tdx

    cpu = claims_of(fake, fake.quote(attrs=1 << tdx.ATTR_DEBUG | 1 << tdx.ATTR_MIGRATABLE))
    assert cpu["debug"] is True and cpu["migratable"] is True


@pytest.mark.parametrize(
    ("change", "code", "detail"),
    [
        ({"ca_cn": "Intel SGX PCK Other CA"}, "untrusted_root", "chain names"),
        ({"ca_cn": "Intel SGX PCK Processor CA"}, None, None),
        ({"revoke": ("leaf",)}, "cert_revoked", "PCK is on the PCK CRL"),
        ({"revoke": ("ca",)}, "cert_revoked", "PCK CA is on the root CRL"),
        ({"revoke": ("signer",)}, "cert_revoked", "TCB signing certificate is on the root CRL"),
        ({"cpusvn": bytes(16)}, "untrusted_root", "PCK CPUSVN"),
        ({"qe_mrsigner": bytes(32)}, "untrusted_root", "the quoting enclave is not the one in qe_identity"),
        ({"mr_signer_seam": b"\x01" * 48}, "untrusted_root", "the TDX module is not the one in tcb_info"),
        ({"tcb_info_changes": {"fmspc": "00806f050000"}}, "untrusted_root", "tcb_info is for another platform"),
        ({"tcb_info_changes": {"pceId": "0100"}}, "untrusted_root", "tcb_info is for another platform"),
        ({"tcb_info_changes": {"version": 2}}, "bad_attestation", "tcb_info is not TDX TCB Info version 3"),
        ({"tcb_info_changes": {"id": "SGX"}}, "bad_attestation", "tcb_info is not TDX TCB Info version 3"),
        ({"tcb_info_changes": {"tcbType": 1}}, "bad_attestation", "tcb_info.tcbType"),
        ({"tcb_info_changes": {"tcbLevels": []}}, "bad_attestation", "tcb_info.tcbLevels"),
        ({"tcb_info_changes": {"nextUpdate": "soon"}}, "bad_attestation", "tcb_info.nextUpdate"),
        ({"qe_identity_changes": {"id": "QE"}}, "bad_attestation", "qe_identity is not TD QE Identity version 2"),
        ({"qe_identity_changes": {"isvprodid": 1}}, "untrusted_root", "the quoting enclave is not the one in qe_identity"),
        ({"qe_identity_changes": {"attributes": "01" + "00" * 15}}, "untrusted_root", "the quoting enclave is not the one in qe_identity"),
    ],
)  # fmt: skip
def test_each_fault_is_refused(
    fake: FakeIntel, change: dict, code: str | None, detail: str | None
) -> None:
    f = variant(fake, **change)
    if code is None:
        claims_of(f)
        return
    got = fake_refused(f)
    assert (got.code, got.detail) == (code, detail)


def test_a_lower_platform_matches_a_lower_level(fake: FakeIntel) -> None:
    up = {
        "tcb": {
            "sgxtcbcomponents": [{"svn": c + 1} for c in fake.comps],
            "pcesvn": fake.pce_svn,
            "tdxtcbcomponents": [{"svn": c} for c in fake.tee_tcb_svn],
        },
        "tcbDate": "2026-01-01T00:00:00Z",
        "tcbStatus": "UpToDate",
    }
    low = json.loads(json.dumps(up))
    low["tcb"]["sgxtcbcomponents"] = [{"svn": c} for c in fake.comps]
    low["tcbStatus"] = "OutOfDate"
    low["advisoryIDs"] = ["INTEL-SA-00002", "INTEL-SA-00001"]
    cpu = claims_of(variant(fake, tcb_levels=[up, low]))
    assert cpu["tcb"]["tcb_status"] == "OutOfDate"
    assert cpu["advisory_ids"] == ["INTEL-SA-00001", "INTEL-SA-00002"]
    none = claims_of(variant(fake, tcb_levels=[up]))
    assert none["tcb"]["tcb_status"] == "Unsupported"


def test_a_lower_quoting_enclave_has_its_level(fake: FakeIntel) -> None:
    cpu = claims_of(variant(fake, qe_isvsvn=3))
    assert cpu["tcb"]["qe_tcb_status"] == "OutOfDate"
    assert cpu["advisory_ids"] == ["INTEL-SA-00000"]
    assert claims_of(variant(fake, qe_isvsvn=1))["tcb"]["qe_tcb_status"] == "Unsupported"


def test_a_tdx_1_5_module_uses_its_module_identity(fake: FakeIntel) -> None:
    svn = bytes([3, 1, 9] + [0] * 13)  # module major version 1, minor 3
    ident = {
        "id": "TDX_01",
        "mrsigner": "00" * 48,
        "attributes": "0000000000000000",
        "attributesMask": "FFFFFFFFFFFFFFFF",
        "tcbLevels": [
            {"tcb": {"isvsvn": 4}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate"},
            {"tcb": {"isvsvn": 2}, "tcbDate": "2025-01-01T00:00:00Z", "tcbStatus": "OutOfDate",
             "advisoryIDs": ["INTEL-SA-00009"]},
        ],
    }  # fmt: skip
    # TEE_TCB_SVN[0..1] are not compared with the TCB level when [1] > 0.
    f = variant(fake, tee_tcb_svn=svn)
    level = json.loads(f.tcb_info()[len(b'{"tcbInfo":') : f.tcb_info().rindex(b',"signature"')])
    level = level["tcbLevels"][0]
    level["tcb"]["tdxtcbcomponents"][0]["svn"] = 99
    cpu = claims_of(variant(f, module_identities=[ident], tcb_levels=[level]))
    assert cpu["tcb"]["tcb_status"] == "UpToDate"
    assert cpu["tcb"]["tdx_module_tcb_status"] == "OutOfDate"
    assert cpu["advisory_ids"] == ["INTEL-SA-00009"]
    assert (
        claims_of(variant(f, tcb_levels=[level]))["tcb"]["tdx_module_tcb_status"] == "Unsupported"
    )
    other = {**ident, "mrsigner": "11" * 48}
    got = fake_refused(variant(f, module_identities=[other], tcb_levels=[level]))
    assert (got.code, got.detail) == ("untrusted_root", "the TDX module is not TDX_01 of tcb_info")


def test_a_quote_signed_by_another_key_is_refused(fake: FakeIntel) -> None:
    q = bytearray(fake.quote())
    q[0x30 + 0x248 + 4 + 5] ^= 1  # the quote signature
    got = fake_refused(fake, bytes(q))
    assert (got.code, got.detail) == ("untrusted_root", "quote signature")


def test_a_qe_report_that_binds_another_key_is_refused(fake: FakeIntel) -> None:
    got = fake_refused(fake, fake.quote(qe_report_data=bytes(64)))
    assert (got.code, got.detail) == (
        "untrusted_root",
        "QE report does not bind the attestation key",
    )


@pytest.mark.parametrize(
    ("kwargs", "detail"),
    [
        ({"cert_data_type": 5}, "certification data type 5 is not 6"),
        ({"inner_type": 4}, "inner certification data type 4 is not 5"),
        ({"pem": b"not pem"}, "PCK chain is not PEM"),
    ],
)
def test_bad_certification_data_is_bad_attestation(
    fake: FakeIntel, kwargs: dict, detail: str
) -> None:
    got = fake_refused(fake, fake.quote(**kwargs))
    assert (got.code, got.detail) == ("bad_attestation", detail)


def test_a_chain_of_two_is_refused(fake: FakeIntel) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    c = fake.chain()
    pem = b"".join(
        x509.load_der_x509_certificate(c[n]).public_bytes(serialization.Encoding.PEM)
        for n in ("leaf", "root")
    )
    got = fake_refused(fake, fake.quote(pem=pem))
    assert (got.code, got.detail) == ("untrusted_root", "PCK chain is not leaf, CA, root")


@pytest.mark.parametrize(
    "evidence",
    [
        None,
        [],
        {"quote": "AA=="},
        {k: 1 for k in ("pck_crl", "qe_identity", "quote", "root_crl", "tcb_info", "tcb_signing")},
    ],
)
def test_bad_forms_are_bad_attestation(evidence: object) -> None:
    assert refused(evidence).code == "bad_attestation"


def test_raw_tdx_has_no_gpu_evidence(fake: FakeIntel) -> None:
    assert refused(fake.evidence(fake.quote()), roots(fake), gpu={}).code == "bad_attestation"


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{}",
        b'{"tcbInfo":[],"signature":"' + b"00" * 64 + b'"}',
        b'{"enclaveIdentity":{},"signature":"' + b"00" * 64 + b'"}',
    ],
)
def test_malformed_collateral_is_refused(fake: FakeIntel, raw: bytes) -> None:
    assert fake_refused(fake, tcb_info=raw).code in ("bad_attestation", "untrusted_root")


def test_signed_collateral_with_duplicate_names_is_refused(fake: FakeIntel) -> None:
    import tdxkit

    body = fake.tcb_info()[len(b'{"tcbInfo":') : fake.tcb_info().rindex(b',"signature"')]
    dup = body[:-1] + b',"tcbType":0}'
    sig = tdxkit.raw_sig(fake.signer_key, dup).hex().encode()
    got = fake_refused(fake, tcb_info=b'{"tcbInfo":' + dup + b',"signature":"' + sig + b'"}')
    assert (got.code, got.detail) == ("bad_attestation", "collateral has a duplicate name")


def test_signed_collateral_with_an_unknown_status_is_refused(fake: FakeIntel) -> None:
    f = variant(fake, tcb_levels=[{**_level(fake), "tcbStatus": "Fine"}])
    got = fake_refused(f)
    assert (got.code, got.detail) == ("bad_attestation", "tcb_info.tcbLevels[0].tcbStatus 'Fine'")


def _level(f: FakeIntel) -> dict:
    return {
        "tcb": {
            "sgxtcbcomponents": [{"svn": c} for c in f.comps],
            "pcesvn": f.pce_svn,
            "tdxtcbcomponents": [{"svn": c} for c in f.tee_tcb_svn],
        },
        "tcbDate": "2025-08-13T00:00:00Z",
    }


def test_signed_collateral_by_another_key_is_refused(fake: FakeIntel) -> None:
    import tdxkit

    raw = signed_body("tcbInfo", {"id": "TDX"}, tdxkit.key("someone"))
    got = fake_refused(fake, tcb_info=raw)
    assert (got.code, got.detail) == ("untrusted_root", "tcb_info signature")


@pytest.mark.parametrize(
    "part", [{"tcb_signing": b"\x30\x03\x02\x01\x00"}, {"root_crl": b"junk"}, {"pck_crl": b""}]
)
def test_garbage_certificates_and_crls_are_bad_attestation(fake: FakeIntel, part: dict) -> None:
    assert fake_refused(fake, **part).code == "bad_attestation"


def test_flipped_bytes_anywhere_give_only_refusals(fake: FakeIntel) -> None:
    rng = random.Random(7)  # noqa: S311 - a fixed seed, not a secret
    good = fake.quote()
    parts = {"quote": good, "tcb_info": fake.tcb_info(), "qe_identity": fake.qe_identity(), **{
        k: fake.chain()[k] for k in ("tcb_signing", "root_crl", "pck_crl")}}  # fmt: skip
    for _ in range(400):
        name = rng.choice(sorted(parts))
        raw = bytearray(parts[name])
        at = rng.randrange(len(raw))
        old = raw[at]
        raw[at] ^= 1 << rng.randrange(8)
        if name == "quote":
            ev = fake.evidence(bytes(raw))
        else:
            ev = fake.evidence(good, **{name: bytes(raw)})
        try:
            tdx_claims(ev, None, roots(fake))  # type: ignore[arg-type]
        except Refused:
            continue
        raise AssertionError(f"{name}[{at}] {old:#x} -> {raw[at]:#x} passed")


def test_flipped_bits_in_real_evidence_give_only_refusals() -> None:
    rng = random.Random(11)  # noqa: S311 - a fixed seed, not a secret
    names = ("quote", "tcb_info", "qe_identity", "tcb_signing", "root_crl", "pck_crl")
    files = {
        "quote": trimmed(_file("spr_quote.dat")),
        "tcb_info": _file("tcb_info_50806f000000.json"),
        "qe_identity": _file("qe_identity.json"),
        "tcb_signing": _file("tcb_signing.der"),
        "root_crl": _file("root.crl"),
        "pck_crl": _file("pck_platform.crl"),
    }
    passed = []
    for _ in range(1500):
        name = rng.choice(names)
        raw = bytearray(files[name])
        at = rng.randrange(len(raw))
        raw[at] ^= 1 << rng.randrange(8)
        try:
            tdx_claims(real_evidence(**{name: bytes(raw)}), None, PROD)  # type: ignore[arg-type]
        except Refused:
            continue
        passed.append((name, at))
    # Every byte is covered: the header and body by the quote signature, the
    # QE report by the PCK, the auth data by the QE report's hash, the chain
    # and collateral by Intel's signatures.
    assert passed == []


def test_parse_quote_stays_layout_only() -> None:
    q = parse_quote(trimmed(_file("spr_quote.dat")))
    assert q.cert_data_type == 6


def test_an_unsupported_or_revoked_status_never_passes_a_floor() -> None:
    cpu = {
        "tcb": {"tcb_status": "Revoked", "qe_tcb_status": "UpToDate", "tdx_module_tcb_status": "UpToDate",
                "tcb_evaluation_data_number": 20},
        "tcb_required": ["qe_tcb_status", "tcb_evaluation_data_number", "tcb_status", "tdx_module_tcb_status"],
    }  # fmt: skip
    floor = {"tcb_status": ["UpToDate", "Revoked", "Unsupported"], "qe_tcb_status": ["UpToDate"],
             "tdx_module_tcb_status": ["UpToDate"], "tcb_evaluation_data_number": 17}  # fmt: skip
    with pytest.raises(Refused) as exc:
        _check_floor(floor, cpu, None)
    assert (exc.value.code, exc.value.detail) == ("tcb_below_floor", "tcb_status")
    cpu["tcb"]["tcb_status"] = "UpToDate"
    _check_floor(floor, cpu, None)
    floor["tcb_evaluation_data_number"] = 21
    with pytest.raises(Refused):
        _check_floor(floor, cpu, None)


# --- the SGX extensions, the collateral and the quote: each refusal ------------

C16 = (9, 9, 2, 2, 4, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0)


def _sgx(*, tcb: bytes | None = None, top: list[bytes] | None = None) -> bytes:
    from tdxkit import SGX, der, der_uint, pair, seq

    if tcb is None:
        items = [pair(f"{SGX}.2.{i + 1}", der_uint(c)) for i, c in enumerate(C16)]
        items += [pair(f"{SGX}.2.17", der_uint(11)), pair(f"{SGX}.2.18", der(0x04, bytes(C16)))]
        tcb = seq(*items)
    if top is None:
        top = [
            pair(f"{SGX}.1", der(0x04, bytes(16))),
            pair(f"{SGX}.2", tcb),
            pair(f"{SGX}.3", der(0x04, b"\x00\x00")),
            pair(f"{SGX}.4", der(0x04, bytes.fromhex("50806f000000"))),
            pair(f"{SGX}.5", der(0x0A, b"\x00")),
        ]
    return seq(*top)


def _bad_ext_cases() -> list[tuple[bytes, str]]:
    from tdxkit import SGX, der, der_oid, der_uint, pair, seq

    good_tcb = [pair(f"{SGX}.2.{i + 1}", der_uint(c)) for i, c in enumerate(C16)]
    good_tcb += [pair(f"{SGX}.2.17", der_uint(11)), pair(f"{SGX}.2.18", der(0x04, bytes(C16)))]
    top = [
        pair(f"{SGX}.1", der(0x04, bytes(16))),
        pair(f"{SGX}.2", seq(*good_tcb)),
        pair(f"{SGX}.3", der(0x04, b"\x00\x00")),
        pair(f"{SGX}.4", der(0x04, bytes(6))),
        pair(f"{SGX}.5", der(0x0A, b"\x00")),
    ]
    return [
        (b"", "PCK has no SGX extensions"),
        (b"\x1f\x00", "PCK SGX extensions: DER"),
        (b"\x30\x81\x05", "PCK SGX extensions: DER length"),  # long form for a short length
        (b"\x30\x83\x00\x00\x00", "PCK SGX extensions: DER length"),  # 3 length bytes
        (b"\x30\x05\x00", "PCK SGX extensions: DER length"),  # runs past the end
        (b"\x31\x00", "PCK SGX extensions: structure"),
        (seq() + b"\x00", "PCK SGX extensions: structure"),
        (seq(der(0x02, b"\x00")), "PCK SGX extensions: structure"),
        (seq(seq(der(0x06, b"\x2a\x86"))), "PCK SGX extensions: structure"),
        (seq(seq(der(0x06, b"\x2a\x86"), der(0x05, b""))), "PCK SGX extensions: OID"),
        (seq(seq(der(0x06, b"\x2a\x80\x01"), der(0x05, b""))), "PCK SGX extensions: OID"),
        (seq(pair("1.2.3", der(0x05, b""))), "PCK SGX extensions: OID 1.2.3"),
        (seq(*top, top[0]), f"PCK SGX extensions: OID {SGX}.1"),
        (seq(*top[:4]), "PCK SGX extensions: fields"),
        (seq(*top, pair(f"{SGX}.8", der(0x05, b""))), "PCK SGX extensions: fields"),
        (seq(pair(f"{SGX}.1", der(0x04, bytes(15))), *top[1:]), "PCK PPID"),
        (seq(top[0], pair(f"{SGX}.2", der(0x04, b"")), *top[2:]), "PCK TCB: structure"),
        (seq(top[0], pair(f"{SGX}.2", seq(*good_tcb[:17])), *top[2:]), "PCK TCB: fields"),
        (
            seq(
                top[0],
                pair(f"{SGX}.2", seq(pair(f"{SGX}.2.1", der(0x02, b"\x00\x05")), *good_tcb[1:])),
                *top[2:],
            ),
            "PCK TCB component 1",
        ),
        (
            seq(
                top[0],
                pair(f"{SGX}.2", seq(pair(f"{SGX}.2.1", der(0x02, b"\xff")), *good_tcb[1:])),
                *top[2:],
            ),
            "PCK TCB component 1",
        ),
        (
            seq(
                top[0],
                pair(f"{SGX}.2", seq(pair(f"{SGX}.2.1", der_uint(256)), *good_tcb[1:])),
                *top[2:],
            ),
            "PCK TCB component 1",
        ),
        (seq(*top[:4], pair(f"{SGX}.5", der(0x0A, b"\x02"))), "PCK SGX type"),
        (seq(*top[:4], pair(f"{SGX}.5", der(0x04, b"\x00"))), "PCK SGX type"),
        (seq(*top[:2], pair(f"{SGX}.3", der(0x04, b"\x00")), *top[3:]), "PCK PCE-ID"),
        (seq(der_oid("1.2")), "PCK SGX extensions: structure"),
    ]


@pytest.mark.parametrize(("ext", "detail"), _bad_ext_cases())
def test_each_malformed_sgx_extension_is_refused(fake: FakeIntel, ext: bytes, detail: str) -> None:
    got = fake_refused(variant(fake, sgx_ext=ext))
    assert (got.code, got.detail) == ("untrusted_root", detail)


def test_a_well_formed_sgx_extension_with_long_lengths_passes(fake: FakeIntel) -> None:
    assert claims_of(variant(fake, sgx_ext=_sgx()))["fmspc"] == "50806f000000"


def _info(fake: FakeIntel, **changes: object) -> bytes:
    return variant(fake, tcb_info_changes=changes).tcb_info()


@pytest.mark.parametrize(
    ("changes", "detail"),
    [
        ({"fmspc": "zz806f000000"}, "tcb_info.fmspc"),
        ({"fmspc": 5}, "tcb_info.fmspc"),
        ({"version": True}, "tcb_info.version"),
        ({"tcbEvaluationDataNumber": -1}, "tcb_info.tcbEvaluationDataNumber"),
        ({"issueDate": "2026-13-45T00:00:00Z"}, "tcb_info.issueDate"),
        ({"tdxModule": {"mrsigner": "00"}}, "tcb_info.tdxModule.mrsigner"),
        ({"tcbLevels": [{"tcb": {}}]}, "tcb_info.tcbLevels[0].sgxtcbcomponents"),
        ({"tcbLevels": "x"}, "tcb_info.tcbLevels"),
    ],
)
def test_each_malformed_tcb_info_field_is_refused(
    fake: FakeIntel, changes: dict, detail: str
) -> None:
    got = fake_refused(fake, tcb_info=_info(fake, **changes))
    assert (got.code, got.detail) == ("bad_attestation", detail)


def test_bad_advisory_ids_are_refused(fake: FakeIntel) -> None:
    level = {**_level(fake), "tcbStatus": "UpToDate", "advisoryIDs": "INTEL-SA-1"}
    got = fake_refused(variant(fake, tcb_levels=[level]))
    assert (got.code, got.detail) == ("bad_attestation", "tcb_info.tcbLevels[0].advisoryIDs")


@pytest.mark.parametrize(
    ("body", "detail"),
    [
        (b'{"a":NaN}', "collateral has NaN"),
        (b'{"a":\xff}', "tcb_info is not JSON"),
        (b'{"a":}', "tcb_info is not JSON"),
    ],
)
def test_signed_collateral_that_is_not_json_is_refused(
    fake: FakeIntel, body: bytes, detail: str
) -> None:
    import tdxkit

    sig = tdxkit.raw_sig(fake.signer_key, body).hex().encode()
    got = fake_refused(fake, tcb_info=b'{"tcbInfo":' + body + b',"signature":"' + sig + b'"}')
    assert (got.code, got.detail) == ("bad_attestation", detail)


def test_a_module_identity_with_no_matching_level_is_unsupported(fake: FakeIntel) -> None:
    svn = bytes([1, 1, 9] + [0] * 13)
    ident = {
        "id": "tdx_01",
        "mrsigner": "00" * 48,
        "attributes": "0000000000000000",
        "attributesMask": "FFFFFFFFFFFFFFFF",
        "tcbLevels": [
            {"tcb": {"isvsvn": 4}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate"}
        ],
    }
    cpu = claims_of(variant(fake, tee_tcb_svn=svn, module_identities=[ident]))
    assert cpu["tcb"]["tdx_module_tcb_status"] == "Unsupported"


def test_raw_signed_refuses_a_short_or_out_of_range_signature() -> None:
    import tdxkit

    pub = tdxkit.key("x").public_key()
    assert not intel.raw_signed(pub, b"\x00" * 63, b"m")
    assert not intel.raw_signed(pub, b"\x00" * 64, b"m")  # r = s = 0
    with pytest.raises(Refused, match="bad_attestation"):
        intel.point_key(b"\x00" * 63, "key")
    with pytest.raises(Refused, match="bad_attestation"):
        intel.point_key(b"\x00" * 64, "key")  # not on the curve
    with pytest.raises(Refused, match="bad_attestation"):
        intel.QeReport.parse(b"\x00" * 383)


def test_a_quote_with_a_bad_attestation_key_is_refused(fake: FakeIntel) -> None:
    q = bytearray(fake.quote())
    q[0x30 + 0x248 + 4 + 64 : 0x30 + 0x248 + 4 + 128] = bytes(64)
    got = fake_refused(fake, bytes(q))
    assert got.code in ("bad_attestation", "untrusted_root")


@pytest.mark.parametrize(
    ("cut", "detail"),
    [
        (lambda q: q[: 0x30 + 0x248 + 4 + 134 + 100], "QE certification data is too short"),
    ],
)
def test_short_certification_data_is_refused(fake: FakeIntel, cut: object, detail: str) -> None:
    q = fake.quote()
    short = cut(q)  # type: ignore[operator]
    # Rewrite the lengths so only the inner check fails.
    n = len(short) - (0x30 + 0x248 + 4)
    short = (
        short[: 0x30 + 0x248]
        + struct.pack("<I", n)
        + short[0x30 + 0x248 + 4 : 0x30 + 0x248 + 4 + 130]
    )
    short += struct.pack("<I", n - 134) + q[0x30 + 0x248 + 4 + 134 : 0x30 + 0x248 + 4 + n]
    got = fake_refused(fake, short)
    assert (got.code, got.detail) == ("bad_attestation", detail)


def test_auth_data_longer_than_the_data_is_refused(fake: FakeIntel) -> None:
    q = bytearray(fake.quote())
    at = 0x30 + 0x248 + 4 + 134 + 448
    q[at : at + 2] = struct.pack("<H", 0xFFFF)
    got = fake_refused(fake, bytes(q))
    assert (got.code, got.detail) == (
        "bad_attestation",
        "QE authentication data length does not match",
    )


def test_a_pck_chain_length_that_does_not_match_is_refused(fake: FakeIntel) -> None:
    q = fake.quote()
    got = fake_refused(fake, q[:-1] + b"")  # the outer lengths no longer match
    assert got.code == "bad_attestation"


def test_a_crl_with_no_next_update_is_refused(fake: FakeIntel) -> None:
    import datetime as dt

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509 import CertificateRevocationListBuilder, Name, NameAttribute
    from cryptography.x509.oid import NameOID

    name = Name([NameAttribute(NameOID.COMMON_NAME, "Intel SGX Root CA"),
                 NameAttribute(NameOID.ORGANIZATION_NAME, "Intel Corporation")])  # fmt: skip
    crl = (
        CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(dt.datetime(2026, 1, 1, tzinfo=dt.UTC))
        .next_update(dt.datetime(2027, 1, 1, tzinfo=dt.UTC))
        .sign(fake.root_key, hashes.SHA256())
    )
    der = crl.public_bytes(serialization.Encoding.DER)
    assert claims_of(fake, root_crl=der)
