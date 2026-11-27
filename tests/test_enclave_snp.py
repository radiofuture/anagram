"""The `raw-snp` evidence step (spec/enclave-trust.md 4.3, rule 8): real AMD
evidence passes with AMD's pinned roots, and each tampered or wrong part is
refused with its spec code. The fake chains come from `snpkit`."""

from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace

import pytest
from snpkit import FakeAmd, variant

from anagram.network.formats.strict import Refused
from anagram.network.matching.trust.attestation import _check_collateral, _check_floor
from anagram.network.matching.trust.profiles import amd
from anagram.network.matching.trust.profiles.snp import snp_claims
from anagram.network.matching.trust.roots import AMD_ARK_SHA256

FIX = Path(__file__).parent / "fixtures" / "snp"


def _file(name: str) -> bytes:
    return (FIX / name).read_bytes()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def real_evidence(**override: bytes) -> dict[str, str]:
    parts = {
        "ark": _file("milan_ark.der"),
        "ask": _file("milan_ask.der"),
        "crl": _file("milan_ark.crl"),
        "leaf": _file("milan_vcek.der"),
        "report": _file("milan_report.bin"),
        **override,
    }
    return {k: _b64(v) for k, v in parts.items()}


PROD = SimpleNamespace(amd_arks=AMD_ARK_SHA256)


def refused(evidence: object, roots: object = PROD, gpu: object = None) -> Refused:
    with pytest.raises(Refused) as exc:
        snp_claims(evidence, gpu, roots)  # type: ignore[arg-type]
    return exc.value


# --- real evidence and AMD's real roots ---------------------------------------


def test_real_milan_evidence_passes_the_evidence_step() -> None:
    claims = snp_claims(real_evidence(), None, PROD)  # type: ignore[arg-type]
    cpu = claims.cpu
    assert claims.gpu is None
    assert cpu["reference"]["product"] == "milan"
    assert cpu["signing_key"] == "vcek" and cpu["csp_id"] is None
    assert cpu["tcb"] == {
        "report_version": 2,
        "milan_boot_loader": 2,
        "milan_tee": 0,
        "milan_snp": 5,
        "milan_microcode": 68,
    }
    assert "genoa_snp" in cpu["tcb_not_applicable"]
    assert cpu["tcb_required"] == sorted(cpu["tcb"])
    # This VM ran with debug on and SMT on; rule 3 refuses it later.
    assert cpu["debug"] is True and cpu["policy"]["smt"] is True
    assert cpu["valid_until"] > 1_790_000_000


def test_a_changed_byte_of_the_real_report_breaks_its_signature() -> None:
    report = bytearray(_file("milan_report.bin"))
    report[0x90] ^= 1  # measurement
    got = refused(real_evidence(report=bytes(report)))
    assert (got.code, got.detail) == ("untrusted_root", "report signature")


def test_a_changed_byte_of_the_real_signature_is_refused() -> None:
    report = bytearray(_file("milan_report.bin"))
    report[0x2A0] ^= 1
    assert refused(real_evidence(report=bytes(report))).code == "untrusted_root"


def test_another_products_root_is_not_milans() -> None:
    got = refused(real_evidence(ark=_file("genoa_ark.der"), ask=_file("genoa_ask.der")))
    assert got.code == "untrusted_root"


def test_the_crl_of_another_root_is_refused() -> None:
    assert refused(real_evidence(crl=_file("genoa_ark.crl"))).code == "untrusted_root"


def test_with_no_pinned_amd_root_nothing_passes() -> None:
    got = refused(real_evidence(), SimpleNamespace(amd_arks=()))
    assert got.code == "untrusted_root"


def test_the_pins_are_the_files_that_amd_serves() -> None:
    import hashlib

    pins = dict(AMD_ARK_SHA256)
    assert hashlib.sha256(_file("milan_ark.der")).hexdigest() == pins["milan"]
    assert hashlib.sha256(_file("genoa_ark.der")).hexdigest() == pins["genoa"]


# --- a fake AMD: each check ----------------------------------------------------


@pytest.fixture(scope="module")
def fake() -> FakeAmd:
    return FakeAmd()


def _claims(f: FakeAmd, report: bytes, **override: bytes):  # type: ignore[no-untyped-def]
    return snp_claims(f.evidence(report, **override), None, SimpleNamespace(amd_arks=f.pins()))  # type: ignore[arg-type]


def _refused(f: FakeAmd, report: bytes, **override: bytes) -> Refused:
    return refused(f.evidence(report, **override), SimpleNamespace(amd_arks=f.pins()))


def test_a_good_vcek_report_gives_its_claims(fake: FakeAmd) -> None:
    binding = bytes(range(32))
    cpu = _claims(fake, fake.report(report_data=binding)).cpu
    assert cpu["report_data"] == binding.hex()
    assert cpu["debug"] is False and cpu["migratable"] is False
    assert cpu["policy"]["smt"] is False and cpu["policy"]["page_swap_disable"] is True
    assert cpu["reference"]["measurement"] == "11" * 48
    assert cpu["tcb"]["report_version"] == 3 and cpu["tcb"]["milan_snp"] == 22


def test_a_vlek_report_names_its_cloud(fake: FakeAmd) -> None:
    v = variant(fake, signing_key=amd.VLEK)
    cpu = _claims(v, v.report()).cpu
    assert cpu["signing_key"] == "vlek" and cpu["csp_id"] == "Amazon Web Services"


def test_report_data_with_a_non_zero_tail_cannot_match_a_binding(fake: FakeAmd) -> None:
    cpu = _claims(fake, fake.report(report_data=bytes(32) + b"\x01" + bytes(31))).cpu
    assert len(cpu["report_data"]) == 128


@pytest.mark.parametrize(
    ("change", "code", "detail"),
    [
        ({"hwid": bytes(64)}, "untrusted_root", "hwID"),
        (
            {"spl": {"boot_loader": 4, "tee": 0, "snp": 23, "microcode": 219}},
            "untrusted_root",
            "leaf TCB",
        ),
        ({"revoke": ("leaf",)}, "cert_revoked", "leaf"),
        ({"revoke": ("ask",)}, "cert_revoked", "ask"),
        ({"ask_cn": "SEV-VLEK-Milan"}, "untrusted_root", "chain names"),  # VCEK report, VLEK chain
        ({"leaf_product": "Genoa"}, "untrusted_root", "CPUID product"),
        ({"leaf_ec": False}, "untrusted_root", "P-384"),
    ],
)
def test_each_chain_fault_is_refused(fake: FakeAmd, change: dict, code: str, detail: str) -> None:
    v = variant(fake, **change)
    got = _refused(v, v.report())
    assert (got.code, detail in got.detail) == (code, True)


def test_mask_chip_key_is_refused(fake: FakeAmd) -> None:
    got = _refused(fake, fake.report(mask_chip_key=True))
    assert got.code == "untrusted_root" and "MASK_CHIP_KEY" in got.detail


def test_a_report_signed_by_another_key_is_refused(fake: FakeAmd) -> None:
    got = _refused(fake, FakeAmd().report())
    assert got.code == "untrusted_root" and got.detail == "report signature"


def test_a_cpuid_that_differs_from_the_leaf_is_refused(fake: FakeAmd) -> None:
    got = _refused(fake, fake.report(cpuid=(0x19, 0x11, 1)))
    assert got.code == "untrusted_root"


def test_turin_is_refused_until_its_fmc_extension_is_confirmed() -> None:
    t = FakeAmd(
        product="turin", tcb={"fmc": 1, "boot_loader": 4, "tee": 0, "snp": 22, "microcode": 9}
    )
    got = _refused(t, t.report())
    assert got.code == "untrusted_root" and "FMC" in got.detail


@pytest.mark.parametrize(
    "evidence",
    [
        None,
        [],
        {"report": "AAAA"},
        {"ark": "", "ask": "", "crl": "", "leaf": "", "report": "", "extra": ""},
        {"ark": "!!", "ask": "", "crl": "", "leaf": "", "report": ""},
        {"ark": 1, "ask": "", "crl": "", "leaf": "", "report": ""},
    ],
)
def test_bad_forms_are_bad_attestation(evidence: object) -> None:
    assert refused(evidence).code == "bad_attestation"


def test_raw_snp_has_no_gpu_evidence() -> None:
    assert refused(real_evidence(), gpu={}).code == "bad_attestation"


def test_garbage_certificates_are_bad_attestation(fake: FakeAmd) -> None:
    got = _refused(fake, fake.report(), leaf=b"not a certificate")
    assert got.code in ("bad_attestation", "untrusted_root")


# --- totality and order (review of PR 4) -----------------------------------------


def test_a_leaf_with_a_malformed_basic_constraints_is_refused(fake: FakeAmd) -> None:
    v = variant(fake, extra_exts=(("2.5.29.19", b"\x30\x03\x01\x01"),))
    got = refused(v.evidence(v.report()), SimpleNamespace(amd_arks=v.pins()))
    assert got.code == "bad_attestation"


def test_a_leaf_with_two_product_names_is_refused(fake: FakeAmd) -> None:
    # The library will not build it, so build it with a stand-in OID of the
    # same length and patch the DER (this breaks the ASK's signature, but
    # the product name is read before that check).
    stand_in = "1.3.6.1.4.1.3704.1.9"
    v = variant(fake, extra_exts=((stand_in, b"\x16\x08Milan-B0"),))
    leaf = v.chain()["leaf"]
    oid9 = bytes.fromhex("06092b060104019c780109")  # 1.3.6.1.4.1.3704.1.9
    oid2 = bytes.fromhex("06092b060104019c780102")  # 1.3.6.1.4.1.3704.1.2
    assert leaf.count(oid9) == 1
    patched = leaf.replace(oid9, oid2)
    got = refused(v.evidence(v.report(), leaf=patched), SimpleNamespace(amd_arks=v.pins()))
    assert got.code == "bad_attestation"


def test_flipped_bytes_anywhere_give_only_refusals(fake: FakeAmd) -> None:
    import random

    rng = random.Random(4)  # noqa: S311 - reproducible test flips, not a secret
    good = {**fake.chain(), "report": fake.report()}
    roots = SimpleNamespace(amd_arks=fake.pins())
    for _ in range(400):
        name = rng.choice(sorted(good))
        raw = bytearray(good[name])
        for _ in range(rng.randint(1, 3)):
            raw[rng.randrange(len(raw))] ^= 1 << rng.randrange(8)
        evidence = {k: _b64(bytes(raw) if k == name else v) for k, v in good.items()}
        try:
            snp_claims(evidence, None, roots)  # type: ignore[arg-type]
        except Refused:
            continue
        # Every byte of the evidence is signed or pinned (the outer
        # algorithm identifiers must be exact), so no flip may pass.
        raise AssertionError(f"a flip in {name} passed")


def test_a_revoked_chain_with_a_wrong_tcb_gives_the_tcb_code(fake: FakeAmd) -> None:
    v = variant(fake, revoke=("leaf",), spl={"boot_loader": 1, "tee": 0, "snp": 1, "microcode": 1})
    got = _refused(v, v.report())
    assert (got.code, got.detail) == ("untrusted_root", "leaf TCB differs from REPORTED_TCB")


def test_a_revoked_chain_with_a_wrong_hwid_gives_the_hwid_code(fake: FakeAmd) -> None:
    v = variant(fake, revoke=("ask",), hwid=bytes(64))
    got = _refused(v, v.report())
    assert (got.code, got.detail) == ("untrusted_root", "VCEK hwID differs from CHIP_ID")


def test_mask_chip_key_comes_before_the_leaf(fake: FakeAmd) -> None:
    got = _refused(fake, fake.report(mask_chip_key=True), leaf=b"not a certificate")
    assert (got.code, got.detail) == ("untrusted_root", "MASK_CHIP_KEY is set")


# --- rule 2 and rule 4 with the new claims ----------------------------------------


CPU = {
    "tcb": {"report_version": 3, "milan_snp": 22, "milan_tee": 0},
    "tcb_required": ["milan_snp", "milan_tee", "report_version"],
    "tcb_not_applicable": ["genoa_snp", "genoa_tee"],
}


def test_the_floor_checks_the_items_of_this_product() -> None:
    _check_floor({"report_version": 3, "milan_snp": 22, "milan_tee": 0, "genoa_snp": 99}, CPU, None)
    with pytest.raises(Refused, match="tcb_below_floor"):
        _check_floor({"report_version": 3, "milan_snp": 23, "milan_tee": 0}, CPU, None)


def test_a_floor_with_no_item_for_this_product_refuses() -> None:
    with pytest.raises(Refused, match="tcb_below_floor"):
        _check_floor({"report_version": 3, "genoa_snp": 1, "genoa_tee": 0}, CPU, None)


def test_the_simulated_floor_still_works() -> None:
    _check_floor({"svn": 3}, {"tcb": {"svn": 3}}, None)
    with pytest.raises(Refused, match="tcb_below_floor"):
        _check_floor({"svn": 4}, {"tcb": {"svn": 3}}, None)


def test_collateral_past_its_next_update_is_expired() -> None:
    _check_collateral({"valid_until": 1000}, 999)
    _check_collateral({}, 10**12)  # a profile with no collateral
    for cpu, now in (({"valid_until": 1000}, 1000), ({"valid_until": "1000"}, 0)):
        with pytest.raises(Refused, match="evidence_expired"):
            _check_collateral(cpu, now)
