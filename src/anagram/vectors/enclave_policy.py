"""Vectors of the strict policy (spec/enclave-trust.md 4.9): rule 9 (cloud
binding) and the rule 3 bits of each profile, at the level of verified
claims. Writes `enclave-policy.json`.

Each case gives a profile, whether the app is a production app, the
release's `cloud` pins, the CPU and GPU claims, and the expected code
("ok" for a pass). The first vector file (enclave-trust.json) is frozen
and keeps rules 1 to 8 of the first draft.
"""

from __future__ import annotations

import copy
import json
from typing import Any

from anagram.network.formats.strict import Refused
from anagram.network.matching.trust.policy import check_cloud, check_policy
from anagram.vectors.cli import output_dir

FILE = "enclave-policy.json"

SNP_PINS = {"csp_ids": ["ExampleCloud"]}
GCP_PINS = {"project_numbers": ["123456789012"], "zones": ["us-central1-a", "us-central1-b"]}

SNP_CPU: dict[str, Any] = {
    "csp_id": "ExampleCloud",
    "debug": False,
    "migratable": False,
    "policy": {
        "abi_major": 0,
        "abi_minor": 0,
        "ciphertext_hiding": True,
        "cxl_allow": False,
        "debug": False,
        "mem_aes_256_xts": False,
        "migrate_ma": False,
        "page_swap_disable": True,
        "rapl_dis": False,
        "single_socket": False,
        "smt": False,
    },
    "signing_key": "vlek",
}

GCP_CPU: dict[str, Any] = {
    "cloud": {"project_number": "123456789012", "zone": "us-central1-a"},
    "cmd_override": [],
    "debug": False,
    "env_override": {},
    "migratable": False,
    "secboot": True,
    "support_attributes": ["LATEST", "STABLE", "USABLE"],
}

TDX_CPU: dict[str, Any] = {"debug": False, "migratable": False}

GPU: dict[str, Any] = {"bound_by_cpu_evidence": True, "cc_mode": "ON", "dbgstat": "disabled"}


def _with(base: dict[str, Any], path: str, value: Any) -> dict[str, Any]:
    out = copy.deepcopy(base)
    cur = out
    *head, last = path.split(".")
    for name in head:
        cur = cur[name]
    if value is ...:
        del cur[last]
    else:
        cur[last] = value
    return out


def outcome(case: dict[str, Any]) -> str:
    """The code that the policy checks give for a case, in rule order 9, 3."""
    try:
        check_cloud(case["profile"], case["cloud"], case["cpu"], case["production"])
        check_policy(case["profile"], case["cpu"], case["gpu"])
    except Refused as exc:
        return exc.code
    return "ok"


def cases() -> list[dict[str, Any]]:
    def case(name: str, profile: str, cpu: dict, *, cloud: dict | None = None, gpu: dict | None = None,
             production: bool = True, expect: str) -> dict[str, Any]:  # fmt: skip
        pins = {"raw-snp": SNP_PINS, "gcp-cs": GCP_PINS}.get(profile, {})
        return {
            "cloud": pins if cloud is None else cloud,
            "cpu": cpu,
            "expect": expect,
            "gpu": gpu,
            "name": name,
            "production": production,
            "profile": profile,
        }

    snp, gcp, tdx = SNP_CPU, GCP_CPU, TDX_CPU
    out = [
        # Rule 9: cloud binding.
        case("snp_vlek_pinned", "raw-snp", snp, expect="ok"),
        case(
            "snp_vcek",
            "raw-snp",
            _with(_with(snp, "signing_key", "vcek"), "csp_id", None),
            expect="evidence_not_cloud_bound",
        ),  # fmt: skip
        case(
            "snp_vlek_other_cloud",
            "raw-snp",
            _with(snp, "csp_id", "OtherCloud"),
            expect="evidence_not_cloud_bound",
        ),  # fmt: skip
        case(
            "snp_vcek_in_development",
            "raw-snp",
            _with(snp, "signing_key", "vcek"),
            production=False,
            expect="evidence_not_cloud_bound",
        ),  # fmt: skip
        case("gcp_pinned", "gcp-cs", gcp, gpu=GPU, expect="ok"),
        case(
            "gcp_other_project",
            "gcp-cs",
            _with(gcp, "cloud.project_number", "999"),
            expect="evidence_not_cloud_bound",
        ),  # fmt: skip
        case(
            "gcp_other_zone",
            "gcp-cs",
            _with(gcp, "cloud.zone", "europe-west4-a"),
            expect="evidence_not_cloud_bound",
        ),  # fmt: skip
        case(
            "gcp_no_gce_claims",
            "gcp-cs",
            _with(gcp, "cloud", None),
            expect="evidence_not_cloud_bound",
        ),  # fmt: skip
        case("tdx_production", "raw-tdx", tdx, expect="evidence_not_cloud_bound"),
        case("tdx_development", "raw-tdx", tdx, production=False, expect="ok"),
        case("azure_parked", "azure-cvm-gpu", tdx, expect="evidence_not_cloud_bound"),
        case("simulated_has_no_cloud", "simulated", tdx, production=False, expect="ok"),
        # Rule 3: one bit at a time, each with its own code.
        case("snp_debug", "raw-snp", _with(snp, "debug", True), expect="policy_refused"),
        case("snp_migratable", "raw-snp", _with(snp, "migratable", True), expect="policy_refused"),
        case("snp_smt", "raw-snp", _with(snp, "policy.smt", True), expect="smt_allowed"),
        case(
            "snp_ciphertext_hiding_off",
            "raw-snp",
            _with(snp, "policy.ciphertext_hiding", False),
            expect="ciphertext_hiding_off",
        ),  # fmt: skip
        case(
            "snp_page_swap",
            "raw-snp",
            _with(snp, "policy.page_swap_disable", False),
            expect="page_swap_allowed",
        ),  # fmt: skip
        case("snp_no_policy", "raw-snp", _with(snp, "policy", ...), expect="smt_allowed"),
        case(
            "gcp_secure_boot_off", "gcp-cs", _with(gcp, "secboot", False), expect="secure_boot_off"
        ),  # fmt: skip
        case(
            "gcp_image_not_stable",
            "gcp-cs",
            _with(gcp, "support_attributes", ["USABLE"]),
            expect="image_not_stable",
        ),  # fmt: skip
        case(
            "gcp_cmd_override",
            "gcp-cs",
            _with(gcp, "cmd_override", ["/bin/sh"]),
            expect="launch_override",
        ),  # fmt: skip
        case(
            "gcp_env_override",
            "gcp-cs",
            _with(gcp, "env_override", {"DEBUG": "1"}),
            expect="launch_override",
        ),  # fmt: skip
        case(
            "gcp_gpu_devtools",
            "gcp-cs",
            gcp,
            gpu=_with(GPU, "dbgstat", "enabled"),
            expect="policy_refused",
        ),  # fmt: skip
        # Rule 9 comes before rule 3.
        case(
            "cloud_before_policy",
            "raw-snp",
            _with(_with(snp, "signing_key", "vcek"), "policy.smt", True),
            expect="evidence_not_cloud_bound",
        ),  # fmt: skip
    ]
    wrong = [c["name"] for c in out if outcome(c) != c["expect"]]
    if wrong:
        raise ValueError(f"cases that do not give their code: {wrong}")
    return out


def build() -> dict[str, Any]:
    return {"cases": cases(), "schema": "anagram.vectors.enclave_policy.v1"}


def main(argv: list[str] | None = None) -> None:
    out = (
        output_dir(argv, prog="python -m anagram.vectors.enclave_policy", description=__doc__)
        / FILE
    )
    out.write_text(json.dumps(build(), indent=1, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
