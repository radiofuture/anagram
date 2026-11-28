"""Cloud binding (rule 9) and the policy bits (rule 3) of each profile
(spec/enclave-trust.md 3.5 and 4.9).

Both read only the claims of evidence that rule 8 has verified, and the
`cloud` pins of an accepted release. Each enforced bit has its own code, so
a refusal names its cause. The debug, migration and GPU checks keep the
code `policy_refused` of the first draft.
"""

from __future__ import annotations

from anagram.core.canonical import JsonObject
from anagram.network.formats.strict import Refused

NOT_CLOUD_BOUND = "evidence_not_cloud_bound"
CLOUD_CODES = (NOT_CLOUD_BOUND,)

# Rule 3 codes. `policy_refused` covers debug, migration and the GPU mode.
POLICY_CODES = (
    "policy_refused",
    "smt_allowed",
    "ciphertext_hiding_off",
    "page_swap_allowed",
    "secure_boot_off",
    "image_not_stable",
    "launch_override",
)

# The profiles whose evidence names the cloud that runs it, and the pins
# that a release gives for each (section 2.3). `raw-tdx` evidence names no
# cloud: a production app refuses it. `azure-cvm-gpu` is parked (section 20).
CLOUD_PINS = {
    "raw-snp": ("csp_ids",),
    "gcp-cs": ("project_numbers", "zones"),
    "raw-tdx": (),
    "azure-cvm-gpu": (),
}


def check_cloud(profile: str, cloud: JsonObject, cpu: JsonObject, production: bool) -> None:
    """Rule 9: the evidence shows that a pinned cloud runs the instance.
    `cloud` is the release's `profiles[profile].cloud` ({} for `simulated`)."""
    if profile == "simulated":
        return  # protects nothing; a production app refuses it by rule 8
    if profile == "raw-snp":
        # Only a VLEK names a cloud (its csp_id). A VCEK names a chip, and a
        # machine that the operator owns can have one.
        if cpu.get("signing_key") != "vlek":
            raise Refused(NOT_CLOUD_BOUND, "a VCEK names no cloud")
        if cpu.get("csp_id") not in cloud.get("csp_ids", []):
            raise Refused(NOT_CLOUD_BOUND, "the VLEK's cloud is not pinned")
        return
    if profile == "gcp-cs":
        where = cpu.get("cloud")
        if not isinstance(where, dict):
            raise Refused(NOT_CLOUD_BOUND, "no project or zone")
        if where.get("project_number") not in cloud.get("project_numbers", []):
            raise Refused(NOT_CLOUD_BOUND, "the project is not pinned")
        if where.get("zone") not in cloud.get("zones", []):
            raise Refused(NOT_CLOUD_BOUND, "the zone is not pinned")
        return
    if profile == "raw-tdx" and not production:
        return  # development only: TDX evidence names no cloud
    raise Refused(NOT_CLOUD_BOUND, f"{profile} evidence names no cloud")


def check_policy(profile: str, cpu: JsonObject, gpu: JsonObject | None) -> None:
    """Rule 3: the policy bits that the profile's evidence shows."""
    if cpu.get("debug") is not False or cpu.get("migratable") is not False:
        raise Refused("policy_refused", "cpu")
    if gpu is not None and (gpu.get("dbgstat") != "disabled" or gpu.get("cc_mode") != "ON"):
        raise Refused("policy_refused", "gpu")
    if profile == "raw-snp":
        policy = cpu.get("policy")
        policy = policy if isinstance(policy, dict) else {}
        if policy.get("smt") is not False:
            raise Refused("smt_allowed")
        if policy.get("ciphertext_hiding") is not True:
            raise Refused("ciphertext_hiding_off")
        if policy.get("page_swap_disable") is not True:
            raise Refused("page_swap_allowed")
    elif profile == "gcp-cs":
        if cpu.get("secboot") is not True:
            raise Refused("secure_boot_off")
        attributes = cpu.get("support_attributes")
        if not isinstance(attributes, list) or "STABLE" not in attributes:
            raise Refused("image_not_stable")
        if cpu.get("cmd_override") != [] or cpu.get("env_override") != {}:
            raise Refused("launch_override")
