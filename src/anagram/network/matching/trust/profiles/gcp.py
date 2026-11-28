"""The `gcp-cs` profile: a Google Confidential Space attestation token of
the PKI type (spec/enclave-trust.md 2.6, 4.5, rule 8).

Sources: Google Cloud, "Attestation token claims"; "Access resources not
managed by Google Cloud IAM" (the PKI token and its validation); "Attestation
token validation endpoint fields" (`root_ca_uri`). Read 2026-11-27.

    Confidential Space Root CA (self-signed, pinned; rotates every 10 years)
     └─ intermediate
         └─ leaf (signs the token, RS256)

The token is a JWT whose header carries the chain in `x5c` (leaf,
intermediate, root). Every certificate is sha256WithRSAEncryption with an
RSA key; the token is RS256 by the leaf.

Every check is total on untrusted input: it gives `Refused` with a spec
code, never another exception.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import SignatureAlgorithmOID

from anagram.core.canonical import JsonObject
from anagram.network.formats.strict import Refused
from anagram.network.matching.trust.profiles import Claims, evidence_object
from anagram.network.matching.trust.profiles.amd import (
    _bit_string_unused,
    _check_ca,
    _check_not_ca,
    _cn,
    _load_cert,
    untrusted,
)
from anagram.network.matching.trust.release import version_key
from anagram.network.matching.trust.roots import Roots

ISSUER = "https://confidentialcomputing.googleapis.com"
AUDIENCE = "anagram/v1/enclave"
ROOT_CN = "Confidential Space Root CA"
MIN_RSA_BITS = 2048
# The DER AlgorithmIdentifier of sha256WithRSAEncryption (NULL parameters).
# The outer copy is outside the signature, so only these exact bytes pass.
_RSA_SHA256_ALG = bytes.fromhex("300d06092a864886f70d01010b0500")
MAX_TOKEN = 64 * 1024
TCB_REQUIRED = ("swversion", "tcb_evaluation_data_number", "tcb_status")
REFERENCE_FIELDS = ("args", "env", "gpu", "hwmodel", "image_digest", "restart_policy", "swname")

_B64URL = re.compile(r"\A[A-Za-z0-9_-]*\Z")
_DIGITS = re.compile(r"\A[0-9]{1,9}\Z")
_VERSION = re.compile(r"\A[0-9A-Fa-f]{1,8}(\.[0-9A-Fa-f]{1,8}){0,7}\Z")


# --- the JWT and its chain -----------------------------------------------------


def _b64url(part: str, what: str) -> bytes:
    if not _B64URL.match(part) or len(part) % 4 == 1:
        raise Refused("bad_attestation", f"token {what} is not base64url")
    try:
        return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    except (binascii.Error, ValueError) as exc:
        raise Refused("bad_attestation", f"token {what} is not base64url") from exc


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out = dict(pairs)
    if len(out) != len(pairs):
        raise Refused("bad_attestation", "token has a duplicate name")
    return out


def _no_constant(name: str) -> None:
    raise Refused("bad_attestation", f"token has {name}")


def _json_object(raw: bytes, what: str) -> dict[str, Any]:
    try:
        obj = json.loads(raw, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except (ValueError, RecursionError) as exc:  # bad JSON, bad UTF-8, or nested too deep
        raise Refused("bad_attestation", f"token {what} is not JSON") from exc
    if not isinstance(obj, dict):
        raise Refused("bad_attestation", f"token {what} form")
    return obj


def _rsa_key(key: object, what: str) -> rsa.RSAPublicKey:
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < MIN_RSA_BITS:
        raise Refused("untrusted_root", f"{what}: not an RSA key of {MIN_RSA_BITS} bits or more")
    return key


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate, what: str) -> None:
    """sha256WithRSAEncryption (PKCS #1 v1.5) by `issuer`, with the exact
    algorithm identifier inside and outside the signed part."""
    if cert.issuer != issuer.subject:
        raise Refused("untrusted_root", f"{what}: issuer name")
    if cert.signature_algorithm_oid != SignatureAlgorithmOID.RSA_WITH_SHA256:
        raise Refused("untrusted_root", f"{what}: not sha256WithRSAEncryption")
    der = cert.public_bytes(serialization.Encoding.DER)
    tbs = cert.tbs_certificate_bytes
    at = der.find(tbs)
    outer = der[at + len(tbs) :] if at >= 0 else b""
    if not outer.startswith(_RSA_SHA256_ALG + b"\x03") or _RSA_SHA256_ALG not in tbs:
        raise Refused("untrusted_root", f"{what}: algorithm identifier")
    if _bit_string_unused(outer[len(_RSA_SHA256_ALG) :]) != 0:
        raise Refused("untrusted_root", f"{what}: signature has unused bits")
    key = _rsa_key(issuer.public_key(), f"{what} issuer")
    try:
        key.verify(cert.signature, tbs, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise Refused("untrusted_root", f"{what}: signature") from exc


@dataclass(frozen=True)
class Token:
    header: dict[str, Any]
    payload: dict[str, Any]
    valid_from: int  # the latest not-before of the chain and `nbf`
    valid_until: int  # the earliest expiry of the chain and `exp`


def _verify_chain(x5c: object, pin: str) -> tuple[rsa.RSAPublicKey, int, int]:
    """Steps 2 and 3: the `x5c` chain to the pinned root. Return the leaf
    key and the chain's validity."""
    if not isinstance(x5c, list) or len(x5c) != 3 or not all(isinstance(c, str) for c in x5c):
        raise Refused("untrusted_root", "x5c is not leaf, intermediate, root")
    ders = []
    for i, text in enumerate(x5c):
        try:
            ders.append(base64.b64decode(text, validate=True))
        except (binascii.Error, ValueError) as exc:
            raise Refused("untrusted_root", f"x5c[{i}] is not base64") from exc
    with untrusted("gcp chain"):
        # Step 2: the root is the pinned Confidential Space root.
        if hashlib.sha256(ders[2]).hexdigest() != pin:
            raise Refused("untrusted_root", "root is not the pinned Confidential Space root")
        leaf, mid, root = (
            _load_cert(d, n) for d, n in zip(ders, ("leaf", "intermediate", "root"), strict=True)
        )
        # Step 3: names and signatures.
        if _cn(root.subject) != ROOT_CN:
            raise Refused("untrusted_root", "root name")
        _issued_by(root, root, "root")
        _issued_by(mid, root, "intermediate")
        _issued_by(leaf, mid, "leaf")
        _check_ca(root, "root", crl_sign=True)
        _check_ca(mid, "intermediate", crl_sign=False)
        _check_not_ca(leaf, "leaf")
        leaf_key = _rsa_key(leaf.public_key(), "leaf")
        chain = (leaf, mid, root)
        not_before = max(int(c.not_valid_before_utc.timestamp()) for c in chain)
        not_after = min(int(c.not_valid_after_utc.timestamp()) for c in chain)
        if not_before >= not_after:
            raise Refused("untrusted_root", "certificate validity window is empty")
    return leaf_key, not_before, not_after


def verify_token(token: object, pin: str) -> Token:
    """Rule 8 for the token (spec section 4.5, steps 1 to 5)."""
    # Step 1: the form of the JWT.
    if not isinstance(token, str) or not token.isascii() or len(token) > MAX_TOKEN:
        raise Refused("bad_attestation", "token form")
    parts = token.split(".")
    if len(parts) != 3:
        raise Refused("bad_attestation", "token is not a JWS of 3 parts")
    header = _json_object(_b64url(parts[0], "header"), "header")
    if set(header) - {"alg", "kid", "typ", "x5c"} or header.get("alg") != "RS256":
        raise Refused("bad_attestation", "token header (alg must be RS256)")
    if "typ" in header and header["typ"] != "JWT":
        raise Refused("bad_attestation", "token header typ")
    leaf_key, not_before, not_after = _verify_chain(header.get("x5c"), pin)
    # Step 4: the leaf signs the token.
    signature = _b64url(parts[2], "signature")
    try:
        leaf_key.verify(
            signature, f"{parts[0]}.{parts[1]}".encode(), padding.PKCS1v15(), hashes.SHA256()
        )
    except InvalidSignature as exc:
        raise Refused("untrusted_root", "token signature") from exc
    # Step 5: issuer, audience and times.
    payload = _json_object(_b64url(parts[1], "payload"), "payload")
    if payload.get("iss") != ISSUER:
        raise Refused("untrusted_root", "token issuer")
    if payload.get("aud") != AUDIENCE:
        raise Refused("bad_attestation", "token audience")
    times = {}
    for name in ("exp", "iat", "nbf"):
        v = payload.get(name)
        if type(v) is not int or not 0 <= v < 2**40:
            raise Refused("bad_attestation", f"token {name}")
        times[name] = v
    if not times["nbf"] <= times["iat"] < times["exp"]:
        raise Refused("bad_attestation", "token times")
    return Token(header, payload, max(not_before, times["nbf"]), min(not_after, times["exp"]))


# --- the claims ------------------------------------------------------------------


def _get(obj: object, path: str, kind: type | tuple[type, ...], *, optional: bool = False) -> Any:
    """`a.b.c` of the payload, of `kind`; absent is `None` when optional."""
    cur: object = obj
    for name in path.split("."):
        if not isinstance(cur, dict) or name not in cur:
            if optional:
                return None
            raise Refused("bad_attestation", f"token claim {path}")
        cur = cur[name]
    if not isinstance(cur, kind) or (isinstance(cur, bool) and kind is int):
        raise Refused("bad_attestation", f"token claim {path}")
    return cur


def _strings(value: object, path: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise Refused("bad_attestation", f"token claim {path}")
    return list(value)


def _string_map(value: object, path: str) -> dict[str, str]:
    if not isinstance(value, dict) or not all(isinstance(v, str) for v in value.values()):
        raise Refused("bad_attestation", f"token claim {path}")
    return dict(value)


def _nonce(payload: dict[str, Any]) -> str:
    """`eat_nonce`: a string, or an array of exactly one string."""
    value = payload.get("eat_nonce")
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    if not isinstance(value, str):
        raise Refused("bad_attestation", "token claim eat_nonce (one nonce)")
    return value


def _tcb(payload: dict[str, Any]) -> dict[str, object]:
    """The floor items: `swversion` from the one value of `swversion`, and
    the TDX items from the one object of `tdx` (absent unless TDX)."""
    sw = _strings(payload.get("swversion"), "swversion")
    if len(sw) != 1 or not _DIGITS.match(sw[0]):
        raise Refused("bad_attestation", "token claim swversion")
    out: dict[str, object] = {"swversion": int(sw[0])}
    tdx = payload.get("tdx")
    if tdx is None:
        return out
    if not isinstance(tdx, list) or len(tdx) != 1:
        raise Refused("bad_attestation", "token claim tdx")
    number = _get(tdx[0], "tcb_evaluation_data_number", int)
    if not 0 <= number < 2**32:
        raise Refused("bad_attestation", "token claim tdx.tcb_evaluation_data_number")
    out["tcb_evaluation_data_number"] = number
    out["tcb_status"] = _get(tdx[0], "gcp_attester_tcb_status", str)
    return out


def _lowest(versions: list[str], base: int, path: str) -> str:
    for v in versions:
        if not _VERSION.match(v):
            raise Refused("bad_attestation", f"token claim {path}")
    return min(versions, key=lambda v: version_key(v, base))


def _gpu(payload: dict[str, Any]) -> JsonObject | None:
    """The GPU claims: Google verified the GPUs and put them in this token,
    so the token binds them (spec section 4.5, rule 6). The lowest driver
    and VBIOS versions meet the floor; `DEVTOOLS` is a debug mode."""
    nv = _get(payload, "submods.nvidia_gpu", dict, optional=True)
    if nv is None:
        return None
    gpus = _get(nv, "gpus", list)
    if not gpus or not all(isinstance(g, dict) for g in gpus):
        raise Refused("bad_attestation", "token claim submods.nvidia_gpu.gpus")
    models = sorted({_get(g, "hwmodel", str) for g in gpus})
    cc_mode = _get(nv, "cc_mode", str)
    return {
        "bound_by_cpu_evidence": True,
        "cc_feature": _get(nv, "cc_feature", str),
        "cc_mode": cc_mode,
        "count": len(gpus),
        "dbgstat": "enabled" if cc_mode == "DEVTOOLS" else "disabled",
        "driver_version": _lowest(
            [_get(g, "driver_version", str) for g in gpus], 10, "gpus.driver_version"
        ),
        "hwmodels": models,
        "vbios_version": _lowest(
            [_get(g, "vbios_version", str) for g in gpus], 16, "gpus.vbios_version"
        ),
    }


EVIDENCE_FIELDS = frozenset({"token"})


def _cloud(p: JsonObject) -> JsonObject | None:
    """The project and zone of the VM (`submods.gce`), for rule 9."""
    gce = _get(p, "submods.gce", dict, optional=True)
    if gce is None:
        return None
    return {
        "project_number": _get(gce, "project_number", str),
        "zone": _get(gce, "zone", str),
    }


def gcp_claims(platform_evidence: object, gpu_evidence: object, roots: Roots) -> Claims:
    """Rule 8 for `gcp-cs`, then the claims that the other rules read."""
    ev = evidence_object(platform_evidence, "platform_evidence")
    if set(ev) != EVIDENCE_FIELDS:
        raise Refused("bad_attestation", "gcp-cs evidence fields")
    if gpu_evidence is not None:
        raise Refused("bad_attestation", "gcp-cs has no separate GPU evidence")
    token = verify_token(ev["token"], roots.gcp_cs_root)
    p = token.payload
    container = _get(p, "submods.container", dict)
    gpu = _gpu(p)
    reference: JsonObject = {
        "args": _strings(_get(container, "args", list), "submods.container.args"),
        "env": _string_map(
            _get(container, "env", dict, optional=True) or {}, "submods.container.env"
        ),
        "gpu": gpu is not None,
        "hwmodel": _get(p, "hwmodel", str),
        "image_digest": _get(container, "image_digest", str),
        "restart_policy": _get(container, "restart_policy", str),
        "swname": _get(p, "swname", str),
    }
    cpu: JsonObject = {
        "cloud": _cloud(p),
        "cmd_override": _strings(
            _get(container, "cmd_override", list, optional=True) or [], "cmd_override"
        ),
        "debug": _get(p, "dbgstat", str) != "disabled-since-boot",
        "env_override": _string_map(
            _get(container, "env_override", dict, optional=True) or {}, "env_override"
        ),
        "migratable": False,  # Confidential Space VMs do not live-migrate
        "reference": reference,
        "report_data": _nonce(p),
        "secboot": _get(p, "secboot", bool),
        "support_attributes": _strings(
            _get(p, "submods.confidential_space.support_attributes", list),
            "submods.confidential_space.support_attributes",
        ),
        "tcb": _tcb(p),
        "tcb_required": list(TCB_REQUIRED),
        "valid_from": token.valid_from,
        "valid_until": token.valid_until,
    }
    return Claims(cpu=cpu, gpu=gpu)


@dataclass(frozen=True)
class GcpEvidence:
    """The evidence verifier of the `gcp-cs` profile."""

    profile: str = "gcp-cs"
    reason: str = "Google Confidential Space: a PKI attestation token chained to the pinned root"
    available: bool = True

    def claims(self, doc: JsonObject, roots: Roots) -> Claims:
        return gcp_claims(doc["platform_evidence"], doc["gpu_evidence"], roots)


VERIFIER = GcpEvidence()
