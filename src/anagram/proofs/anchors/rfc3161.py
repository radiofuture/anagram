"""RFC 3161 timestamp authority (TSA) adapter.

ASN.1 parsing and encoding use `asn1crypto`. Signature checks use pyca
`cryptography`. The adapter uses the network only in RFC3161Anchor.stamp().

Offline verification of a token checks:

1. The token is CMS SignedData with eContentType id-ct-TSTInfo.
2. The TSTInfo message imprint is SHA-256 and equals the expected digest.
3. Exactly one SignerInfo. Its signed attributes have content-type TSTInfo and a
   message-digest equal to the hash of the TSTInfo bytes.
4. The signature over the signed attributes is valid for the signer
   certificate (RSA PKCS#1 v1.5, ECDSA, or Ed25519).
5. If an ESS signing-certificate-v2 attribute is present, its hash matches the
   signer certificate.
6. The signer certificate has the critical extended key usage timeStamping.
7. A chain of issuer signatures leads from the signer certificate to one of the
   pinned TSA roots. Each certificate in the chain is valid at genTime.

Not checked: certificate revocation (CRL, OCSP), name constraints, policy OIDs,
and RSA-PSS signatures. A fail on any check gives ok=False.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import urllib.request
from collections.abc import Callable

from asn1crypto import cms, tsp
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID

from anagram.proofs.anchors.base import Anchor, AnchorCheck, AnchorTrust

Transport = Callable[[str, bytes], bytes]

_HASHES = {
    "sha256": (hashlib.sha256, hashes.SHA256),
    "sha384": (hashlib.sha384, hashes.SHA384),
    "sha512": (hashlib.sha512, hashes.SHA512),
}


class TSAError(ValueError):
    pass


def build_request(digest: bytes, nonce: int | None = None, cert_req: bool = True) -> bytes:
    """Build a DER TimeStampReq for a SHA-256 digest."""
    if len(digest) != 32:
        raise TSAError("digest must be 32 bytes (SHA-256)")
    fields = {
        "version": "v1",
        "message_imprint": {
            "hash_algorithm": {"algorithm": "sha256"},
            "hashed_message": digest,
        },
        "cert_req": cert_req,
    }
    if nonce is not None:
        fields["nonce"] = nonce
    return tsp.TimeStampReq(fields).dump()


def token_from_response(response: bytes, digest: bytes, nonce: int | None) -> bytes:
    """Check status, imprint, and nonce of a TimeStampResp. Return the token DER."""
    resp = tsp.TimeStampResp.load(response)
    status = resp["status"]["status"].native
    if status not in ("granted", "granted_with_mods"):
        raise TSAError(f"TSA refused: {status} {resp['status']['status_string'].native}")
    token = resp["time_stamp_token"]
    tst = token["content"]["encap_content_info"]["content"].parsed
    imprint = tst["message_imprint"]
    if imprint["hash_algorithm"]["algorithm"].native != "sha256":
        raise TSAError("TSA used a different hash algorithm")
    if imprint["hashed_message"].native != digest:
        raise TSAError("TSA token is for a different digest")
    if nonce is not None and tst["nonce"].native != nonce:
        raise TSAError("TSA nonce mismatch")
    return token.dump()


def _http_post(url: str, body: bytes) -> bytes:
    if not url.startswith("https://") and not url.startswith("http://"):
        raise TSAError("TSA URL must be http(s)")
    req = urllib.request.Request(  # noqa: S310 - scheme checked above
        url,
        data=body,
        headers={"Content-Type": "application/timestamp-query"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        return resp.read(1 << 20)


class RFC3161Anchor(Anchor):
    """Anchor through a TSA. stamp() uses the network (unless a transport is given)."""

    type = "rfc3161"

    def __init__(self, url: str, transport: Transport | None = None) -> None:
        self.url = url
        self.transport = transport or _http_post

    def stamp(self, digest: bytes) -> dict:
        nonce = secrets.randbits(63)
        response = self.transport(self.url, build_request(digest, nonce))
        token = token_from_response(response, digest, nonce)
        return {"token": base64.b64encode(token).decode(), "tsa": self.url, "type": self.type}


# ----------------------------------------------------------------- verification


def _verify_sig(cert: x509.Certificate, algo: str, hash_name: str, sig: bytes, data: bytes):
    pub = cert.public_key()
    h = _HASHES[hash_name][1]()
    if isinstance(pub, rsa.RSAPublicKey) and algo == "rsassa_pkcs1v15":
        pub.verify(sig, data, padding.PKCS1v15(), h)
    elif isinstance(pub, ec.EllipticCurvePublicKey) and algo == "ecdsa":
        pub.verify(sig, data, ec.ECDSA(h))
    elif isinstance(pub, ed25519.Ed25519PublicKey) and algo == "ed25519":
        pub.verify(sig, data)
    else:
        raise TSAError(f"unsupported signature algorithm: {algo}")


def _check_issuer_cert(
    cand: x509.Certificate,
    intermediates: int,
    *,
    is_root: bool,
    when,
) -> bool:
    """RFC 5280 checks on an issuer certificate (intermediate or pinned root)."""
    if not cand.not_valid_before_utc <= when <= cand.not_valid_after_utc:
        return False
    try:
        bc = cand.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return False
    if not bc.ca:
        return False
    if bc.path_length is not None and intermediates > bc.path_length:
        return False
    try:
        ku = cand.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        ku = None
    if ku is not None and not ku.key_cert_sign:
        return False
    if not is_root:
        try:
            eku = cand.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            eku = None
        if eku is not None and (
            ExtendedKeyUsageOID.TIME_STAMPING not in eku
            and ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE not in eku
        ):
            return False
    return True


def _find_root(
    current: x509.Certificate,
    candidates: list[x509.Certificate],
    root_map: dict[bytes, x509.Certificate],
    when,
    intermediates: int,
    seen: frozenset[bytes],
) -> x509.Certificate | None:
    if intermediates >= 8:
        return None
    for cand in candidates:
        if cand.subject != current.issuer:
            continue
        cand_fp = cand.fingerprint(hashes.SHA256())
        if cand_fp in seen:
            continue
        is_root = cand_fp in root_map
        if not _check_issuer_cert(cand, intermediates, is_root=is_root, when=when):
            continue
        try:
            current.verify_directly_issued_by(cand)
        except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
            continue
        if is_root:
            return root_map[cand_fp]
        found = _find_root(cand, candidates, root_map, when, intermediates + 1, seen | {cand_fp})
        if found is not None:
            return found
    return None


def _chain_to_root(
    leaf: x509.Certificate,
    pool: list[x509.Certificate],
    roots: list[x509.Certificate],
    when,
) -> x509.Certificate:
    if not leaf.not_valid_before_utc <= when <= leaf.not_valid_after_utc:
        raise TSAError(f"certificate not valid at genTime: {leaf.subject.rfc4514_string()}")
    try:
        leaf_bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        leaf_bc = None
    if leaf_bc is not None and leaf_bc.ca:
        raise TSAError("signer certificate must not be a CA")
    root_map = {r.fingerprint(hashes.SHA256()): r for r in roots}
    leaf_fp = leaf.fingerprint(hashes.SHA256())
    found = _find_root(leaf, roots + pool, root_map, when, 0, frozenset({leaf_fp}))
    if found is None:
        raise TSAError("no chain to a pinned TSA root")
    return found


def _signer_cert(certs: list[x509.Certificate], sid: cms.SignerIdentifier) -> x509.Certificate:
    """The certificate in the token that the signer identifier names."""
    signer = None
    for c in certs:
        if sid.name == "issuer_and_serial_number":
            ias = sid.chosen
            if c.serial_number == ias["serial_number"].native and (
                c.issuer.public_bytes() == ias["issuer"].dump()
            ):
                signer = c
        elif sid.name == "subject_key_identifier":
            try:
                ski = c.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            except x509.ExtensionNotFound:
                continue
            if ski.value.digest == sid.chosen.native:
                signer = c
    if signer is None:
        raise TSAError("signer certificate not in token")
    return signer


def _check_signer_cert(signer: x509.Certificate, by_type: dict) -> None:
    """Check the ESS certificate hash (if the token gives one) and the
    critical timeStamping extended key usage of the signer."""
    if "signing_certificate_v2" in by_type:
        ess = by_type["signing_certificate_v2"][0]["certs"][0]
        ess_hash = ess["hash_algorithm"]["algorithm"].native
        der = signer.public_bytes(Encoding.DER)
        if ess["cert_hash"].native != _HASHES[ess_hash][0](der).digest():
            raise TSAError("ESS signing certificate hash mismatch")
    try:
        eku = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound as exc:
        raise TSAError("signer has no extended key usage") from exc
    if not eku.critical or ExtendedKeyUsageOID.TIME_STAMPING not in eku.value:
        raise TSAError("signer is not a critical timeStamping certificate")


def verify_token(token_der: bytes, digest: bytes, roots: list[x509.Certificate]) -> AnchorCheck:
    try:
        ci = cms.ContentInfo.load(token_der)
        if ci["content_type"].native != "signed_data":
            raise TSAError("token is not SignedData")
        sd = ci["content"]
        eci = sd["encap_content_info"]
        if eci["content_type"].native != "tst_info":
            raise TSAError("token content is not TSTInfo")
        tst_bytes = eci["content"].contents
        tst = eci["content"].parsed
        imprint = tst["message_imprint"]
        if imprint["hash_algorithm"]["algorithm"].native != "sha256":
            raise TSAError("message imprint is not SHA-256")
        if imprint["hashed_message"].native != digest:
            raise TSAError("message imprint does not match the digest")
        gen_time = tst["gen_time"].native

        if len(sd["signer_infos"]) != 1:
            raise TSAError("expected exactly one signer")
        si = sd["signer_infos"][0]
        hash_name = si["digest_algorithm"]["algorithm"].native
        if hash_name not in _HASHES:
            raise TSAError(f"unsupported digest: {hash_name}")
        hfn = _HASHES[hash_name][0]
        attrs = si["signed_attrs"]
        if not attrs:
            raise TSAError("no signed attributes")
        by_type = {a["type"].native: a["values"] for a in attrs}
        if by_type.get("content_type", [None])[0].native != "tst_info":
            raise TSAError("signed content-type is not TSTInfo")
        if by_type.get("message_digest", [None])[0].native != hfn(tst_bytes).digest():
            raise TSAError("signed message-digest does not match TSTInfo")

        certs = [
            x509.load_der_x509_certificate(c.chosen.dump())
            for c in sd["certificates"] or []
            if c.name == "certificate"
        ]
        signer = _signer_cert(certs, si["sid"])

        signed_data = b"\x31" + attrs.dump()[1:]
        algo = si["signature_algorithm"].signature_algo
        _verify_sig(signer, algo, hash_name, si["signature"].native, signed_data)
        _check_signer_cert(signer, by_type)

        if not roots:
            raise TSAError("no TSA roots pinned")
        root_cert = _chain_to_root(signer, certs, list(roots), gen_time)
    except (
        TSAError,
        InvalidSignature,
        UnsupportedAlgorithm,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        IndexError,
        OverflowError,
    ) as exc:
        return AnchorCheck("rfc3161", False, detail=f"{type(exc).__name__}: {exc}")
    fingerprint = root_cert.fingerprint(hashes.SHA256()).hex()
    return AnchorCheck(
        "rfc3161",
        True,
        time=gen_time,
        detail=f"TSA chain to {root_cert.subject.rfc4514_string()}",
        source=f"rfc3161:{fingerprint}",
    )


def verify_record(record: dict, digest: bytes, trust: AnchorTrust) -> AnchorCheck:
    token = base64.b64decode(record["token"], validate=True)
    return verify_token(token, digest, trust.tsa_roots)
