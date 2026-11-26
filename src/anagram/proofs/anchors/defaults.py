"""Default anchors of a real node, the bundled TSA roots, and plain labels.

Default TSAs (free, public, no account; checked live on 2026-10-15):

- FreeTSA, https://freetsa.org/tsr. Root: "Free TSA Root CA" (valid to 2041).
  Its TSA certificate changed in March 2026 (P-384 key, valid to 2040).
- DigiCert, http://timestamp.digicert.com. Root: "DigiCert Trusted Root G4"
  (valid to 2038). DigiCert gives only an http URL. This is safe: the token is
  signed, and the verifier checks the signature and the chain.

OpenTimestamps uses the public calendars in `anagram.proofs.anchors.ots`.

The bundled roots (`roots/*.pem`) are public CA certificates, the same as a
browser trust store. A verifier can add other roots with `--tsa-root`. A node
cannot change them, because the verifier reads them from its own package.
"""

from __future__ import annotations

from functools import cache
from importlib import resources
from urllib.parse import urlsplit

from cryptography import x509

DEFAULT_TSAS = ("https://freetsa.org/tsr", "http://timestamp.digicert.com")
DEFAULT_ANCHORS = (*(f"rfc3161:{u}" for u in DEFAULT_TSAS), "opentimestamps")
NETWORK_KINDS = ("rfc3161", "opentimestamps")
ROOT_FILES = ("freetsa-root.pem", "digicert-trusted-root-g4.pem")


@cache
def _roots_pem() -> tuple[bytes, ...]:
    base = resources.files("anagram.proofs.anchors").joinpath("roots")
    return tuple(base.joinpath(name).read_bytes() for name in ROOT_FILES)


def bundled_tsa_roots() -> list[x509.Certificate]:
    """The TSA roots for the default TSAs (new objects at each call)."""
    return [x509.load_pem_x509_certificate(p) for p in _roots_pem()]


def anchor_kind(spec: str) -> str:
    """Kind of a node anchor spec: fake, rfc3161, or opentimestamps."""
    if spec == "fake":
        return "fake"
    if spec.startswith("rfc3161:"):
        return "rfc3161"
    if spec == "opentimestamps" or spec.startswith("opentimestamps:"):
        return "opentimestamps"
    raise ValueError(f"unknown anchor: {spec}")


def describe_record(record: object) -> str:
    """A short plain label for an anchor record (no check)."""
    if not isinstance(record, dict):
        return "unknown anchor"
    kind = record.get("type")
    if kind == "rfc3161":
        host = urlsplit(str(record.get("tsa", ""))).hostname or "unknown TSA"
        return f"RFC 3161 timestamp from {host}"
    if kind == "opentimestamps":
        return "OpenTimestamps (Bitcoin)"
    if kind == "fake":
        return "fake anchor (local test key, NO independent time)"
    return f"unknown anchor type {kind!r}"
