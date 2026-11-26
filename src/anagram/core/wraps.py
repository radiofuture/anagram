"""Key wraps: one secret sealed (HPKE) to each device of a person.

A wrap list is `[{"ciphertext": base64, "device": ed25519 hex}, ...]`, sorted
by device and unique. Grants, guardian sets, lab key packages, and recovery
use it (spec/vault.md, spec/lab.md).
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable, Sequence
from typing import Any, TypedDict

from anagram.core.canonical import JsonObject
from anagram.core.crypto import hpke
from anagram.core.errors import FormatError
from anagram.core.validate import HEX32, exact_fields, hex_field

MAX_WRAPS = 32


class Wrap(TypedDict):
    """One entry of a wrap list."""

    ciphertext: str  # base64 of the HPKE output
    device: str  # ed25519 public key, hex


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_field(value: Any, what: str) -> bytes:
    """Standard base64 text (strict) to bytes."""
    try:
        if not isinstance(value, str):
            raise TypeError
        return base64.b64decode(value, validate=True)
    except (TypeError, ValueError, binascii.Error) as exc:
        raise FormatError(f"{what}: bad base64") from exc


def validate_wraps(wraps: Any) -> None:
    if not isinstance(wraps, list) or not 0 < len(wraps) <= MAX_WRAPS:
        raise FormatError("wraps: need 1 to 32 device wraps")
    devices = []
    for w in wraps:
        exact_fields(w, {"ciphertext", "device"}, "wrap")
        devices.append(hex_field(w["device"], HEX32, "device"))
        b64_field(w["ciphertext"], "ciphertext")
    if devices != sorted(set(devices)):
        raise FormatError("wraps: devices must be sorted and unique")


def wrap_to_devices(
    plaintext: bytes, devices: Sequence[JsonObject], info_for: Callable[[bytes], bytes]
) -> list[Wrap]:
    """HPKE-seal the same plaintext to each device X25519 key. Each device has
    the hex fields `ed25519` and `x25519`."""
    out: list[Wrap] = []
    for d in sorted(devices, key=lambda d: d["ed25519"]):
        ct = hpke.seal(bytes.fromhex(d["x25519"]), plaintext, info_for(bytes.fromhex(d["ed25519"])))
        out.append({"ciphertext": b64(ct), "device": d["ed25519"]})
    return out


def find_wrap(wraps: Sequence[Wrap], device_ed25519: str) -> bytes | None:
    for w in wraps:
        if w["device"] == device_ed25519:
            return b64_field(w["ciphertext"], "ciphertext")
    return None
