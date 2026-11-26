"""Glue between the clean-room client and a running network: the enclave
log read API over HTTP (enclave-trust.md 2.1), and the pinned keys.

`GET /log/entries?start=&end=` gives at most 256 entries at a time, so the
reader asks in runs of 256.
"""

from __future__ import annotations

from dataclasses import dataclass

from .core import parse_canonical
from .logs import NoteKey
from .trust import Pins

RUN = 256


@dataclass
class LogAdapter:
    http: object  # a client of the log service (httpx)

    def entries(self, start: int, end: int) -> list[dict]:
        out: list[dict] = []
        for at in range(start, end, RUN):
            r = self.http.get(f"/log/entries?start={at}&end={min(at + RUN, end)}")
            if r.status_code != 200:
                raise RuntimeError(f"log entries {r.status_code}")
            out += parse_canonical(r.content)["entries"]
        return out

    def covering(self, index: int) -> str:
        return self._note(f"/log/checkpoint/covering/{index}")

    def checkpoint(self) -> str:
        return self._note("/log/checkpoint")

    def _note(self, path: str) -> str:
        r = self.http.get(path)
        if r.status_code != 200:
            raise RuntimeError(f"{path} {r.status_code}")
        return r.content.decode("utf-8")


def pins_from(roots: object) -> Pins:
    """Pins from the test network's published root keys (the values an app
    binary would carry, enclave-trust.md 2.6)."""

    def note(v: object) -> NoteKey:
        return NoteKey(v.name, v.alg, bytes(v.public))

    return Pins(
        log_key=note(roots.log_key),
        witnesses=[
            {
                "key": note(w.cosign),
                "entry_key": w.entry_key,
                "independent": w.independent,
                "name": w.cosign.name,
            }
            for w in roots.witnesses
        ],
        release_key=roots.release_key,
        rebuilders=list(roots.rebuilders),
        dev_root=roots.dev_root,
    )
