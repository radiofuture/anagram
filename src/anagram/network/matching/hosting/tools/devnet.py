"""The keys and public pins of a development network (`simulated` profile).

    anagram enclave devnet init --dir DIR --network NET --origin ORIGIN

makes, in DIR:

    devnet.json   the public pins: network ID, roster key, log origin and key,
                  the three witnesses (two keys each and the flags), the
                  release key, the rebuilders and the development root.
                  Nodes and apps read only this file.
    keys/SERVICE/key.json   one key file for each service (`--keys DIR`
                  puts them in DIR/SERVICE/key.json):
                    log        log
                    roster     roster
                    enclave    dev-root (the simulated platform's root)
                    operator   release, rebuild-ci, rebuild-ext
                    witness-N  witness-N-cosign, witness-N-entry (N = 1, 2, 3)

A process started with `--key FILE` reads only that file, so a deployment
gives each service its own key file and nothing else (deploy/
compose.enclave.yaml). In a real network each key is in another place
(the witnesses are other organisations); here one host makes them all,
which is why the profile protects nothing.

Witness 1 is Radiofuture's (not independent), witness 2 a university's and
witness 3 a public witness network (both independent). Witnesses 1 and 2
read entries (spec/enclave-trust.md 2.4).
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from pathlib import Path

from anagram.core.canonical import canonical_json
from anagram.core.crypto.signing import SigningKey
from anagram.core.files import atomic_write
from anagram.network.matching.trust.pins import Pins, WitnessPin
from anagram.network.matching.trust.profiles.simulated import PROFILE
from anagram.proofs.log.note import ALG_COSIGNATURE_V1, NoteSigner

WITNESSES = (  # (number, independent, reads entries)
    (1, False, True),
    (2, True, True),
    (3, True, False),
)
KEYS_SCHEMA = "anagram.enclave.devnet-keys.v1"
KEY_FILE = "key.json"
SERVICE_KEYS: dict[str, tuple[str, ...]] = {
    "log": ("log",),
    "roster": ("roster",),
    "enclave": ("dev-root",),
    "operator": ("release", "rebuild-ci", "rebuild-ext"),
    **{f"witness-{n}": (f"witness-{n}-cosign", f"witness-{n}-entry") for n, _, _ in WITNESSES},
}


def witness_name(network: str, n: int) -> str:
    return f"witness-{n}.{network}"


def service_of(key: str) -> str:
    """The service whose key file holds the key `key`."""
    for service, names in SERVICE_KEYS.items():
        if key in names:
            return service
    raise KeyError(f"no development network key {key!r}")


@dataclass(frozen=True)
class DevNet:
    """A development network directory. With `key_file` (`--key FILE`) the
    process reads its keys from that file only; else from the key file of
    each key's service under `keys` (default DIR/keys)."""

    dir: Path
    key_file: Path | None = None
    keys: Path | None = None

    @property
    def pins_path(self) -> Path:
        return self.dir / "devnet.json"

    @property
    def keys_dir(self) -> Path:
        return self.keys or self.dir / "keys"

    def pins(self) -> Pins:
        return Pins.read(self.pins_path)

    def key(self, name: str) -> SigningKey:
        path = self.key_file or self.keys_dir / service_of(name) / KEY_FILE
        try:
            doc = json.loads(path.read_text())
        except FileNotFoundError:
            raise FileNotFoundError(f"development network key file missing: {path}") from None
        seed = doc.get("keys", {}).get(name) if doc.get("schema") == KEYS_SCHEMA else None
        if not isinstance(seed, str):
            raise FileNotFoundError(f"development network key {name} is not in {path}")
        return SigningKey.from_seed(bytes.fromhex(seed))

    def log_signer(self) -> NoteSigner:
        return NoteSigner(self.pins().origin, self.key("log"))

    def witness_keys(self, n: int) -> tuple[SigningKey, SigningKey]:
        """(cosignature/v1 key, entry key) of witness `n`."""
        return self.key(f"witness-{n}-cosign"), self.key(f"witness-{n}-entry")


def init_devnet(
    directory: str | Path, network: str, origin: str, keys: str | Path | None = None
) -> DevNet:
    """Make the key files of the services and `devnet.json`. Refuse a
    directory that has a network."""
    net = DevNet(Path(directory), keys=Path(keys) if keys is not None else None)
    if net.pins_path.exists():
        raise FileExistsError(f"a development network exists in {net.dir}")
    net.dir.mkdir(parents=True, exist_ok=True)
    for service, names in SERVICE_KEYS.items():
        folder = net.keys_dir / service
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        doc = {
            "keys": {name: secrets.token_bytes(32).hex() for name in names},
            "schema": KEYS_SCHEMA,
            "service": service,
        }
        atomic_write(folder / KEY_FILE, canonical_json(doc))
    witnesses = []
    for n, independent, reads in WITNESSES:
        cosign, entry = net.witness_keys(n)
        name = witness_name(network, n)
        verifier = NoteSigner(name, cosign, ALG_COSIGNATURE_V1).verifier
        witnesses.append(
            WitnessPin(name, verifier.vkey(), entry.public_bytes().hex(), independent, reads)
        )
    pins = Pins(
        profile=PROFILE,
        network=network,
        roster_key=net.key("roster").public_bytes().hex(),
        origin=origin,
        log_key=NoteSigner(origin, net.key("log")).verifier.vkey(),
        witnesses=tuple(witnesses),
        release_key=net.key("release").public_bytes().hex(),
        rebuilders=tuple(
            sorted(net.key(k).public_bytes().hex() for k in ("rebuild-ci", "rebuild-ext"))
        ),
        dev_root=net.key("dev-root").public_bytes().hex(),
    )
    text = json.dumps(pins.to_json(), indent=2, sort_keys=True) + "\n"
    atomic_write(net.pins_path, text.encode(), mode=0o644)  # public: the pins
    Pins.read(net.pins_path)  # the file reads back
    return net
