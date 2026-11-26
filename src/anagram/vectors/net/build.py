"""Write spec/vectors/pack.json, enclave-messages.json and network.json.

    uv run python -m anagram.vectors.net.build spec/vectors

The random values of the last run (Biscuit tokens, HPKE ciphertexts) stay
when they still verify (see `fixtures`), so a run with no change writes the
same files. Each file keeps its random values by label under "random".
"""

from __future__ import annotations

import json
from pathlib import Path

from anagram.vectors.cli import output_dir
from anagram.vectors.net import build_messages, build_network, build_pack
from anagram.vectors.net.fixtures import Reuse

FILES = ("pack.json", "enclave-messages.json", "network.json")


def previous_random(directory: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in FILES:
        path = directory / name
        if path.exists():
            out.update(json.loads(path.read_text()).get("random", {}))
    return out


def build_all(directory: Path) -> dict[str, dict]:
    previous = previous_random(directory)
    files = {}
    reuse = Reuse(previous)
    files["pack.json"] = build_pack.build(reuse)
    files["pack.json"]["random"] = dict(sorted(reuse.used.items()))
    reuse = Reuse(previous)
    small = files["pack.json"]["small_pack"]["doc"]
    known = bytes.fromhex(files["pack.json"]["known_small"]["hex"])
    files["enclave-messages.json"] = build_messages.build(reuse, small, known)
    files["enclave-messages.json"]["random"] = dict(sorted(reuse.used.items()))
    reuse = Reuse(previous)
    files["network.json"] = build_network.build(reuse)
    files["network.json"]["random"] = dict(sorted(reuse.used.items()))
    return files


def dump(obj: dict) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name, obj in build_all(directory).items():
        (directory / name).write_text(dump(obj))


if __name__ == "__main__":  # pragma: no cover
    write(output_dir(None, prog="python -m anagram.vectors.net.build", description=__doc__))
