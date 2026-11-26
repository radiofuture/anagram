"""Write or check a directory of vendored JavaScript modules.

    uv run python scripts/vendor_js.py src/anagram/shell/ui/static/vendor           # download and write
    uv run python scripts/vendor_js.py src/anagram/shell/ui/static/vendor --check   # no network
    uv run python scripts/vendor_js.py <target dir> --update                  # accept new hashes

The target directory holds `manifest.json`. The manifest is the pin and the
input of this script:

    {"files": {"preact.mjs": {"package": "preact", "version": "11.2.0", "license": "MIT",
                              "source": "https://registry.npmjs.org/preact/-/preact-11.2.0.tgz#package/dist/preact.mjs",
                              "sha256": "<hex>"}}}

`source` is the URL of the release file (an npm tarball). The text after `#`
is the path of the module in the tarball. To add a module, add an entry with
no `sha256` and run the script. The script removes `//# sourceMappingURL`
lines; the hash is the hash of the result. A hash that is in the manifest and
does not match the download stops the script (use `--update` only after a
review of the new file).

The script writes `LICENSES.txt` from the license file of each tarball. A write
needs the network. `--check` and the tests do not. Do not edit the copies.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import tarfile
import urllib.request
from pathlib import Path

KEYS = ("package", "version", "license", "source", "sha256")
# The comment is on its own line or at the end of the last line of code.
SOURCE_MAP = re.compile(rb"[ \t]*//[#@][ \t]*sourceMappingURL=[^\r\n]*(?:\r?\n)?")
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
LICENSE_NAMES = ("package/LICENSE", "package/LICENSE.md", "package/LICENSE.txt", "package/license")
OWN_FILES = ("manifest.json", "LICENSES.txt")


class VendorError(Exception):
    pass


def strip_source_map(content: bytes) -> bytes:
    return SOURCE_MAP.sub(b"", content)


def load_manifest(target: Path) -> dict:
    path = target / "manifest.json"
    if not path.exists():
        raise VendorError(f"{path} does not exist. Write it first (see the top of this script).")
    manifest = json.loads(path.read_text())
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise VendorError(f"{path} has no files.")
    for name, entry in files.items():
        if not NAME.match(name) or name in OWN_FILES:
            raise VendorError(f"Bad file name in the manifest: {name}")
        for key in KEYS[:4]:
            if not isinstance(entry.get(key), str) or not entry[key]:
                raise VendorError(f"{name}: the manifest entry has no {key}.")
        url, _, member = entry["source"].partition("#")
        if not url.startswith("https://") or not member.startswith("package/"):
            raise VendorError(f"{name}: source must be https://…tgz#package/<path>.")
    return manifest


def check(target: Path) -> list[str]:
    """Return the faults of a vendor directory. No network."""
    faults: list[str] = []
    try:
        manifest = load_manifest(target)
    except (VendorError, ValueError) as exc:
        return [str(exc)]
    files = manifest["files"]
    for name, entry in sorted(files.items()):
        path = target / name
        if not path.is_file():
            faults.append(f"{name}: the file is absent.")
            continue
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != entry.get("sha256"):
            faults.append(f"{name}: the hash differs from the manifest.")
        if b"sourceMappingURL" in content:
            faults.append(f"{name}: has a sourceMappingURL line.")
    if not (target / "LICENSES.txt").is_file():
        faults.append("LICENSES.txt is absent.")
    present = {p.name for p in target.iterdir()}
    for extra in sorted(present - set(files) - set(OWN_FILES)):
        faults.append(f"{extra}: not in the manifest.")
    return faults


def fetch(url: str) -> bytes:  # pragma: no cover - network
    if not url.startswith("https://"):
        raise VendorError(f"Not an https URL: {url}")
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - https only
        return response.read()


def member_bytes(tarball: bytes, member: str) -> bytes | None:
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as tar:
        try:
            handle = tar.extractfile(member)
        except KeyError:
            return None
        return handle.read() if handle is not None else None


def write(target: Path, *, update: bool = False, fetch=fetch) -> None:
    manifest = load_manifest(target)
    tarballs: dict[str, bytes] = {}
    licenses: dict[str, str] = {}
    for name, entry in sorted(manifest["files"].items()):
        url, _, member = entry["source"].partition("#")
        if url not in tarballs:
            tarballs[url] = fetch(url)
        raw = member_bytes(tarballs[url], member)
        if raw is None:
            raise VendorError(f"{name}: {member} is not in {url}")
        content = strip_source_map(raw)
        digest = hashlib.sha256(content).hexdigest()
        pinned = entry.get("sha256")
        if pinned and pinned != digest and not update:
            raise VendorError(
                f"{name}: the download does not match the pinned hash. "
                "Examine the file, then use --update."
            )
        entry["sha256"] = digest
        (target / name).write_bytes(content)
        title = f"{entry['package']} {entry['version']} ({entry['license']})"
        if title not in licenses:
            text = next(
                (t for t in (member_bytes(tarballs[url], n) for n in LICENSE_NAMES) if t), None
            )
            if text is None:
                raise VendorError(f"{name}: no license file in {url}")
            licenses[title] = text.decode("utf-8").strip()
    parts = [f"{title}\n{'=' * len(title)}\n\n{text}\n" for title, text in sorted(licenses.items())]
    (target / "LICENSES.txt").write_text("\n".join(parts))
    for entry in manifest["files"].values():
        for key in [k for k in entry if k not in KEYS]:
            del entry[key]
    (target / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("target", type=Path, help="the vendor directory (holds manifest.json)")
    parser.add_argument("--check", action="store_true", help="fail if a file differs; no network")
    parser.add_argument("--update", action="store_true", help="accept a changed hash")
    args = parser.parse_args()
    try:
        if args.check:
            faults = check(args.target)
            if faults:
                raise VendorError("\n".join(faults))
        else:
            write(args.target, update=args.update)
            faults = check(args.target)
            if faults:
                raise VendorError("\n".join(faults))
    except VendorError as exc:
        raise SystemExit(f"Vendored modules: {exc}") from exc


if __name__ == "__main__":
    main()
