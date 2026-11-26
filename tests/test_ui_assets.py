"""The UI is self-contained: no file outside the package, no CDN, brand
files that match their manifest, and pinned vendored modules
(scripts/vendor_js.py). The rules apply to `src/anagram/shell/ui/static/`
and to `src/anagram/web/`.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import re
from pathlib import Path

PRODUCT = Path(__file__).resolve().parents[1]
STATIC = PRODUCT / "src/anagram/shell/ui/static"
WEB = PRODUCT / "src/anagram/web"
ROOTS = [STATIC, WEB]
# Our own code puts text in the page as text. It does not use these.
HTML_SINKS = (
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "dangerouslySetInnerHTML",
    "document.write",
)
VENDOR_KEYS = {"package", "version", "license", "source", "sha256"}


def _files(*suffixes: str):
    for root in ROOTS:
        if root.exists():
            yield from (f for f in sorted(root.rglob("*")) if f.suffix in suffixes)


def _vendor_dirs() -> list[Path]:
    return [
        d for root in ROOTS if root.exists() for d in sorted(root.rglob("vendor")) if d.is_dir()
    ]


def _vendor_js():
    spec = importlib.util.spec_from_file_location("vendor_js", PRODUCT / "scripts/vendor_js.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_brand_copies_match_manifest():
    manifest = json.loads((STATIC / "brand/manifest.json").read_text())
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((STATIC / "brand" / name).read_bytes()).hexdigest() == digest, name


def test_no_external_references():
    for f in _files(".html", ".js", ".mjs", ".css"):
        text = f.read_text()
        assert not re.search(r"(src|href)=[\"']https?://", text), f
        assert "@import url('http" not in text, f
        assert "sourceMappingURL" not in text, f
        if "brand" in f.parts or "vendor" in f.parts:
            continue  # unchanged copies with a hash manifest (pdf.js has `cdNumChunks`)
        assert "cdn" not in text.lower(), f
        for sink in HTML_SINKS:
            assert sink not in text, f"{f}: {sink}"


def test_only_the_core_module_imports_the_vendored_modules():
    for f in _files(".js", ".html"):
        if "brand" in f.parts or "vendor" in f.parts or f.suffix == ".html":
            continue
        if f == STATIC / "js/core/html.js":
            continue
        text = f.read_text()
        assert "/vendor/" not in text, f
        assert not re.search(r"from\s+['\"](preact|htm|@preact)", text), f


def test_vendor_directories_match_their_manifests():
    dirs = _vendor_dirs()
    assert STATIC / "vendor" in dirs
    vendor_js = _vendor_js()
    for d in dirs:
        assert vendor_js.check(d) == [], d
        manifest = json.loads((d / "manifest.json").read_text())
        names = {p.name for p in d.iterdir()}
        assert names == set(manifest["files"]) | {"manifest.json", "LICENSES.txt"}, d
        for name, entry in manifest["files"].items():
            assert set(entry) == VENDOR_KEYS, (d, name)
            assert entry["source"].startswith("https://"), (d, name)
            assert entry["version"] in entry["source"], (d, name)
            digest = hashlib.sha256((d / name).read_bytes()).hexdigest()
            assert digest == entry["sha256"], f"{d / name} differs: run scripts/vendor_js.py"
        licenses = (d / "LICENSES.txt").read_text()
        for entry in manifest["files"].values():
            assert f"{entry['package']} {entry['version']} ({entry['license']})" in licenses, d


def test_vendor_script_removes_source_map_comments():
    strip = _vendor_js().strip_source_map
    assert strip(b"export{a};//# sourceMappingURL=a.mjs.map") == b"export{a};"
    assert strip(b"let a;\n//# sourceMappingURL=a.mjs.map\n") == b"let a;\n"
    assert strip(b"let a;\n") == b"let a;\n"


def test_import_map_names_only_vendored_files():
    html = (STATIC / "index.html").read_text()
    blocks = re.findall(r'<script type="importmap">(.*?)</script>', html, re.DOTALL)
    assert len(blocks) == 1
    # The import map comes before the first module script (a later map is ignored).
    assert html.index('type="importmap"') < html.index('type="module"')
    manifest = json.loads((STATIC / "vendor/manifest.json").read_text())
    imports = json.loads(blocks[0])["imports"]
    assert {v for v in imports.values()} == {f"/static/vendor/{n}" for n in manifest["files"]}
    # No other inline script: each other script tag has a src.
    for tag in re.findall(r"<script\b[^>]*>", html):
        assert 'type="importmap"' in tag or " src=" in tag, tag


def test_csp_hash_equals_the_import_map_hash():
    from anagram.shell.ui import server

    html = (STATIC / "index.html").read_text(encoding="utf-8")
    block = re.search(r'<script type="importmap">(.*?)</script>', html, re.DOTALL).group(1)
    digest = base64.b64encode(hashlib.sha256(block.encode()).digest()).decode()
    assert server.IMPORTMAP_SHA == digest
    policy = dict(part.strip().split(" ", 1) for part in server.CSP.split(";"))
    assert policy["script-src"] == f"'self' 'sha256-{digest}'"
    assert policy["worker-src"] == "'self'"
    assert policy["img-src"] == "'self' data: blob:"
    assert "unsafe" not in server.CSP
