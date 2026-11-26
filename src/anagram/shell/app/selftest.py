"""`anagram app selftest`: checks for a packaged build.

A packaged build (PyInstaller) must hold the native libraries and the data
files that the app uses. This command proves it on the build computer and in
CI, with no network and no keychain:

- keys: a file keystore in a temp data directory (no keychain item);
- vault: an encrypted local database (SQLCipher) opens, and a wrong key fails;
- index: the index store opens, and `sqlite-vec` loads into it;
- docx, pdf: markitdown converts one small Word file and one small PDF;
- data: the vocabulary and the static UI files are in the build;
- app: the app starts on a loopback port and `GET /health` answers.

Each check prints one line. The exit code is 0 only if all checks pass. The
temp data directory is removed at the end.
"""

from __future__ import annotations

import io
import json
import os
import secrets
import tempfile
import time
import urllib.request
import zipfile
from collections.abc import Callable
from pathlib import Path

CHECK_WORD = "Selftest"


def _keys(home: Path) -> None:
    from anagram.identity.api import open_keystore

    ks = open_keystore(home)
    value = secrets.token_bytes(32)
    ks.put("selftest-key", value)
    if ks.get("selftest-key") != value:
        raise RuntimeError("the keystore gave another value")


def _vault(home: Path) -> None:
    from anagram.local.api import (
        LocalDBError,
        connect,
    )

    key = secrets.token_bytes(32)
    path = home / "selftest.sqlite"
    db = connect(path, key, b"anagram.selftest.v1")
    db.execute("CREATE TABLE t (v TEXT)")
    db.execute("INSERT INTO t VALUES (?)", (CHECK_WORD,))
    db.close()
    if CHECK_WORD.encode() in path.read_bytes():
        raise RuntimeError("the database file is not encrypted")
    try:
        connect(path, secrets.token_bytes(32), b"anagram.selftest.v1").close()
    except LocalDBError:
        return
    raise RuntimeError("a wrong key opened the database")


def _index(home: Path) -> None:
    from anagram.local.api import IndexStore

    store = IndexStore(home / "index.sqlite", secrets.token_bytes(32))
    try:
        if not store.vec:
            raise RuntimeError("sqlite-vec did not load")
        store.one("SELECT vec_version()")
    finally:
        store.close()


def docx_bytes(text: str) -> bytes:
    """A small, complete Word file with one paragraph."""
    w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    parts = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" '
            'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/'
            'vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            "</Types>"
        ),
        "_rels/.rels": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/'
            '2006/relationships/officeDocument" Target="word/document.xml"/>'
            "</Relationships>"
        ),
        "word/document.xml": (
            f'<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="{w}"><w:body>'
            f"<w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>"
        ),
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in parts.items():
            zf.writestr(name, body)
    return buf.getvalue()


def pdf_bytes(text: str) -> bytes:
    """A small, complete PDF with one line of text (with a cross-reference
    table, so that a strict reader opens it)."""
    stream = f"BT /F1 24 Tf 72 720 Td ({text}) Tj ET".encode()
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream),
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (i, body)
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objs) + 1,
        xref,
    )
    return bytes(out)


def _convert(name: str, data: bytes, media_type: str) -> None:
    from anagram.local.api import (
        Blob,
        MarkItDownConverter,
    )

    conv = MarkItDownConverter()
    if not conv.available():
        raise RuntimeError("markitdown is not in the build")
    doc = conv.convert(Blob(data=data, name=name, media_type=media_type))
    if CHECK_WORD not in doc.markdown:
        raise RuntimeError(f"the text of {name} is not in the result")


def _docx(home: Path) -> None:
    from anagram.local.api import DOCX

    _convert("selftest.docx", docx_bytes(f"{CHECK_WORD} document"), DOCX)


def _pdf(home: Path) -> None:
    from anagram.local.api import PDF

    _convert("selftest.pdf", pdf_bytes(f"{CHECK_WORD} document"), PDF)


def _data(home: Path) -> None:
    from anagram.local.api import default_vocabulary
    from anagram.shell.ui.server import STATIC

    if not default_vocabulary():
        raise RuntimeError("the vocabulary is empty")
    for name in ("index.html", "js/main.js", "brand/manifest.json", "node/join.js"):
        if not (STATIC / name).is_file():
            raise RuntimeError(f"the static file {name} is not in the build")


def _app(home: Path) -> None:
    from anagram.shell.app.runtime import AppRuntime

    rt = AppRuntime(home / "app-home", embed=False)
    rt.start()
    try:
        url = f"http://127.0.0.1:{rt.port}/health"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url, timeout=10) as resp:  # loopback only
            doc = json.loads(resp.read())
        if doc != {"instance": rt.instance, "ok": True, "version": rt.version}:
            raise RuntimeError("the health route gave another answer")
    finally:
        rt.stop()


CHECKS: list[tuple[str, Callable[[Path], None]]] = [
    ("keys", _keys),
    ("vault", _vault),
    ("index", _index),
    ("docx", _docx),
    ("pdf", _pdf),
    ("data", _data),
    ("app", _app),
]


def run(out: Callable[[str], object] = print) -> int:
    """Run each check in a new temp data directory. Return the exit code."""
    os.environ["ANAGRAM_KEYSTORE"] = "file"  # never the keychain of this computer
    failed = 0
    with tempfile.TemporaryDirectory(prefix="anagram-selftest-") as tmp:
        home = Path(tmp)
        os.chmod(home, 0o700)
        for name, check in CHECKS:
            t0 = time.monotonic()
            try:
                check(home)
            except Exception as exc:  # each fault is one line
                failed += 1
                out(f"FAIL {name}: {type(exc).__name__}: {exc}")
                continue
            out(f"ok   {name} ({time.monotonic() - t0:.1f} s)")
    out("selftest passed" if not failed else f"selftest failed: {failed} of {len(CHECKS)}")
    return 0 if not failed else 1
