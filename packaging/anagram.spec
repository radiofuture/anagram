# PyInstaller spec of the Anagram app. One-folder build.
#
#   uv run --group packaging pyinstaller --noconfirm packaging/anagram.spec
#
# macOS: the result is dist/Anagram.app (unsigned; packaging/macos/build.sh).
# Set ANAGRAM_NO_BUNDLE=1 to stop at the folder dist/Anagram/ (no .app): a
# build computer that must not register the anagram:// scheme (Launch
# Services can register an .app that it sees) checks the folder only.
#
# The embedding model is not in the build: the app downloads it at first use.

import os
import plistlib
import sys
from pathlib import Path

from PyInstaller.utils.hooks import (
    collect_data_files,
    collect_dynamic_libs,
    collect_submodules,
    copy_metadata,
)

HERE = Path(SPECPATH)  # noqa: F821 - set by PyInstaller
PRODUCT = HERE.parent
SRC = str(PRODUCT / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

datas = []
binaries = []
hiddenimports = []

# Our package: the static UI, the brand copy, the node page scripts, the
# vocabulary, the TSA roots. Exclude test vectors and simulation fixtures.
datas += collect_data_files(
    "anagram",
    excludes=["**/__pycache__/*", "sim/data/kinds_*.json", "vectors/**"],
)
hiddenimports += [
    m for m in collect_submodules("anagram") if m != "anagram.vectors" and not m.startswith("anagram.vectors.")
]

# Native libraries that are loaded by path (not found by the import graph).
binaries += collect_dynamic_libs("sqlite_vec")
binaries += collect_dynamic_libs("onnxruntime")

# Data files of the converters and the embedder.
for package in ("markitdown", "magika", "pdfminer", "fastembed", "certifi"):
    datas += collect_data_files(package)
for package in ("markitdown", "magika", "fastembed", "onnxruntime", "keyring", "uvicorn"):
    datas += copy_metadata(package)

# uvicorn picks these by name at run time.
hiddenimports += [
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan.on",
    "keyring.backends.macOS",
    "keyring.backends.SecretService",
    "keyring.backends.Windows",
]

a = Analysis(  # noqa: F821
    [str(HERE / "entry.py")],
    pathex=[SRC],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "pytest", "playwright", "anagram.vectors"],
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821
exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Anagram",
    console=False,
    # H29: argv_emulation forwards macOS OpenURL Apple Events into sys.argv;
    # keep disabled outside signed bundles where not needed, or migrate to a
    # native Apple Event handler when macOS signing/notarization is added.
    argv_emulation=sys.platform == "darwin",
    codesign_identity=os.environ.get("ANAGRAM_CODESIGN_IDENTITY") or None,
)
coll = COLLECT(exe, a.binaries, a.datas, name="Anagram")  # noqa: F821

if sys.platform == "darwin" and os.environ.get("ANAGRAM_NO_BUNDLE") in (None, "", "0"):
    with open(HERE / "macos" / "Info.plist", "rb") as f:
        info = plistlib.load(f)
    from anagram.core.version import VERSION  # the one source of the version

    version = os.environ.get("ANAGRAM_VERSION", VERSION)
    info["CFBundleShortVersionString"] = version
    info["CFBundleVersion"] = version
    app = BUNDLE(  # noqa: F821
        coll,
        name="Anagram.app",
        bundle_identifier=info["CFBundleIdentifier"],
        info_plist=info,
    )
