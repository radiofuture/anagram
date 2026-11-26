#!/bin/sh
# Build Anagram.app on macOS (unsigned).
#
#   packaging/macos/build.sh [OUT_DIR]
#
# The result is OUT_DIR/Anagram.app (default: dist). The script then runs the
# self test of the build. An unsigned build is for tests only: Gatekeeper
# stops it, and the keychain asks again after each new build.
#
# With ANAGRAM_NO_BUNDLE=1 the build stops at OUT_DIR/Anagram/ (no .app), and
# the self test runs from that folder. Use it on a computer where the
# anagram:// scheme must not be registered.
set -eu

cd "$(dirname "$0")/../.."
OUT="${1:-dist}"
VERSION="$(uv run --offline python -c 'import anagram; print(anagram.__version__)')"
export ANAGRAM_VERSION="$VERSION"

uv run --group packaging pyinstaller --noconfirm --clean \
  --distpath "$OUT" --workpath "$OUT/.work" packaging/anagram.spec

if [ -n "${ANAGRAM_NO_BUNDLE:-}" ]; then
  PROGRAM="$OUT/Anagram/Anagram"
else
  PROGRAM="$OUT/Anagram.app/Contents/MacOS/Anagram"
fi

# The self test must not find the Python of this computer.
env -i HOME="$HOME" PATH=/usr/bin:/bin "$PROGRAM" app selftest
du -sh "$OUT"/Anagram*
