#!/usr/bin/env bash
# Local end-to-end test of the Docker deployment. See deploy/local_e2e.py.
#   deploy/local-e2e.sh [--keep] [--no-build]    (from the repository root)
set -euo pipefail
cd "$(dirname "$0")/.."
command -v docker >/dev/null || { echo "docker is not installed" >&2; exit 2; }
uv sync --quiet --extra node
exec uv run --quiet python deploy/local_e2e.py "$@"
