"""Build the bundled OpenAlex Topics snapshot (a maintainer tool).

This is the only part of `anagram.local.index` that calls OpenAlex. It reads the
public topic list (CC0) and sends no private data. Tests never run it.

    uv run python -m anagram.local.understanding.vocab_build src/anagram/local/understanding/vocab --date 2026-10-15

The output is `openalex-topics-<date>.json.gz`, with the compact form:

    {"schema": "anagram.vocab.openalex_topics.v1", "date": ..., "source": ...,
     "licence": "CC0-1.0", "topics": [[id, name, [keywords], field], ...]}
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
import time
import urllib.request
from pathlib import Path

API = "https://api.openalex.org/topics"
FIELDS = "id,display_name,keywords,subfield,field,domain"
SNAPSHOT_SCHEMA = "anagram.vocab.openalex_topics.v1"


def fetch_all(per_page: int = 200, pause: float = 0.3) -> list[dict]:
    out: list[dict] = []
    page = 1
    while True:
        url = f"{API}?per_page={per_page}&page={page}&select={FIELDS}"
        data = None
        for _ in range(4):
            try:
                with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 - fixed https URL
                    data = json.loads(resp.read())
                break
            except OSError as exc:
                print(f"retry page {page}: {exc}", file=sys.stderr)
                time.sleep(3)
        if data is None:
            raise SystemExit(f"OpenAlex page {page} failed")
        if not data["results"]:
            return out
        out.extend(data["results"])
        page += 1
        time.sleep(pause)


def short_id(url: str) -> str:
    """https://openalex.org/T10044 -> openalex:t10044 (lowercase prefix:id format)."""
    return "openalex:" + url.rsplit("/", 1)[-1].lower()


def compact(raw: list[dict]) -> list[list]:
    rows = {}
    for t in raw:
        kws = sorted({k["display_name"] for k in t.get("keywords") or [] if k.get("display_name")})
        field = (t.get("field") or {}).get("display_name") or ""
        rows[short_id(t["id"])] = [short_id(t["id"]), t["display_name"], kws, field]
    return [rows[k] for k in sorted(rows)]


def write_snapshot(out_dir: Path, date: str, topics: list[list]) -> Path:
    doc = {
        "date": date,
        "licence": "CC0-1.0",
        "schema": SNAPSHOT_SCHEMA,
        "source": API,
        "topics": topics,
    }
    path = out_dir / f"openalex-topics-{date}.json.gz"
    raw = json.dumps(doc, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode()
    # mtime=0 makes the gzip bytes depend only on the content.
    path.write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))
    return path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m anagram.local.understanding.vocab_build")
    ap.add_argument("out_dir", type=Path)
    ap.add_argument("--date", required=True, help="snapshot date, YYYY-MM-DD")
    ap.add_argument("--raw", type=Path, help="read a saved raw JSON list in place of the API")
    args = ap.parse_args(argv)
    raw = json.loads(args.raw.read_text()) if args.raw else fetch_all()
    topics = compact(raw)
    path = write_snapshot(args.out_dir, args.date, topics)
    print(f"{len(topics)} topics -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
