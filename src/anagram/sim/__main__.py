"""python -m anagram.sim OUT_DIR [--seed N] [--large-mb M]"""

from __future__ import annotations

import argparse
import sys

from anagram.sim.generate import DEFAULT_LARGE_BYTES, generate_community


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m anagram.sim", description="Write the Anagram synthetic community."
    )
    parser.add_argument("out_dir", help="output folder (must not exist or be empty)")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument(
        "--large-mb",
        type=float,
        default=DEFAULT_LARGE_BYTES / (1024 * 1024),
        help="size of each lab's large file in MiB (default 20)",
    )
    args = parser.parse_args(argv)
    try:
        result = generate_community(
            args.out_dir, seed=args.seed, large_bytes=int(args.large_mb * 1024 * 1024)
        )
    except (FileExistsError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    truth = result.ground_truth
    print(
        f"Wrote {len(truth['labs'])} labs, {len(truth['people'])} people, "
        f"{len(truth['files'])} files, {len(result.canaries)} canaries to {result.out_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
