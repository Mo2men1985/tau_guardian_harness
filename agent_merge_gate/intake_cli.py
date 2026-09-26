"""CLI for deterministic Git/PR intake."""

from __future__ import annotations

import argparse
from pathlib import Path

from .intake import build_git_intake


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize an exact Git candidate for Agent Merge Gate.")
    parser.add_argument("--repo-path", default=".")
    parser.add_argument("--repository", required=True, help="owner/name")
    parser.add_argument("--base", required=True, help="exact SHA or Git ref")
    parser.add_argument("--candidate", required=True, help="exact SHA or Git ref")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    intake = build_git_intake(
        repo_path=args.repo_path,
        repository=args.repository,
        base_ref=args.base,
        candidate_ref=args.candidate,
    )
    payload = intake.canonical_json() + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
