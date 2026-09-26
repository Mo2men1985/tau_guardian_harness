#!/usr/bin/env python3
"""Run a user-supplied official SWE-bench evaluator command and verify its output artifact exists."""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="External SWE-bench evaluator wrapper")
    parser.add_argument("--predictions-path", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--outdir", required=True)
    parser.add_argument("--timeout", type=int, default=3600)
    args = parser.parse_args()

    cli = os.getenv("GUARDIAN_SWE_EVAL_CLI")
    if not cli:
        raise SystemExit("GUARDIAN_SWE_EVAL_CLI must point to the official evaluator command template")
    outdir = Path(args.outdir).resolve(); outdir.mkdir(parents=True, exist_ok=True)
    command = cli.format(predictions=str(Path(args.predictions_path).resolve()), run_id=args.run_id, outdir=str(outdir))
    proc = subprocess.run(shlex.split(command), check=False, timeout=args.timeout)
    if proc.returncode != 0: raise SystemExit(proc.returncode)
    expected = outdir / "instance_results.jsonl"
    if not expected.exists(): raise SystemExit(f"expected external result artifact missing: {expected}")
    print(expected)


if __name__ == "__main__": main()
