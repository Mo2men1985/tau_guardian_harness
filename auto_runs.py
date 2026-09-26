"""Convenience commands for evidence-gated local and external evaluations."""
from __future__ import annotations

import argparse
import glob
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

from harness import experiment


def _safe_model_name(model: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", model.strip())


def _next_run_index(pattern: str) -> int:
    indexes = []
    for path in glob.glob(pattern):
        match = re.search(r"_run(\d+)", os.path.basename(path))
        if match: indexes.append(int(match.group(1)))
    return max(indexes, default=0) + 1


def _run(cmd: List[str]) -> Tuple[int, str]:
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
    return proc.returncode, proc.stdout


def cmd_internal(args: argparse.Namespace) -> None:
    if args.provider: os.environ["LLM_PROVIDER"] = args.provider
    model_safe = _safe_model_name(args.model)
    outdir = Path(args.results_dir); outdir.mkdir(parents=True, exist_ok=True)
    idx = _next_run_index(str(outdir / f"results_{model_safe}_run*.jsonl"))
    out = outdir / f"results_{model_safe}_run{idx:02d}.jsonl"
    experiment(args.model, max_attempts=args.max_attempts, results_path=str(out))
    print(out)


def cmd_external_swe(args: argparse.Namespace) -> None:
    output = Path(args.output)
    cmd = [
        sys.executable,
        "analyze_mini_swe_results.py",
        "--predictions", args.predictions,
        "--instance-results", args.instance_results,
        "--output", str(output),
        "--model-id", args.model_id,
    ]
    if args.security_reports_dir:
        cmd.extend(["--security-reports-dir", args.security_reports_dir])
    rc, out = _run(cmd)
    print(out)
    if rc != 0: raise SystemExit(rc)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evidence-gated evaluation helpers")
    subs = parser.add_subparsers(dest="command", required=True)

    internal = subs.add_parser("internal", help="Run the internal regression task suite")
    internal.add_argument("--model", required=True)
    internal.add_argument("--provider", choices=["openai", "gemini", "ollama", "fake"], default=None)
    internal.add_argument("--max-attempts", type=int, default=int(os.getenv("GUARDIAN_MAX_ATTEMPTS", "3")))
    internal.add_argument("--results-dir", default=".")
    internal.set_defaults(func=cmd_internal)

    swe = subs.add_parser("swe-join", help="Join official SWE-bench results with security evidence")
    swe.add_argument("--predictions", required=True)
    swe.add_argument("--instance-results", required=True)
    swe.add_argument("--security-reports-dir", default=None)
    swe.add_argument("--model-id", required=True)
    swe.add_argument("--output", required=True)
    swe.set_defaults(func=cmd_external_swe)
    return parser


def main() -> None:
    args = build_parser().parse_args(); args.func(args)


if __name__ == "__main__": main()
