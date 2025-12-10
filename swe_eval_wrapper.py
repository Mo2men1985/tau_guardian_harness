#!/usr/bin/env python3
"""
swe_eval_wrapper.py

Thin CLI wrapper for SWE / mini-SWE evaluation in τGuardian.

Goal:
- Provide a stable command-line interface used by:
    - run_ablation_experiment.py
    - other orchestrators / CI jobs

Contract:
    python swe_eval_wrapper.py \n        --predictions-path /path/to/preds.jsonl \n        --run-id my_run_001 \n        --outdir evaluation_results/ \n        [--timeout 3600]

Expected output:
- A directory:
    <outdir>/<run_id>/instance_results.jsonl

`instance_results.jsonl` is a JSONL file where each line is a single
instance result object. This wrapper is intentionally conservative and
has two modes:

1) Real evaluator:
   - Set TG_SWE_EVAL_CLI to a shell command template, e.g.:
        TG_SWE_EVAL_CLI="python -m swebench.evaluate --predictions {predictions} --run-id {run_id} --outdir {outdir}"
   - The wrapper formats that command and executes it with a timeout.
   - It expects the evaluator to write instance_results.jsonl to the
     expected path.

2) Fallback / stub (development):
   - If TG_SWE_EVAL_CLI is not set, this wrapper synthesizes a minimal
     instance_results.jsonl, marking each prediction as:
        "status": "unknown", "tests_passed": 0, "tests_failed": 0, "total_tests": 0
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any, Dict, List


def _run_shell_command(cmd: str, cwd: Path | None, timeout: int) -> int:
    """
    Execute a shell command safely with a timeout.

    The command string is split via shlex.split to avoid shell injection
    vulnerabilities. This assumes TG_SWE_EVAL_CLI is a plain command template,
    not an arbitrary shell script.
    """
    print(f"[swe_eval_wrapper] RUN: {cmd}")
    args = shlex.split(cmd)
    proc = subprocess.Popen(args, cwd=str(cwd or Path(".")))
    try:
        rc = proc.wait(timeout=timeout)
        return rc
    except subprocess.TimeoutExpired:
        proc.kill()
        raise RuntimeError(f"External SWE evaluator timed out after {timeout} seconds")


def _load_predictions(predictions_path: Path) -> List[Dict[str, Any]]:
    """
    Load predictions from JSONL or JSON.

    Supports:
    - JSONL: one object per line
    - JSON: a single object or a list of objects
    """
    if not predictions_path.exists():
        raise FileNotFoundError(f"predictions-path not found: {predictions_path}")

    text = predictions_path.read_text(encoding="utf-8").strip()
    if not text:
        return []

    # Heuristic: if it contains newline and '{', treat as JSONL
    if "\n" in text:
        preds: List[Dict[str, Any]] = []
        for ln in text.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            preds.append(json.loads(ln))
        return preds

    # Otherwise parse as JSON
    obj = json.loads(text)
    if isinstance(obj, list):
        return obj
    return [obj]


def _write_stub_results(
    predictions: List[Dict[str, Any]],
    instance_results_path: Path,
) -> None:
    """
    Fallback stub: write a minimal instance_results.jsonl.

    Each line contains:
        {
          "instance_id": <task or id or synthetic>,
          "status": "unknown",
          "tests_passed": 0,
          "tests_failed": 0,
          "total_tests": 0
        }
    """
    instance_results_path.parent.mkdir(parents=True, exist_ok=True)
    with instance_results_path.open("w", encoding="utf-8") as fh:
        for idx, pred in enumerate(predictions, start=1):
            instance_id = (
                pred.get("instance_id")
                or pred.get("task")
                or pred.get("id")
                or f"unknown_instance_{idx}"
            )
            rec = {
                "instance_id": instance_id,
                "status": "unknown",
                "tests_passed": 0,
                "tests_failed": 0,
                "total_tests": 0,
            }
            fh.write(json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n")

    print(
        f"[swe_eval_wrapper] Wrote stub instance_results.jsonl "
        f"with {len(predictions)} records to {instance_results_path}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Wrapper around SWE / mini-SWE evaluation for τGuardian."
    )
    parser.add_argument(
        "--predictions-path",
        required=True,
        help="Path to model predictions (JSON or JSONL).",
    )
    parser.add_argument(
        "--run-id",
        required=True,
        help="Run identifier (used in output directory structure).",
    )
    parser.add_argument(
        "--outdir",
        required=True,
        help="Root output directory for evaluation results.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=3600,
        help="Timeout in seconds for external evaluator (default: 3600).",
    )
    args = parser.parse_args()

    predictions_path = Path(args.predictions_path).resolve()
    outdir = Path(args.outdir).resolve()
    run_id = args.run_id
    timeout = args.timeout

    eval_run_dir = outdir / run_id
    instance_results_path = eval_run_dir / "instance_results.jsonl"

    # If instance_results already exist, do nothing (idempotent for re-runs)
    if instance_results_path.exists():
        print(f"[swe_eval_wrapper] Reusing existing {instance_results_path}")
        return

    # Mode 1: external CLI provided via environment
    cli_template = os.environ.get("TG_SWE_EVAL_CLI")
    if cli_template:
        cmd = cli_template.format(
            predictions=str(predictions_path),
            run_id=run_id,
            outdir=str(outdir),
        )
        rc = _run_shell_command(cmd, cwd=None, timeout=timeout)
        if rc != 0:
            raise RuntimeError(f"External SWE eval CLI failed (rc={rc})")

        if not instance_results_path.exists():
            raise FileNotFoundError(
                f"Expected instance_results.jsonl at {instance_results_path} "
                f"after running external CLI"
            )

        print(f"[swe_eval_wrapper] Found instance_results at {instance_results_path}")
        return

    # Mode 2: fallback stub evaluator
    print(
        "[swe_eval_wrapper] TG_SWE_EVAL_CLI not set; "
        "using stub evaluator (no tests run)."
    )
    predictions = _load_predictions(predictions_path)
    _write_stub_results(predictions, instance_results_path)


if __name__ == "__main__":
    main()
