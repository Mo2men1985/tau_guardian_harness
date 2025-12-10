#!/usr/bin/env python3
"""swe_eval_wrapper.py

Thin CLI wrapper for SWE / mini-SWE evaluation in τGuardian.
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
    if not predictions_path.exists():
        raise FileNotFoundError(f"predictions-path not found: {predictions_path}")

    text = predictions_path.read_text(encoding="utf-8").strip()
    if not text:
        return []

    if "\n" in text:
        preds: List[Dict[str, Any]] = []
        for ln in text.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            preds.append(json.loads(ln))
        return preds

    obj = json.loads(text)
    if isinstance(obj, list):
        return obj
    return [obj]

def _write_stub_results(predictions: List[Dict[str, Any]], instance_results_path: Path) -> None:
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

    if instance_results_path.exists():
        print(f"[swe_eval_wrapper] Reusing existing {instance_results_path}")
        return

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

    print(
        "[swe_eval_wrapper] TG_SWE_EVAL_CLI not set; "
        "using stub evaluator (no tests run)."
    )
    predictions = _load_predictions(predictions_path)
    _write_stub_results(predictions, instance_results_path)

if __name__ == "__main__":
    main()
