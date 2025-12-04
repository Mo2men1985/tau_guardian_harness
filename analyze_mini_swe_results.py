"""Convert mini-SWE-agent outputs into τGuardian JSONL with optional evaluation.

This script ingests the ``preds.json`` and ``exit_statuses_*.yaml`` artifacts
produced by the mini-SWE-agent runner and emits rows that mirror the fields used
by ``harness.py`` / ``swe_runner.py``.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover - optional dependency
    yaml = None  # type: ignore[assignment]

# Optional SWE-bench evaluation
try:  # pragma: no cover - heavy optional dependency
    from swebench.harness.run_evaluation import run_evaluation

    SWEBENCH_AVAILABLE = True
except Exception:  # pragma: no cover
    run_evaluation = None  # type: ignore[assignment]
    SWEBENCH_AVAILABLE = False


# ---------------------------------------------------------------------------
# Status loading
# ---------------------------------------------------------------------------


def load_statuses(msa_dir: str) -> Dict[str, str]:
    """Load and merge exit_statuses_*.yaml with defensive parsing."""

    status_map: Dict[str, str] = {}
    pattern = os.path.join(msa_dir, "exit_statuses_*.yaml")
    paths = sorted(glob.glob(pattern))

    if not paths:
        print(f"[WARN] No exit_statuses_*.yaml files found under {msa_dir}")
        return status_map

    if yaml is None:
        raise RuntimeError("PyYAML is required to parse exit statuses; pip install pyyaml")

    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as exc:
            print(f"[ERROR] Failed to read {path}: {exc}")
            continue

        if not isinstance(data, dict):
            print(f"[WARN] {path} does not contain a mapping; skipping")
            continue

        # Nested format
        if "instances_by_exit_status" in data:
            ibs = data.get("instances_by_exit_status")
            if not isinstance(ibs, dict):
                print(f"[WARN] {path} has malformed instances_by_exit_status")
                continue

            for status, instances in ibs.items():
                if not isinstance(instances, (list, tuple)):
                    print(f"[WARN] {path}: status '{status}' has non-list instances")
                    continue
                for inst_id in instances:
                    if inst_id is None:
                        continue
                    status_map[str(inst_id)] = str(status)
            continue

        # Flat format
        for inst_id, status in data.items():
            if inst_id is None or status is None:
                continue
            status_map[str(inst_id)] = str(status)

    print(f"[INFO] Loaded {len(status_map)} statuses from {len(paths)} files")
    return status_map


# ---------------------------------------------------------------------------
# SWE-bench integration
# ---------------------------------------------------------------------------


def run_swebench_eval(
    predictions: List[Dict[str, str]],
    dataset_name: str,
    split: str = "test",
    timeout: int = 300,
) -> Dict[str, Dict[str, Any]]:
    """Optionally run the SWE-bench harness for ground-truth outcomes."""

    if not SWEBENCH_AVAILABLE or run_evaluation is None:
        print("[WARN] swebench not installed; skipping ground-truth evaluation")
        return {}

    print(f"[INFO] Running SWE-bench evaluation on {len(predictions)} predictions…")
    results = run_evaluation(
        predictions=predictions,
        dataset_name=dataset_name,
        split=split,
        timeout=timeout,
    )
    return results


# ---------------------------------------------------------------------------
# Status mapping
# ---------------------------------------------------------------------------


def map_status_to_metrics(
    status: Optional[str],
    eval_result: Optional[Dict[str, Any]] = None,
) -> Tuple[int, int, int, str]:
    """Translate mini-SWE-agent status (plus optional eval) into τGuardian fields."""

    if eval_result is not None:
        resolved = bool(eval_result.get("resolved", False))
        if resolved:
            return 1, 0, 1, "OK"
        return 0, 1, 1, "ABSTAIN"

    status_norm = str(status or "").strip().lower()

    if status_norm in {"success", "ok", "pass", "passed", "resolved"}:
        return 1, 0, 1, "OK"

    if status_norm in {"runtimeerror", "timeout", "environmenterror", "error"}:
        return 0, 1, 1, "VETO"

    if status_norm in {"submitted", "pending"}:
        return 0, 0, 0, "ABSTAIN"

    if not status_norm or status_norm in {"unknown", "none"}:
        return 0, 0, 0, "ABSTAIN"

    return 0, 1, 1, "ABSTAIN"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert mini-SWE-agent results to τGuardian JSONL, optionally running SWE-bench evaluation.",
    )
    parser.add_argument("--msa-dir", default="msa_outputs", help="mini-SWE-agent output directory")
    parser.add_argument("--model-id", default="mini-swe-agent", help="Logical model identifier")
    parser.add_argument("--output", default="swe_results.jsonl", help="Output JSONL path")
    parser.add_argument(
        "--run-eval", action="store_true", help="Run SWE-bench evaluation harness if installed"
    )
    parser.add_argument(
        "--dataset", default="princeton-nlp/SWE-bench_Lite", help="SWE-bench dataset name for evaluation"
    )
    parser.add_argument("--timeout", type=int, default=300, help="Timeout per instance for evaluation (seconds)")

    args = parser.parse_args()

    preds_path = os.path.join(args.msa_dir, "preds.json")
    if not os.path.exists(preds_path):
        raise SystemExit(f"[ERROR] preds.json not found at {preds_path}")

    with open(preds_path, "r", encoding="utf-8") as f:
        preds = json.load(f)

    if not isinstance(preds, dict):
        raise SystemExit("[ERROR] preds.json must be a mapping of instance_id -> record")

    statuses = load_statuses(args.msa_dir)

    eval_results: Dict[str, Dict[str, Any]] = {}
    if args.run_eval:
        predictions = [
            {"instance_id": iid, "model_patch": rec.get("model_patch", "")}
            for iid, rec in preds.items()
        ]
        eval_results = run_swebench_eval(
            predictions,
            dataset_name=args.dataset,
            timeout=args.timeout,
        )

    total = 0
    success = 0

    with open(args.output, "w", encoding="utf-8") as out_f:
        for instance_id, rec in preds.items():
            patch = rec.get("model_patch", "")
            status = statuses.get(instance_id, "Unknown")
            eval_result = eval_results.get(instance_id)

            tests_passed, tests_failed, total_tests, decision = map_status_to_metrics(
                status, eval_result
            )

            cri = (tests_passed / total_tests) if total_tests else 0.0

            row = {
                "model": args.model_id,
                "provider": rec.get("provider", "unknown"),
                "task": instance_id,
                "type": "external_swe_agent",
                "source": "mini-swe-agent",
                "status": status,
                "eval_status": eval_result.get("resolved") if eval_result else None,
                "tests_passed": tests_passed,
                "tests_failed": tests_failed,
                "total_tests": total_tests,
                "test_pass_rate": cri if total_tests else 0.0,
                "cri": cri,
                "sad_flag": False,
                "tau": 1,
                "final_decision": decision,
                "iterations": 1,
                "patch": patch,
            }

            out_f.write(json.dumps(row) + "\n")

            total += 1
            if tests_passed > 0:
                success += 1

    if total == 0:
        print(f"[INFO] No predictions found in {preds_path}")
    else:
        rate = success / total if total else 0.0
        print(f"[INFO] Wrote {total} records to {args.output}")
        print(f"[INFO] Success: {success}/{total} ({rate:.1%})")
        if args.run_eval:
            print(f"[INFO] Ground-truth evaluation completed for {len(eval_results)} instances")


if __name__ == "__main__":
    main()
