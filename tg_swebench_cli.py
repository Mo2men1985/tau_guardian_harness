#!/usr/bin/env python3
"""Run the SWE-bench harness and emit instance-level results.

This thin wrapper normalizes mini-SWE predictions into a format the
``swebench`` harness expects, executes the harness, and converts its
report into a compact ``instance_results.jsonl`` for downstream tooling.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List


def _ensure_instance_id(record: Dict[str, Any], fallback: str) -> Dict[str, Any]:
    """Return a copy of ``record`` with a best-effort instance_id.

    mini-SWE outputs sometimes omit ``instance_id`` and use alternate keys
    such as ``task`` or ``id``. This helper standardizes the field so the
    SWE-bench harness can consume the predictions list.
    """

    out = dict(record)
    instance_id = (
        out.get("instance_id")
        or out.get("task")
        or out.get("id")
        or out.get("task_id")
        or fallback
    )
    out["instance_id"] = instance_id
    return out


def _normalize_prediction_mapping(mapping: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Handle ``{instance_id: payload}`` style predictions."""

    normalized: List[Dict[str, Any]] = []
    for instance_id, payload in mapping.items():
        if isinstance(payload, dict):
            rec = dict(payload)
        else:
            rec = {"model_patch": payload}
        rec.setdefault("instance_id", instance_id)
        normalized.append(rec)
    return normalized


def _normalize_prediction_obj(obj: Any) -> List[Dict[str, Any]]:
    """Convert various JSON/JSONL shapes into a list of dicts."""

    if obj is None:
        return []
    if isinstance(obj, list):
        result: List[Dict[str, Any]] = []
        for idx, rec in enumerate(obj, start=1):
            if not isinstance(rec, dict):
                rec = {"model_patch": rec}
            result.append(_ensure_instance_id(rec, f"instance_{idx}"))
        return result
    if isinstance(obj, dict):
        if any(k in obj for k in ("instance_id", "task", "id", "task_id")):
            return [_ensure_instance_id(dict(obj), "instance_unknown")]
        return _normalize_prediction_mapping(obj)
    return [_ensure_instance_id({"model_patch": obj}, "instance_unknown")]


def load_predictions(predictions_path: Path) -> List[Dict[str, Any]]:
    """Load predictions from JSON, JSONL, or mapping formats.

    Accepts:
    - JSON array of prediction dicts
    - JSON mapping of instance_id -> payload
    - JSON Lines file (one JSON object per line)

    Leading BOMs or stray whitespace are ignored.
    """

    if not predictions_path.exists():
        raise FileNotFoundError(f"predictions-path not found: {predictions_path}")

    raw_text = predictions_path.read_text(encoding="utf-8-sig")
    if not raw_text.strip():
        return []

    try:
        parsed = json.loads(raw_text)
        return _normalize_prediction_obj(parsed)
    except json.JSONDecodeError:
        pass

    preds: List[Dict[str, Any]] = []
    for idx, line in enumerate(raw_text.splitlines(), start=1):
        ln = line.strip()
        if not ln:
            continue
        obj = json.loads(ln)
        preds.extend(_normalize_prediction_obj(obj or {"instance_id": f"line_{idx}"}))
    return preds


def _write_normalized_predictions(predictions: Iterable[Dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(list(predictions), fh)


def _run_swebench_harness(
    predictions_path: Path,
    run_id: str,
    outdir: Path,
    dataset_name: str,
    split: str,
) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "-m",
        "swebench.harness.run_evaluation",
        "--dataset_name",
        dataset_name,
        "--split",
        split,
        "--predictions_path",
        str(predictions_path),
        "--run_id",
        run_id,
    ]
    print(f"[tg_swebench_cli] RUN: {' '.join(cmd)} (cwd={outdir})")
    proc = subprocess.run(cmd, cwd=outdir)
    if proc.returncode != 0:
        raise SystemExit(f"SWE-bench harness failed with rc={proc.returncode}")


def _find_report(outdir: Path, run_id: str) -> Path:
    pattern = f"*.{run_id}.json"
    candidates = sorted(outdir.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        raise FileNotFoundError(
            f"Unable to find SWE-bench report matching {pattern} under {outdir}"
        )
    return candidates[0]


def _extract_instance_records(report_data: Any) -> List[Dict[str, Any]]:
    if isinstance(report_data, dict):
        if "instances" in report_data and isinstance(report_data["instances"], list):
            return [dict(rec) for rec in report_data["instances"]]
        if "results" in report_data and isinstance(report_data["results"], list):
            return [dict(rec) for rec in report_data["results"]]
        if "instance_id" in report_data:
            return [dict(report_data)]
    if isinstance(report_data, list):
        return [dict(rec) if isinstance(rec, dict) else {"instance_id": str(rec)} for rec in report_data]
    return []


def _build_instance_results(report_path: Path, outdir: Path) -> Path:
    with report_path.open("r", encoding="utf-8") as fh:
        report_data = json.load(fh)

    instance_records = _extract_instance_records(report_data)
    if not instance_records:
        raise RuntimeError(f"No instance records found in report {report_path}")

    out_path = outdir / "instance_results.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as fh:
        for rec in instance_records:
            instance_id = rec.get("instance_id") or rec.get("task") or rec.get("id")
            resolved_bool = rec.get("resolved")
            resolved_status = rec.get("resolved_status") or rec.get("status")
            if resolved_status is None and isinstance(resolved_bool, bool):
                resolved_status = "resolved" if resolved_bool else "unresolved"
            fh.write(
                json.dumps(
                    {
                        "instance_id": instance_id,
                        "resolved": bool(resolved_bool) if resolved_bool is not None else None,
                        "resolved_status": resolved_status,
                    }
                )
                + "\n"
            )

    print(f"[tg_swebench_cli] Wrote {len(instance_records)} rows to {out_path}")
    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Run SWE-bench evaluation for τGuardian")
    parser.add_argument("--predictions-path", required=True, help="Path to predictions JSON/JSONL")
    parser.add_argument("--run-id", required=True, help="Run identifier passed to SWE-bench")
    parser.add_argument("--outdir", required=True, help="Directory for harness outputs")
    parser.add_argument(
        "--dataset-name",
        default="SWE-bench/SWE-bench_Lite",
        help="SWE-bench dataset name (default: SWE-bench/SWE-bench_Lite)",
    )
    parser.add_argument("--split", default="test", help="Dataset split (default: test)")
    args = parser.parse_args()

    predictions_path = Path(args.predictions_path).expanduser().resolve()
    outdir = Path(args.outdir).expanduser().resolve()

    predictions = load_predictions(predictions_path)
    normalized_preds_path = outdir / "normalized_predictions.json"
    _write_normalized_predictions(predictions, normalized_preds_path)

    _run_swebench_harness(
        predictions_path=normalized_preds_path,
        run_id=args.run_id,
        outdir=outdir,
        dataset_name=args.dataset_name,
        split=args.split,
    )

    report = _find_report(outdir, args.run_id)
    _build_instance_results(report, outdir)


if __name__ == "__main__":
    main()
