#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from tg_swebench_cli import load_predictions

SCHEMA_VERSION = "2.0"


def load_instance_results(path: Optional[Path]) -> Dict[str, Dict[str, Any]]:
    if path is None or not path.exists():
        return {}
    rows: Dict[str, Dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if isinstance(obj, dict) and obj.get("instance_id"):
            rows[str(obj["instance_id"])] = obj
    return rows


def load_security_report(reports_dir: Optional[Path], instance_id: str) -> Dict[str, Any]:
    if reports_dir is None:
        return {"completed": False, "findings": [], "error": "security report not supplied"}
    path = reports_dir / f"{instance_id}.json"
    if not path.exists():
        return {"completed": False, "findings": [], "error": "security report missing"}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"completed": False, "findings": [], "error": f"invalid security report: {exc}"}
    return {
        "completed": not bool(data.get("scan_failed", False)),
        "scope": data.get("scan_scope"),
        "findings": data.get("new_violations") or data.get("findings") or [],
        "error": data.get("scan_error"),
    }


def decision_for_external_eval(resolved: Optional[bool], security: Dict[str, Any]) -> Dict[str, Any]:
    if resolved is False:
        return {"state": "VETO", "reason_codes": ["EXTERNAL_BENCHMARK_UNRESOLVED"]}
    if resolved is not True:
        return {"state": "ABSTAIN", "reason_codes": ["EXTERNAL_BENCHMARK_RESULT_MISSING"]}
    if not security.get("completed", False):
        return {"state": "ABSTAIN", "reason_codes": ["SECURITY_EVIDENCE_INCOMPLETE"]}
    if security.get("findings"):
        return {"state": "VETO", "reason_codes": ["SECURITY_REGRESSION_DETECTED"]}
    return {"state": "PASS", "reason_codes": ["EXTERNAL_BENCHMARK_RESOLVED", "SECURITY_EVIDENCE_COMPLETE"]}


def build_eval_records(
    predictions_path: Path,
    output_path: Path,
    instance_results_path: Optional[Path] = None,
    security_reports_dir: Optional[Path] = None,
    model_id: str = "unknown",
) -> tuple[int, int]:
    predictions = load_predictions(predictions_path)
    external = load_instance_results(instance_results_path)
    total = passed = 0
    with output_path.open("w", encoding="utf-8") as out:
        for rec in predictions:
            instance_id = str(rec.get("instance_id") or rec.get("task") or "unknown")
            ext = external.get(instance_id, {})
            resolved_raw = ext.get("resolved")
            resolved: Optional[bool] = resolved_raw if isinstance(resolved_raw, bool) else None
            security = load_security_report(security_reports_dir, instance_id)
            decision = decision_for_external_eval(resolved, security)
            row = {
                "schema_version": SCHEMA_VERSION,
                "model": model_id,
                "instance_id": instance_id,
                "source": "external-swe-evaluation",
                "swebench": {
                    "resolved": resolved,
                    "resolved_status": ext.get("resolved_status"),
                },
                "security": security,
                "decision": decision,
                "patch": rec.get("model_patch", ""),
            }
            out.write(json.dumps(row, sort_keys=True) + "\n")
            total += 1
            if decision["state"] == "PASS": passed += 1
    return total, passed


def main() -> None:
    parser = argparse.ArgumentParser(description="Join external SWE-bench outcomes with separate security evidence.")
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--instance-results", default=None)
    parser.add_argument("--security-reports-dir", default=None)
    parser.add_argument("--model-id", default="unknown")
    args = parser.parse_args()
    total, passed = build_eval_records(
        Path(args.predictions),
        Path(args.output),
        Path(args.instance_results) if args.instance_results else None,
        Path(args.security_reports_dir) if args.security_reports_dir else None,
        args.model_id,
    )
    print(f"Wrote {total} records; PASS={passed}")


if __name__ == "__main__":
    main()
