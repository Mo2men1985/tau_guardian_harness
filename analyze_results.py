#!/usr/bin/env python3
from __future__ import annotations

import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List


def load_results(path: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip(): rows.append(json.loads(line))
    return rows


def _state(rec: Dict[str, Any]) -> str:
    decision = rec.get("decision") or rec.get("final_decision") or {}
    return str(decision.get("state", "UNKNOWN")) if isinstance(decision, dict) else str(decision)


def summarize(path: str) -> Dict[str, Any]:
    rows = load_results(path)
    baseline = [r for r in rows if r.get("type") == "baseline"]
    repaired = [r for r in rows if r.get("type") == "repair_loop"]
    initial_pass = sum(1 for r in baseline if _state(r) == "PASS")
    final_pass = sum(1 for r in repaired if _state(r) == "PASS")
    initial_failed = [r for r in baseline if _state(r) != "PASS"]
    repaired_map = {r.get("task"): r for r in repaired}
    recovered = sum(1 for r in initial_failed if _state(repaired_map.get(r.get("task"), {})) == "PASS")
    attempts = [int(r.get("attempt_count", 0)) for r in repaired if r.get("attempt_count") is not None]
    return {
        "records": len(rows),
        "tasks": len({r.get("task") for r in rows}),
        "initial_pass": initial_pass,
        "final_pass": final_pass,
        "repair_success_given_initial_nonpass": {
            "recovered": recovered,
            "eligible": len(initial_failed),
        },
        "median_attempts": statistics.median(attempts) if attempts else None,
        "abstain": sum(1 for r in repaired if _state(r) == "ABSTAIN"),
        "veto": sum(1 for r in repaired if _state(r) == "VETO"),
    }


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Summarize direct evidence outcomes")
    parser.add_argument("results", nargs="?", default="results-v2.jsonl")
    args = parser.parse_args()
    print(json.dumps(summarize(args.results), indent=2))


if __name__ == "__main__": main()
