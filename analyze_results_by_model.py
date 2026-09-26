#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List


def load_results(path: str) -> List[Dict[str, Any]]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def decision_state(rec: Dict[str, Any]) -> str:
    obj = rec.get("decision") or rec.get("final_decision") or {}
    return str(obj.get("state", "UNKNOWN")) if isinstance(obj, dict) else str(obj)


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect evidence outcomes for one model")
    parser.add_argument("--results", default="results-v2.jsonl")
    parser.add_argument("--model", required=True)
    args = parser.parse_args()
    rows = [r for r in load_results(args.results) if r.get("model") == args.model]
    by_task: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows: by_task[str(row.get("task"))].append(row)
    print(f"Model: {args.model}; tasks={len(by_task)}")
    counts = defaultdict(int)
    for task, task_rows in sorted(by_task.items()):
        final = next((r for r in task_rows if r.get("type") == "repair_loop"), task_rows[-1])
        state = decision_state(final); counts[state] += 1
        decision = final.get("final_decision") or final.get("decision") or {}
        reasons = decision.get("reason_codes", []) if isinstance(decision, dict) else []
        print(f"{task}: {state} reasons={reasons} attempts={final.get('attempt_count', 1)}")
    print("Aggregate:", dict(counts))


if __name__ == "__main__": main()
