from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _load_preds(path: Path) -> Dict[str, Dict[str, Any]]:
    if not path.exists(): return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    rows: Dict[str, Dict[str, Any]] = {}
    if isinstance(data, list):
        for rec in data:
            if isinstance(rec, dict) and rec.get("instance_id"):
                rows[str(rec["instance_id"])] = rec
    elif isinstance(data, dict):
        for inst, rec in data.items():
            row = dict(rec) if isinstance(rec, dict) else {"model_patch": rec}
            row.setdefault("instance_id", inst)
            rows[str(inst)] = row
    return rows


def _load_eval(path: Path) -> Dict[str, Dict[str, Any]]:
    if not path.exists(): return {}
    out: Dict[str, Dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip(): continue
        obj = json.loads(line)
        key = obj.get("instance_id") or obj.get("task")
        if key: out[str(key)] = obj
    return out


def evaluate_candidate(instance_id: str, cand_dir: Path) -> Dict[str, Any]:
    preds = _load_preds(cand_dir / "preds.json")
    evals = _load_eval(cand_dir / "evaluation.jsonl")
    rec = preds.get(instance_id, {"model_patch": ""})
    ev = evals.get(instance_id, {})
    decision_obj = ev.get("decision") or ev.get("final_decision") or {}
    if isinstance(decision_obj, dict):
        state = str(decision_obj.get("state", "ABSTAIN"))
        reasons = list(decision_obj.get("reason_codes") or [])
    else:
        state = str(decision_obj or "ABSTAIN")
        reasons = []
    patch = str(rec.get("model_patch", ""))
    return {
        "candidate_dir": str(cand_dir),
        "instance_id": instance_id,
        "patch": patch,
        "decision": state,
        "reason_codes": reasons,
        "changed_files": sum(1 for line in patch.splitlines() if line.startswith("diff --git ")),
        "patch_size": len(patch),
        "evidence_present": bool(ev),
    }


def _priority(info: Dict[str, Any]) -> Tuple[int, int, int, str]:
    state = info.get("decision")
    tier = 0 if state == "PASS" else 1 if state == "ABSTAIN" else 2
    if not info.get("evidence_present"):
        tier = max(tier, 1)
    return (tier, int(info.get("changed_files", 0)), int(info.get("patch_size", 0)), str(info.get("candidate_dir", "")))


def select_best(candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not candidates:
        raise ValueError("no candidates")
    return sorted(candidates, key=_priority)[0]


def main() -> None:
    parser = argparse.ArgumentParser(description="Select among candidates using explicit evidence state only.")
    parser.add_argument("--cand-dirs", required=True)
    parser.add_argument("--outdir", required=True)
    args = parser.parse_args()
    cand_dirs = [Path(x.strip()) for x in args.cand_dirs.split(",") if x.strip()]
    all_instances: set[str] = set()
    for cand in cand_dirs: all_instances.update(_load_preds(cand / "preds.json").keys())
    merged: List[Dict[str, Any]] = []
    report: List[str] = []
    for instance_id in sorted(all_instances):
        evaluated = [evaluate_candidate(instance_id, cand) for cand in cand_dirs]
        chosen = select_best(evaluated)
        merged.append({"instance_id": instance_id, "model_patch": chosen["patch"]})
        report.append(json.dumps(chosen, sort_keys=True))
    outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "preds.json").write_text(json.dumps(merged, indent=2), encoding="utf-8")
    (outdir / "selection_report.jsonl").write_text("\n".join(report) + ("\n" if report else ""), encoding="utf-8")


if __name__ == "__main__": main()
