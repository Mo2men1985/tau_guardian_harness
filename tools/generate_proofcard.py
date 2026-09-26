#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_record(path: Path, instance_id: Optional[str]) -> Dict[str, Any]:
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip(): continue
        rec = json.loads(line)
        key = rec.get("instance_id") or rec.get("task")
        if instance_id is None or key == instance_id: return rec
    raise ValueError("matching evidence record not found")


def generate_proofcard(evidence_path: Path, out_dir: Path, instance_id: Optional[str] = None) -> Path:
    rec = _load_record(evidence_path, instance_id)
    decision = rec.get("decision") or rec.get("final_decision") or {}
    candidate = rec.get("candidate_identity") or {}
    tests = rec.get("tests") or {}
    tools = rec.get("tools") or {}

    payload = {
        "schema_version": "2.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "instance_id": rec.get("instance_id") or rec.get("task"),
        "model": rec.get("model"),
        "repo_commit_sha": candidate.get("repo_commit_sha"),
        "candidate_sha256": candidate.get("candidate_sha256"),
        "policy_version": candidate.get("policy_version"),
        "pytest_report_sha256": tests.get("report_sha256"),
        "tool_artifact_sha256": {name: ev.get("artifact_sha256") for name, ev in tools.items() if isinstance(ev, dict)},
        "decision": decision,
        "source_evidence_sha256": _sha256(evidence_path.read_bytes()),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload["payload_sha256"] = _sha256(canonical)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "ProofCard.json"
    path.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate an evidence-bound ProofCard.")
    parser.add_argument("--evidence-path", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--instance-id", default=None)
    args = parser.parse_args()
    path = generate_proofcard(Path(args.evidence_path), Path(args.out_dir), args.instance_id)
    print(path)


if __name__ == "__main__": main()
