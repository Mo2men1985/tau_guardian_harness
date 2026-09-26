import json
from pathlib import Path

from analyze_mini_swe_results import build_eval_records


def test_external_resolved_plus_complete_security_passes(tmp_path: Path):
    predictions = tmp_path / "preds.json"
    predictions.write_text(json.dumps([{"instance_id": "x", "model_patch": "diff --git a/a b/a\n"}]), encoding="utf-8")
    results = tmp_path / "instance_results.jsonl"
    results.write_text(json.dumps({"instance_id": "x", "resolved": True, "resolved_status": "RESOLVED"}) + "\n", encoding="utf-8")
    reports = tmp_path / "reports"; reports.mkdir()
    (reports / "x.json").write_text(json.dumps({"scan_failed": False, "findings": []}), encoding="utf-8")
    output = tmp_path / "out.jsonl"
    total, passed = build_eval_records(predictions, output, results, reports, "model")
    assert (total, passed) == (1, 1)
    row = json.loads(output.read_text(encoding="utf-8"))
    assert row["decision"]["state"] == "PASS"
    assert row["swebench"]["resolved"] is True


def test_missing_security_evidence_abstains(tmp_path: Path):
    predictions = tmp_path / "preds.json"
    predictions.write_text(json.dumps([{"instance_id": "x", "model_patch": ""}]), encoding="utf-8")
    results = tmp_path / "instance_results.jsonl"
    results.write_text(json.dumps({"instance_id": "x", "resolved": True}) + "\n", encoding="utf-8")
    output = tmp_path / "out.jsonl"
    _, passed = build_eval_records(predictions, output, results, None, "model")
    row = json.loads(output.read_text(encoding="utf-8"))
    assert passed == 0
    assert row["decision"]["state"] == "ABSTAIN"
