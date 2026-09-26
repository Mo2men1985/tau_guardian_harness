import json
from pathlib import Path
from tg_candidate_select import evaluate_candidate, select_best


def make_candidate(path: Path, state: str, patch: str):
    path.mkdir()
    (path / "preds.json").write_text(json.dumps([{"instance_id": "x", "model_patch": patch}]), encoding="utf-8")
    (path / "evaluation.jsonl").write_text(json.dumps({"instance_id": "x", "decision": {"state": state, "reason_codes": []}}) + "\n", encoding="utf-8")


def test_selector_prefers_pass_then_smaller_patch(tmp_path: Path):
    a = tmp_path / "a"; b = tmp_path / "b"
    make_candidate(a, "PASS", "diff --git a/f b/f\n+x\n")
    make_candidate(b, "ABSTAIN", "diff --git a/f b/f\n+y\n")
    chosen = select_best([evaluate_candidate("x", b), evaluate_candidate("x", a)])
    assert chosen["candidate_dir"] == str(a)
