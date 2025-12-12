import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from analyze_mini_swe_results import build_eval_records


def _write_exit_status(msa_dir: Path, instance_id: str, status: str) -> None:
    content = {"instances_by_exit_status": {status: [instance_id]}}
    (msa_dir / "exit_statuses_0.yaml").write_text(json.dumps(content), encoding="utf-8")


def test_instance_results_drive_eval(tmp_path: Path) -> None:
    msa_dir = tmp_path / "msa"
    msa_dir.mkdir()

    preds = {"demo__proj-1": {"model_patch": "diff --git a/file.py b/file.py"}}
    (msa_dir / "preds.json").write_text(json.dumps(preds), encoding="utf-8")
    _write_exit_status(msa_dir, "demo__proj-1", "Submitted")

    instance_results = tmp_path / "instance_results.jsonl"
    instance_results.write_text(
        json.dumps({"instance_id": "demo__proj-1", "resolved": True, "resolved_status": "resolved"})
        + "\n",
        encoding="utf-8",
    )

    output_path = tmp_path / "eval.jsonl"
    total, success = build_eval_records(
        msa_dir=msa_dir,
        model_id="demo-model",
        output_path=output_path,
        instance_results_path=instance_results,
    )

    assert total == 1
    assert success == 1

    rows = [json.loads(ln) for ln in output_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert rows[0]["eval_status"] == "resolved"
    assert rows[0]["test_pass_rate"] > 0
    assert rows[0]["cri"] == 1.0
    assert rows[0]["final_decision"] == "OK"


def test_load_preds_array_and_jsonl(tmp_path: Path) -> None:
    """Ensure preds.json arrays/JSONL normalize into mappings for eval."""

    msa_dir = tmp_path / "msa_array"
    msa_dir.mkdir()

    preds = [
        {"task": "demo__proj-2", "model_patch": "diff --git a/a b/a"},
        {"id": "demo__proj-3", "model_patch": "diff --git a/b b/b"},
    ]
    (msa_dir / "preds.json").write_text(json.dumps(preds), encoding="utf-8")
    _write_exit_status(msa_dir, "demo__proj-2", "Submitted")
    _write_exit_status(msa_dir, "demo__proj-3", "Submitted")

    instance_results = tmp_path / "instance_results_array.jsonl"
    instance_results.write_text(
        "\n".join(
            [
                json.dumps({"instance_id": "demo__proj-2", "resolved": True}),
                json.dumps({"instance_id": "demo__proj-3", "resolved": False}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    output_path = tmp_path / "eval_array.jsonl"
    total, success = build_eval_records(
        msa_dir=msa_dir,
        model_id="demo-model",
        output_path=output_path,
        instance_results_path=instance_results,
    )

    assert total == 2
    assert success == 1

    rows = [json.loads(ln) for ln in output_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    resolved_ids = {row["task"] for row in rows if row["eval_status"] == "resolved"}
    unresolved_ids = {row["task"] for row in rows if row["eval_status"] == "unresolved"}
    assert resolved_ids == {"demo__proj-2"}
    assert unresolved_ids == {"demo__proj-3"}
