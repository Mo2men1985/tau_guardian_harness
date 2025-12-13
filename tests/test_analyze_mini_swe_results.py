import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from analyze_mini_swe_results import build_eval_records, extract_security_violations_from_patch


def _write_exit_status(msa_dir: Path, instance_ids: list[str], status: str) -> None:
    content = {"instances_by_exit_status": {status: instance_ids}}
    (msa_dir / "exit_statuses_0.yaml").write_text(json.dumps(content), encoding="utf-8")


def test_instance_results_join_and_decisions(tmp_path: Path) -> None:
    msa_dir = tmp_path / "msa"
    msa_dir.mkdir()

    preds = [
        {"instance_id": "demo__proj-1", "model_patch": "diff --git a/file.py b/file.py"},
        {"instance_id": "demo__proj-2", "model_patch": "diff --git a/other.py b/other.py"},
        {"instance_id": "demo__proj-3", "model_patch": "diff --git a/third.py b/third.py"},
    ]
    (msa_dir / "preds.json").write_text(json.dumps(preds), encoding="utf-8")
    _write_exit_status(msa_dir, [rec["instance_id"] for rec in preds], "Submitted")

    instance_results = tmp_path / "instance_results.jsonl"
    instance_results.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "instance_id": "demo__proj-1",
                        "resolved": True,
                        "resolved_status": "RESOLVED",
                    }
                ),
                json.dumps(
                    {
                        "instance_id": "demo__proj-2",
                        "resolved": False,
                        "resolved_status": "UNRESOLVED",
                    }
                ),
                json.dumps(
                    {
                        "instance_id": "demo__proj-3",
                        "resolved": False,
                        "resolved_status": "PATCH_APPLY_FAILED",
                    }
                ),
            ]
        )
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

    assert total == 3
    assert success == 1

    rows = [json.loads(ln) for ln in output_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    rows_by_task = {row["task"]: row for row in rows}

    resolved_row = rows_by_task["demo__proj-1"]
    assert resolved_row["resolved"] is True
    assert resolved_row["resolved_status"] == "RESOLVED"
    assert resolved_row["eval_status"] == "resolved"
    assert resolved_row["cri"] == 1.0
    assert resolved_row["final_decision"] == "OK"

    unresolved_row = rows_by_task["demo__proj-2"]
    assert unresolved_row["resolved"] is False
    assert unresolved_row["resolved_status"] == "UNRESOLVED"
    assert unresolved_row["eval_status"] == "unresolved"
    assert unresolved_row["final_decision"] == "ABSTAIN"

    apply_failed_row = rows_by_task["demo__proj-3"]
    assert apply_failed_row["resolved_status"] == "PATCH_APPLY_FAILED"
    assert apply_failed_row["eval_status"] == "error"
    assert apply_failed_row["final_decision"] == "ABSTAIN"


def test_resolved_instance_with_sad_is_veto(tmp_path: Path) -> None:
    msa_dir = tmp_path / "msa"
    msa_dir.mkdir()

    # Patch includes a Python file with a weak RNG import to trigger SAD.
    patch = """
    diff --git a/file.py b/file.py
    index 000000..111111 100644
    --- a/file.py
    +++ b/file.py
    @@
    +import random
    """
    preds = [{"instance_id": "demo__proj-2", "model_patch": patch}]
    (msa_dir / "preds.json").write_text(json.dumps(preds), encoding="utf-8")
    _write_exit_status(msa_dir, ["demo__proj-2"], "Submitted")

    instance_results = tmp_path / "instance_results.jsonl"
    instance_results.write_text(
        json.dumps({"instance_id": "demo__proj-2", "resolved": True, "resolved_status": "RESOLVED"})
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
    assert success == 0

    rows = [json.loads(ln) for ln in output_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert rows[0]["eval_status"] == "resolved"
    assert rows[0]["cri"] == 1.0
    assert rows[0]["sad_flag"] is True
    assert rows[0]["security_scan_failed"] is False
    assert rows[0]["final_decision"] == "VETO"


def test_diff_fragment_wrapping_prevents_false_sad() -> None:
    patch = """
    diff --git a/foo.py b/foo.py
    index 000000..111111 100644
    --- a/foo.py
    +++ b/foo.py
    @@
    +    value = 1 + 1
    +    return value
    """

    violations, scan_failed = extract_security_violations_from_patch(patch)

    assert violations == []
    assert scan_failed is False


def test_resolved_instance_with_scan_failed_abstains(tmp_path: Path) -> None:
    msa_dir = tmp_path / "msa"
    msa_dir.mkdir()

    patch = """
    diff --git a/file.py b/file.py
    --- a/file.py
    +++ b/file.py
    @@
    +def broken(:
    +    pass
    """
    preds = [{"instance_id": "demo__proj-scanfail", "model_patch": patch}]
    (msa_dir / "preds.json").write_text(json.dumps(preds), encoding="utf-8")
    _write_exit_status(msa_dir, ["demo__proj-scanfail"], "Submitted")

    instance_results = tmp_path / "instance_results.jsonl"
    instance_results.write_text(
        json.dumps(
            {
                "instance_id": "demo__proj-scanfail",
                "resolved": True,
                "resolved_status": "RESOLVED",
            }
        )
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
    assert success == 0

    row = json.loads(output_path.read_text(encoding="utf-8").splitlines()[0])
    assert row["resolved"] is True
    assert row["sad_flag"] is False
    assert row["security_scan_failed"] is True
    assert row["final_decision"] == "ABSTAIN"
