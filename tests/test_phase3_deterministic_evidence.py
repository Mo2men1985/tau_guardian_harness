import hashlib
from pathlib import Path
import subprocess

from agent_merge_gate.common import ABSTAIN, PASS, VETO
from agent_merge_gate.container_runner import ContainerCommandResult, PytestContainerResult
from agent_merge_gate.deterministic_evidence import (
    _bandit_record,
    _criteria_for,
    _pytest_record,
    _ruff_record,
    materialize_candidate,
    python_targets,
    verdict_exit_code,
)
from agent_merge_gate.bundle import build_bundle
from agent_merge_gate.evidence import EvidenceRegistry
from agent_merge_gate.intake import ChangedFile, GitIntake
from agent_merge_gate.target import AuditTarget


CANDIDATE = "b" * 40


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def test_materialize_candidate_uses_exact_git_tree(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "tests@example.com")
    git(repo, "config", "user.name", "Phase3")
    (repo / "value.txt").write_text("one\n", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "one")
    candidate = git(repo, "rev-parse", "HEAD")

    (repo / "value.txt").write_text("working-tree-change\n", encoding="utf-8")

    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    first_hash = materialize_candidate(repo, candidate, first)
    second_hash = materialize_candidate(repo, candidate, second)

    assert first_hash == second_hash
    assert (first / "value.txt").read_text(encoding="utf-8") == "one\n"
    assert (second / "value.txt").read_text(encoding="utf-8") == "one\n"


def make_intake() -> GitIntake:
    target = AuditTarget("owner/repo", "a" * 40, CANDIDATE, "d" * 64)
    return GitIntake(
        schema_version="git-intake-v1",
        audit_target=target,
        merge_base_sha="a" * 40,
        changed_files=(
            ChangedFile("M", "agent_merge_gate/core.py", "Python", ("BUSINESS_LOGIC",)),
            ChangedFile("M", "tests/test_core.py", "Python", ()),
            ChangedFile("M", "README.md", None, ()),
        ),
        languages=(("Python", 2),),
        frameworks=(),
        dependency_manifests=("pyproject.toml",),
        migration_files=(),
        infrastructure_files=(),
        security_sensitive_files=(),
        test_commands=("python -m pytest -q",),
        change_classifications=("BUSINESS_LOGIC",),
    )


def test_python_targets_separate_tests_from_production():
    all_python, production = python_targets(make_intake())
    assert all_python == ("agent_merge_gate/core.py", "tests/test_core.py")
    assert production == ("agent_merge_gate/core.py",)


def pytest_result(*, collected=1, failed=0, errors=0, exit_code=0, completed=True):
    xml = b"<testsuite tests='1' failures='0' errors='0' skipped='0'/>"
    return PytestContainerResult(
        command=("python", "-m", "pytest"),
        exit_code=exit_code,
        completed=completed,
        timed_out=False,
        duration_ms=10,
        collected=collected,
        passed=max(0, collected - failed - errors),
        failed=failed,
        errors=errors,
        skipped=0,
        junit=xml if completed else None,
        junit_sha256=hashlib.sha256(xml).hexdigest() if completed else None,
        stdout=b"",
        stdout_sha256=hashlib.sha256(b"").hexdigest(),
        version="pytest 8.3.5",
        error=None if completed else "incomplete",
    )


def tool_result(payload: bytes, exit_code=0, completed=True):
    return ContainerCommandResult(
        command=("tool",),
        exit_code=exit_code,
        completed=completed,
        timed_out=False,
        duration_ms=5,
        stdout=payload,
        stdout_sha256=hashlib.sha256(payload).hexdigest(),
        stderr=b"",
        stderr_sha256=hashlib.sha256(b"").hexdigest(),
        version="tool 1",
        error=None if completed else "incomplete",
    )


def test_zero_tests_becomes_incomplete_evidence_not_veto():
    record = _pytest_record(
        pytest_result(collected=0, exit_code=5),
        CANDIDATE,
        "sha256:runner",
    )
    assert record.complete is False
    assert record.establishes is None


def test_real_test_failure_is_adverse_evidence():
    record = _pytest_record(
        pytest_result(collected=2, failed=1, exit_code=1),
        CANDIDATE,
        "sha256:runner",
    )
    assert record.complete is True
    assert record.establishes is False


def test_ruff_findings_are_adverse_when_structured_output_is_complete():
    record, findings = _ruff_record(
        tool_result(b'[{"code":"F821"}]', exit_code=1),
        CANDIDATE,
        "sha256:runner",
    )
    assert len(findings) == 1
    assert record.complete is True
    assert record.establishes is False


def test_bandit_only_blocks_medium_high_with_medium_high_confidence():
    payload = b"""{
      "results": [
        {"issue_severity": "LOW", "issue_confidence": "HIGH"},
        {"issue_severity": "HIGH", "issue_confidence": "HIGH"}
      ]
    }"""
    record, findings, blocking = _bandit_record(
        tool_result(payload, exit_code=1),
        CANDIDATE,
        "sha256:runner",
    )
    assert len(findings) == 2
    assert len(blocking) == 1
    assert record.establishes is False


def test_complete_clean_records_build_pass_bundle():
    pytest_record = _pytest_record(pytest_result(), CANDIDATE, "sha256:runner")
    ruff_record, _ = _ruff_record(tool_result(b"[]"), CANDIDATE, "sha256:runner")
    bandit_record, _, _ = _bandit_record(
        tool_result(b'{"results":[]}'),
        CANDIDATE,
        "sha256:runner",
    )
    registry = EvidenceRegistry((pytest_record, ruff_record, bandit_record))
    criteria, submission = _criteria_for(include_ruff=True, include_bandit=True)
    bundle = build_bundle(
        target=make_intake().audit_target,
        criteria_lock=criteria,
        evidence_registry=registry,
        submission=submission,
    )
    assert bundle.decision.decision == PASS


def test_incomplete_tool_record_drives_abstain():
    pytest_record = _pytest_record(pytest_result(), CANDIDATE, "sha256:runner")
    ruff_record, _ = _ruff_record(
        tool_result(b"", exit_code=2, completed=False),
        CANDIDATE,
        "sha256:runner",
    )
    registry = EvidenceRegistry((pytest_record, ruff_record))
    criteria, submission = _criteria_for(include_ruff=True, include_bandit=False)
    bundle = build_bundle(
        target=make_intake().audit_target,
        criteria_lock=criteria,
        evidence_registry=registry,
        submission=submission,
    )
    assert bundle.decision.decision == ABSTAIN


def test_adverse_tool_record_drives_veto():
    pytest_record = _pytest_record(pytest_result(), CANDIDATE, "sha256:runner")
    ruff_record, _ = _ruff_record(
        tool_result(b'[{"code":"F821"}]', exit_code=1),
        CANDIDATE,
        "sha256:runner",
    )
    registry = EvidenceRegistry((pytest_record, ruff_record))
    criteria, submission = _criteria_for(include_ruff=True, include_bandit=False)
    bundle = build_bundle(
        target=make_intake().audit_target,
        criteria_lock=criteria,
        evidence_registry=registry,
        submission=submission,
    )
    assert bundle.decision.decision == VETO


def test_verdict_exit_codes_are_fail_closed():
    assert verdict_exit_code(PASS) == 0
    assert verdict_exit_code(ABSTAIN) != 0
    assert verdict_exit_code(VETO) != 0
