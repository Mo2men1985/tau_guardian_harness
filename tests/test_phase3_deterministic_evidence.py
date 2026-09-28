import hashlib
from pathlib import Path
import subprocess

from agent_merge_gate.common import ABSTAIN, PASS, VETO
from agent_merge_gate.container_runner import ContainerCommandResult, PytestContainerResult
from agent_merge_gate.deterministic_evidence import (
    _bandit_record,
    _criteria_for,
    build_semantic_evidence,
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


def test_materialize_candidate_ignores_export_attributes(tmp_path: Path):
    repo = tmp_path / "repo-attrs"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "tests@example.com")
    git(repo, "config", "user.name", "Phase3")
    (repo / ".gitattributes").write_text(
        "tests/hidden.py export-ignore\nvalue.txt export-subst\n",
        encoding="utf-8",
    )
    (repo / "value.txt").write_text("$Format:%H$\n", encoding="utf-8")
    (repo / "tests").mkdir()
    (repo / "tests" / "hidden.py").write_text("assert True\n", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "attributes")
    candidate = git(repo, "rev-parse", "HEAD")

    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    materialize_candidate(repo, candidate, snapshot)

    assert (snapshot / "tests" / "hidden.py").read_text(encoding="utf-8") == "assert True\n"
    assert (snapshot / "value.txt").read_text(encoding="utf-8") == "$Format:%H$\n"


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
      "errors": [],
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


def test_bandit_scan_errors_make_evidence_incomplete():
    payload = b'{"errors":[{"filename":"broken.py","reason":"parse failed"}],"results":[]}'
    record, findings, blocking = _bandit_record(
        tool_result(payload),
        CANDIDATE,
        "sha256:runner",
    )
    assert findings == []
    assert blocking == []
    assert record.complete is False
    assert record.establishes is None


def test_bandit_missing_errors_field_is_incomplete():
    record, _, _ = _bandit_record(
        tool_result(b'{"results":[]}'),
        CANDIDATE,
        "sha256:runner",
    )
    assert record.complete is False
    assert record.establishes is None


def test_complete_clean_records_build_pass_bundle():
    pytest_record = _pytest_record(pytest_result(), CANDIDATE, "sha256:runner")
    ruff_record, _ = _ruff_record(tool_result(b"[]"), CANDIDATE, "sha256:runner")
    bandit_record, _, _ = _bandit_record(
        tool_result(b'{"errors":[],"results":[]}'),
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


def test_semantic_fingerprint_ignores_run_local_noise():
    pytest_one = pytest_result()
    pytest_two = PytestContainerResult(
        command=pytest_one.command,
        exit_code=pytest_one.exit_code,
        completed=pytest_one.completed,
        timed_out=pytest_one.timed_out,
        duration_ms=9999,
        collected=pytest_one.collected,
        passed=pytest_one.passed,
        failed=pytest_one.failed,
        errors=pytest_one.errors,
        skipped=pytest_one.skipped,
        junit=b"different-run-bytes",
        junit_sha256=hashlib.sha256(b"different-run-bytes").hexdigest(),
        stdout=b"different timing output",
        stdout_sha256=hashlib.sha256(b"different timing output").hexdigest(),
        version=pytest_one.version,
        error=pytest_one.error,
    )

    ruff_one = ContainerCommandResult(
        command=("docker", "run", "-v", "/tmp/a:/workspace:ro", "runner", "ruff", "check"),
        exit_code=0,
        completed=True,
        timed_out=False,
        duration_ms=1,
        stdout=b"[]",
        stdout_sha256=hashlib.sha256(b"[]").hexdigest(),
        stderr=b"",
        stderr_sha256=hashlib.sha256(b"").hexdigest(),
        version="ruff 0.12.12",
        error=None,
    )
    ruff_two = ContainerCommandResult(
        command=("docker", "run", "-v", "/tmp/b:/workspace:ro", "runner", "ruff", "check"),
        exit_code=0,
        completed=True,
        timed_out=False,
        duration_ms=500,
        stdout=b"[]",
        stdout_sha256=hashlib.sha256(b"[]").hexdigest(),
        stderr=b"run-local warning",
        stderr_sha256=hashlib.sha256(b"run-local warning").hexdigest(),
        version="ruff 0.12.12",
        error=None,
    )
    bandit_one = ContainerCommandResult(
        command=("docker", "run", "-v", "/tmp/a:/workspace:ro", "runner", "bandit", "-f", "json"),
        exit_code=0,
        completed=True,
        timed_out=False,
        duration_ms=1,
        stdout=b'{"errors":[],"results":[]}',
        stdout_sha256=hashlib.sha256(b'{"errors":[],"results":[]}').hexdigest(),
        stderr=b"",
        stderr_sha256=hashlib.sha256(b"").hexdigest(),
        version="bandit 1.8.6",
        error=None,
    )
    bandit_two = ContainerCommandResult(
        command=("docker", "run", "-v", "/tmp/b:/workspace:ro", "runner", "bandit", "-f", "json"),
        exit_code=0,
        completed=True,
        timed_out=False,
        duration_ms=800,
        stdout=b'{"errors":[],"results":[]}',
        stdout_sha256=hashlib.sha256(b'{"errors":[],"results":[]}').hexdigest(),
        stderr=b"different warning timestamp",
        stderr_sha256=hashlib.sha256(b"different warning timestamp").hexdigest(),
        version="bandit 1.8.6",
        error=None,
    )

    registry = EvidenceRegistry(
        (
            _pytest_record(pytest_one, CANDIDATE, "sha256:run-one"),
            _ruff_record(ruff_one, CANDIDATE, "sha256:run-one")[0],
            _bandit_record(bandit_one, CANDIDATE, "sha256:run-one")[0],
        )
    )
    criteria, submission = _criteria_for(include_ruff=True, include_bandit=True)
    bundle = build_bundle(
        target=make_intake().audit_target,
        criteria_lock=criteria,
        evidence_registry=registry,
        submission=submission,
    )

    first = build_semantic_evidence(
        intake=make_intake(),
        candidate_tree_sha256="1" * 64,
        runner_spec_sha256="2" * 64,
        image="runner",
        pytest_result=pytest_one,
        ruff_result=ruff_one,
        ruff_findings=[],
        bandit_result=bandit_one,
        bandit_findings=[],
        bandit_blocking=[],
        bundle=bundle,
    )
    second = build_semantic_evidence(
        intake=make_intake(),
        candidate_tree_sha256="1" * 64,
        runner_spec_sha256="2" * 64,
        image="runner",
        pytest_result=pytest_two,
        ruff_result=ruff_two,
        ruff_findings=[],
        bandit_result=bandit_two,
        bandit_findings=[],
        bandit_blocking=[],
        bundle=bundle,
    )
    assert first["fingerprint_sha256"] == second["fingerprint_sha256"]
    assert first["payload"] == second["payload"]


def test_semantic_payload_contains_runner_spec_once():
    pytest_clean = pytest_result()
    ruff_clean = tool_result(b"[]")
    bandit_clean = tool_result(b'{"errors":[],"results":[]}')
    registry = EvidenceRegistry(
        (
            _pytest_record(pytest_clean, CANDIDATE, "sha256:runner"),
            _ruff_record(ruff_clean, CANDIDATE, "sha256:runner")[0],
            _bandit_record(bandit_clean, CANDIDATE, "sha256:runner")[0],
        )
    )
    criteria, submission = _criteria_for(include_ruff=True, include_bandit=True)
    bundle = build_bundle(
        target=make_intake().audit_target,
        criteria_lock=criteria,
        evidence_registry=registry,
        submission=submission,
    )
    semantic = build_semantic_evidence(
        intake=make_intake(),
        candidate_tree_sha256="1" * 64,
        runner_spec_sha256="2" * 64,
        image="runner",
        pytest_result=pytest_clean,
        ruff_result=ruff_clean,
        ruff_findings=[],
        bandit_result=bandit_clean,
        bandit_findings=[],
        bandit_blocking=[],
        bundle=bundle,
    )
    assert semantic["payload"]["runner_spec_sha256"] == "2" * 64
    assert list(semantic["payload"]).count("runner_spec_sha256") == 1
