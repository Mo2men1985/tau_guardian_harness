"""Phase 3 deterministic evidence vertical slice.

An exact Git candidate is materialized without executing repository code, then
tested/scanned in the fixed isolated runner. Raw artifacts are hashed and
translated into Phase-1 EvidenceRecords before adjudication.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile
from typing import Any

from .bundle import EvidenceBundle, build_bundle
from .common import (
    ABSTAIN,
    DETERMINISTIC,
    PASS,
    TRUSTED_SYSTEM,
    VETO,
    MergeGateError,
    canonical_json,
)
from .container_runner import (
    DEFAULT_IMAGE,
    ContainerCommandResult,
    PytestContainerResult,
    image_id,
    parse_bandit,
    parse_json_list,
    run_bandit,
    run_pytest,
    run_ruff,
)
from .criteria import CriteriaLock, Criterion
from .evidence import EvidenceRecord, EvidenceRegistry
from .intake import GitIntake, build_git_intake
from .submission import AuditSubmission, CriterionEvidence


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_bytes(path: Path, data: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return _sha256(data)


def _write_json(path: Path, value: Any) -> str:
    payload = (canonical_json(value) + "\n").encode("utf-8")
    return _write_bytes(path, payload)


def _git_archive(repo_path: Path, candidate_sha: str) -> bytes:
    try:
        proc = subprocess.run(
            ["git", "archive", "--format=tar", candidate_sha],
            cwd=repo_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
    except FileNotFoundError as exc:
        raise MergeGateError("GIT_NOT_AVAILABLE") from exc
    except subprocess.TimeoutExpired as exc:
        raise MergeGateError("GIT_ARCHIVE_TIMEOUT") from exc
    if proc.returncode != 0:
        raise MergeGateError(
            "GIT_ARCHIVE_FAILED: " + proc.stderr.decode("utf-8", "replace").strip()
        )
    return proc.stdout


def _safe_extract_archive(archive: bytes, destination: Path) -> None:
    """Extract a Git archive without accepting links or special files."""
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        for member in tar.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise MergeGateError(f"ARCHIVE_PATH_UNSAFE: {member.name}")
            target = destination.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise MergeGateError(f"ARCHIVE_MEMBER_UNSUPPORTED: {member.name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None:
                raise MergeGateError(f"ARCHIVE_FILE_UNREADABLE: {member.name}")
            target.write_bytes(source.read())
            target.chmod(0o755 if member.mode & 0o111 else 0o644)


def materialize_candidate(
    repo_path: str | Path,
    candidate_sha: str,
    destination: Path,
) -> str:
    archive = _git_archive(Path(repo_path).resolve(), candidate_sha)
    _safe_extract_archive(archive, destination)
    return _sha256(archive)


def _is_test_path(path: str) -> bool:
    p = PurePosixPath(path)
    return (
        "tests" in p.parts
        or "test" in p.parts
        or p.name.startswith("test_")
        or p.name.endswith("_test.py")
        or ".test." in p.name
        or ".spec." in p.name
    )


def python_targets(intake: GitIntake) -> tuple[tuple[str, ...], tuple[str, ...]]:
    all_python = tuple(
        item.path
        for item in intake.changed_files
        if not item.status.startswith("D") and PurePosixPath(item.path).suffix == ".py"
    )
    production = tuple(path for path in all_python if not _is_test_path(path))
    return all_python, production


def _pytest_record(
    result: PytestContainerResult,
    candidate_sha: str,
    runner_id: str,
) -> EvidenceRecord:
    complete = result.completed and result.collected > 0
    establishes = None
    if complete:
        establishes = (
            result.exit_code == 0
            and result.failed == 0
            and result.errors == 0
        )
    detail = result.metadata()
    detail["artifact"] = "pytest.xml"
    if result.completed and result.collected <= 0:
        detail["evidence_error"] = "NO_TESTS_COLLECTED"
    return EvidenceRecord(
        evidence_id="pytest",
        evidence_class=DETERMINISTIC,
        proposition="pytest-pass",
        candidate_sha=candidate_sha,
        producer_kind=TRUSTED_SYSTEM,
        producer=f"guardian-evidence-runner@{runner_id}",
        complete=complete,
        establishes=establishes,
        artifact_sha256=result.junit_sha256,
        detail_json=json.dumps(detail),
    )


def _ruff_record(
    result: ContainerCommandResult,
    candidate_sha: str,
    runner_id: str,
) -> tuple[EvidenceRecord, list[dict[str, Any]]]:
    parse_error = None
    findings: list[dict[str, Any]] = []
    if result.completed:
        try:
            findings = parse_json_list(result)
        except MergeGateError as exc:
            parse_error = str(exc)
    complete = result.completed and parse_error is None
    detail = result.metadata()
    detail.update({
        "artifact": "ruff.json",
        "finding_count": len(findings),
        "parse_error": parse_error,
    })
    return (
        EvidenceRecord(
            evidence_id="ruff",
            evidence_class=DETERMINISTIC,
            proposition="ruff-no-findings",
            candidate_sha=candidate_sha,
            producer_kind=TRUSTED_SYSTEM,
            producer=f"guardian-evidence-runner@{runner_id}",
            complete=complete,
            establishes=(len(findings) == 0) if complete else None,
            artifact_sha256=result.stdout_sha256 if result.stdout else None,
            detail_json=json.dumps(detail),
        ),
        findings,
    )


def _bandit_blocking(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        item
        for item in findings
        if str(item.get("issue_severity", "")).upper() in {"MEDIUM", "HIGH"}
        and str(item.get("issue_confidence", "")).upper() in {"MEDIUM", "HIGH"}
    ]


def _bandit_record(
    result: ContainerCommandResult,
    candidate_sha: str,
    runner_id: str,
) -> tuple[EvidenceRecord, list[dict[str, Any]], list[dict[str, Any]]]:
    parse_error = None
    findings: list[dict[str, Any]] = []
    if result.completed:
        try:
            findings = parse_bandit(result)
        except MergeGateError as exc:
            parse_error = str(exc)
    blocking = _bandit_blocking(findings)
    complete = result.completed and parse_error is None
    detail = result.metadata()
    detail.update({
        "artifact": "bandit.json",
        "finding_count": len(findings),
        "blocking_finding_count": len(blocking),
        "parse_error": parse_error,
    })
    return (
        EvidenceRecord(
            evidence_id="bandit",
            evidence_class=DETERMINISTIC,
            proposition="bandit-no-blocking",
            candidate_sha=candidate_sha,
            producer_kind=TRUSTED_SYSTEM,
            producer=f"guardian-evidence-runner@{runner_id}",
            complete=complete,
            establishes=(len(blocking) == 0) if complete else None,
            artifact_sha256=result.stdout_sha256 if result.stdout else None,
            detail_json=json.dumps(detail),
        ),
        findings,
        blocking,
    )


def _criteria_for(
    *,
    include_ruff: bool,
    include_bandit: bool,
) -> tuple[CriteriaLock, AuditSubmission]:
    criteria = [
        Criterion(
            "repository-tests",
            True,
            frozenset({DETERMINISTIC}),
            frozenset({"pytest-pass"}),
        )
    ]
    citations = [CriterionEvidence("repository-tests", ("pytest",))]
    if include_ruff:
        criteria.append(
            Criterion(
                "changed-python-correctness",
                True,
                frozenset({DETERMINISTIC}),
                frozenset({"ruff-no-findings"}),
            )
        )
        citations.append(CriterionEvidence("changed-python-correctness", ("ruff",)))
    if include_bandit:
        criteria.append(
            Criterion(
                "changed-python-security",
                True,
                frozenset({DETERMINISTIC}),
                frozenset({"bandit-no-blocking"}),
            )
        )
        citations.append(CriterionEvidence("changed-python-security", ("bandit",)))
    return (
        CriteriaLock("phase3-deterministic-v1", tuple(criteria)),
        AuditSubmission(tuple(citations)),
    )


def collect_deterministic_evidence(
    *,
    repo_path: str | Path,
    repository: str,
    base_ref: str,
    candidate_ref: str,
    output_dir: str | Path,
    image: str = DEFAULT_IMAGE,
) -> tuple[GitIntake, EvidenceBundle, dict[str, Any]]:
    repo = Path(repo_path).resolve()
    output = Path(output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)

    intake = build_git_intake(
        repo_path=repo,
        repository=repository,
        base_ref=base_ref,
        candidate_ref=candidate_ref,
    )
    runner_id = image_id(image)
    _write_json(output / "intake.json", intake.to_dict())

    with tempfile.TemporaryDirectory(prefix="amg-candidate-") as temp:
        snapshot = Path(temp) / "candidate"
        snapshot.mkdir()
        archive_sha256 = materialize_candidate(
            repo,
            intake.audit_target.candidate_sha,
            snapshot,
        )
        all_python, production_python = python_targets(intake)

        pytest_result = run_pytest(snapshot, image=image)
        if pytest_result.junit is not None:
            _write_bytes(output / "pytest.xml", pytest_result.junit)
        _write_bytes(output / "pytest.stdout.txt", pytest_result.stdout)

        ruff_result = run_ruff(snapshot, all_python, image=image)
        _write_bytes(output / "ruff.json", ruff_result.stdout)
        _write_bytes(output / "ruff.stderr.txt", ruff_result.stderr)

        bandit_result = run_bandit(snapshot, production_python, image=image)
        _write_bytes(output / "bandit.json", bandit_result.stdout)
        _write_bytes(output / "bandit.stderr.txt", bandit_result.stderr)

    records: list[EvidenceRecord] = [
        _pytest_record(pytest_result, intake.audit_target.candidate_sha, runner_id)
    ]
    ruff_findings: list[dict[str, Any]] = []
    bandit_findings: list[dict[str, Any]] = []
    bandit_blocking: list[dict[str, Any]] = []

    if all_python:
        ruff_record, ruff_findings = _ruff_record(
            ruff_result,
            intake.audit_target.candidate_sha,
            runner_id,
        )
        records.append(ruff_record)
    if production_python:
        bandit_record, bandit_findings, bandit_blocking = _bandit_record(
            bandit_result,
            intake.audit_target.candidate_sha,
            runner_id,
        )
        records.append(bandit_record)

    registry = EvidenceRegistry(tuple(records))
    criteria, submission = _criteria_for(
        include_ruff=bool(all_python),
        include_bandit=bool(production_python),
    )
    bundle = build_bundle(
        target=intake.audit_target,
        criteria_lock=criteria,
        evidence_registry=registry,
        submission=submission,
        schema_version="phase3-evidence-bundle-v1",
    )

    execution = {
        "schema_version": "phase3-deterministic-run-v1",
        "repository": repository,
        "candidate_sha": intake.audit_target.candidate_sha,
        "base_sha": intake.audit_target.base_sha,
        "diff_sha256": intake.audit_target.diff_sha256,
        "intake_sha256": intake.digest,
        "candidate_archive_sha256": archive_sha256,
        "runner_image": image,
        "runner_image_id": runner_id,
        "python_targets": list(all_python),
        "production_python_targets": list(production_python),
        "pytest": pytest_result.metadata(),
        "ruff": ruff_result.metadata(),
        "ruff_findings": ruff_findings,
        "bandit": bandit_result.metadata(),
        "bandit_findings": bandit_findings,
        "bandit_blocking_findings": bandit_blocking,
        "decision": bundle.decision.to_dict(),
        "bundle_sha256": bundle.bundle_sha256,
    }
    _write_json(output / "execution.json", execution)
    _write_json(output / "evidence-bundle.json", bundle.to_dict())
    return intake, bundle, execution


def verdict_exit_code(decision: str) -> int:
    if decision == PASS:
        return 0
    if decision == ABSTAIN:
        return 2
    if decision == VETO:
        return 3
    return 4
