from dataclasses import FrozenInstanceError

import pytest

from agent_merge_gate import (
    ABSTAIN,
    AGENT,
    AGENT_ASSERTION,
    DETERMINISTIC,
    PASS,
    PRIMARY_STATE,
    TRUSTED_SYSTEM,
    VETO,
    AuditSubmission,
    AuditTarget,
    CriteriaLock,
    Criterion,
    CriterionEvidence,
    EvidenceRecord,
    EvidenceRegistry,
    MergeGateError,
    adjudicate,
    build_bundle,
    build_run_manifest,
)

BASE_SHA = "a" * 40
CANDIDATE_SHA = "b" * 40
DIFF_SHA = "d" * 64


def make_target():
    return AuditTarget("owner/repo", BASE_SHA, CANDIDATE_SHA, DIFF_SHA)


def make_criterion(required=True, count=1):
    return Criterion(
        "tests-pass",
        required,
        frozenset({DETERMINISTIC}),
        frozenset({"tests-pass-on-candidate"}),
        count,
    )


def make_lock(*criteria):
    return CriteriaLock("policy-v1", criteria or (make_criterion(),))


def make_record(
    evidence_id="e1",
    candidate_sha=CANDIDATE_SHA,
    establishes=True,
    complete=True,
    proposition="tests-pass-on-candidate",
    evidence_class=DETERMINISTIC,
    producer_kind=TRUSTED_SYSTEM,
):
    return EvidenceRecord(
        evidence_id,
        evidence_class,
        proposition,
        candidate_sha,
        producer_kind,
        "pytest",
        complete,
        establishes if complete else None,
        "e" * 64,
        '{"exit": 0}',
    )


def make_submission(*evidence_ids, criterion_id="tests-pass"):
    return AuditSubmission((CriterionEvidence(criterion_id, tuple(evidence_ids)),))


def decide(registry, submission, criteria_lock=None):
    return adjudicate(
        target=make_target(),
        criteria_lock=criteria_lock or make_lock(),
        evidence_registry=registry,
        submission=submission,
    )


def test_valid_evidence_passes():
    assert decide(EvidenceRegistry((make_record(),)), make_submission("e1")).decision == PASS


def test_missing_required_evidence_abstains():
    assert decide(EvidenceRegistry(()), AuditSubmission(())).decision == ABSTAIN


def test_unresolved_reference_abstains():
    assert decide(EvidenceRegistry(()), make_submission("missing")).decision == ABSTAIN


def test_stale_evidence_abstains():
    registry = EvidenceRegistry((make_record(candidate_sha=BASE_SHA),))
    assert decide(registry, make_submission("e1")).decision == ABSTAIN


def test_incomplete_evidence_abstains():
    registry = EvidenceRegistry((make_record(complete=False),))
    assert decide(registry, make_submission("e1")).decision == ABSTAIN


def test_wrong_proposition_abstains():
    registry = EvidenceRegistry((make_record(proposition="other"),))
    assert decide(registry, make_submission("e1")).decision == ABSTAIN


def test_inadmissible_class_abstains():
    registry = EvidenceRegistry(
        (make_record(evidence_class=PRIMARY_STATE, producer_kind=TRUSTED_SYSTEM),)
    )
    assert decide(registry, make_submission("e1")).decision == ABSTAIN


def test_valid_adverse_evidence_vetoes():
    registry = EvidenceRegistry((make_record(establishes=False),))
    assert decide(registry, make_submission("e1")).decision == VETO


def test_conflicting_evidence_abstains():
    registry = EvidenceRegistry(
        (make_record("e1", establishes=True), make_record("e2", establishes=False))
    )
    assert decide(registry, make_submission("e1", "e2")).decision == ABSTAIN


def test_unknown_submission_criterion_abstains():
    submission = AuditSubmission(
        (
            CriterionEvidence("tests-pass", ("e1",)),
            CriterionEvidence("invented", ()),
        )
    )
    assert decide(EvidenceRegistry((make_record(),)), submission).decision == ABSTAIN


def test_required_record_count_is_enforced():
    criteria_lock = make_lock(make_criterion(count=2))
    assert (
        decide(
            EvidenceRegistry((make_record(),)),
            make_submission("e1"),
            criteria_lock,
        ).decision
        == ABSTAIN
    )


def test_optional_missing_does_not_block():
    criteria_lock = make_lock(
        make_criterion(True),
        Criterion(
            "optional",
            False,
            frozenset({DETERMINISTIC}),
            frozenset({"optional-prop"}),
        ),
    )
    assert (
        decide(
            EvidenceRegistry((make_record(),)),
            make_submission("e1"),
            criteria_lock,
        ).decision
        == PASS
    )


def test_agent_assertion_cannot_be_admitted():
    with pytest.raises(MergeGateError):
        Criterion("x", True, frozenset({AGENT_ASSERTION}), frozenset({"p"}))


def test_deterministic_record_requires_trusted_origin():
    with pytest.raises(MergeGateError):
        make_record(producer_kind=AGENT)


def test_duplicate_evidence_ids_rejected():
    with pytest.raises(MergeGateError):
        EvidenceRegistry((make_record(), make_record()))


def test_duplicate_criteria_rejected():
    with pytest.raises(MergeGateError):
        CriteriaLock("v1", (make_criterion(), make_criterion()))


def test_non_exact_candidate_rejected():
    with pytest.raises(MergeGateError):
        AuditTarget("owner/repo", BASE_SHA, "latest", DIFF_SHA)


def test_complete_record_requires_outcome():
    with pytest.raises(MergeGateError):
        EvidenceRecord(
            "e",
            DETERMINISTIC,
            "p",
            CANDIDATE_SHA,
            TRUSTED_SYSTEM,
            "tool",
            True,
            None,
        )


def test_manifest_is_stable_and_bound():
    registry = EvidenceRegistry((make_record(),))
    submission = make_submission("e1")
    criteria_lock = make_lock()
    target = make_target()

    first = build_run_manifest(
        target=target,
        criteria_lock=criteria_lock,
        evidence_registry=registry,
        submission=submission,
    )
    second = build_run_manifest(
        target=target,
        criteria_lock=criteria_lock,
        evidence_registry=registry,
        submission=submission,
    )
    assert first.manifest_id == second.manifest_id

    other_registry = EvidenceRegistry((make_record("e2"),))
    other_manifest = build_run_manifest(
        target=target,
        criteria_lock=criteria_lock,
        evidence_registry=other_registry,
        submission=make_submission("e2"),
    )
    assert first.manifest_id != other_manifest.manifest_id


def test_bundle_is_stable_and_recomputes_decision():
    registry = EvidenceRegistry((make_record(),))
    submission = make_submission("e1")
    criteria_lock = make_lock()
    target = make_target()

    first = build_bundle(
        target=target,
        criteria_lock=criteria_lock,
        evidence_registry=registry,
        submission=submission,
    )
    second = build_bundle(
        target=target,
        criteria_lock=criteria_lock,
        evidence_registry=registry,
        submission=submission,
    )
    assert first.bundle_sha256 == second.bundle_sha256
    assert first.decision.decision == PASS


def test_frozen_target_cannot_be_mutated():
    target = make_target()
    with pytest.raises(FrozenInstanceError):
        target.candidate_sha = BASE_SHA
