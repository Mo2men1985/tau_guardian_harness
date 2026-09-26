#!/usr/bin/env python3
"""Targeted mutation testing for the Phase 1 Agent Merge Gate core.

The mutations are intentionally semantic: each disables or reverses one named
acceptance invariant while keeping the code syntactically valid. A mutant is
"killed" only when the existing Phase 1 test suite fails against that mutated
implementation.

Exit codes:
- 0: baseline passes and every mutant is killed;
- 1: one or more mutants survive, or baseline fails;
- 2: mutation specification could not be applied exactly once.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "agent_merge_gate"
FOCUSED_TEST = ROOT / "tests" / "test_phase1_core.py"


@dataclass(frozen=True)
class Mutation:
    name: str
    path: str
    old: str
    new: str
    invariant: str


@dataclass
class MutationResult:
    name: str
    invariant: str
    killed: bool
    returncode: int
    output_tail: str


MUTATIONS = (
    Mutation(
        "missing_evidence_cannot_pass",
        "adjudication.py",
        'decision=ABSTAIN,\n            reason_codes=("CRITERION_EVIDENCE_MISSING",),',
        'decision=PASS,\n            reason_codes=("CRITERION_EVIDENCE_MISSING",),',
        "Missing required evidence must not PASS.",
    ),
    Mutation(
        "stale_evidence_rejected",
        "adjudication.py",
        "if record.candidate_sha != candidate_sha:",
        "if False and record.candidate_sha != candidate_sha:",
        "Evidence from another candidate must not establish this candidate.",
    ),
    Mutation(
        "agent_assertion_non_establishing",
        "adjudication.py",
        "if record.evidence_class == AGENT_ASSERTION:",
        "if False and record.evidence_class == AGENT_ASSERTION:",
        "An agent assertion must not become establishing evidence.",
    ),
    Mutation(
        "evidence_class_admissibility_enforced",
        "adjudication.py",
        "if record.evidence_class not in criterion.admissible_evidence_classes:",
        "if False and record.evidence_class not in criterion.admissible_evidence_classes:",
        "A criterion may only use its locked evidence classes.",
    ),
    Mutation(
        "proposition_binding_enforced",
        "adjudication.py",
        "if record.proposition not in criterion.admissible_propositions:",
        "if False and record.proposition not in criterion.admissible_propositions:",
        "Evidence must establish a proposition locked to the criterion.",
    ),
    Mutation(
        "incomplete_evidence_rejected",
        "adjudication.py",
        "if not record.complete:",
        "if False and not record.complete:",
        "Incomplete evidence must not establish a criterion.",
    ),
    Mutation(
        "adverse_evidence_not_counted_positive",
        "adjudication.py",
        'else:\n            negative += 1\n            reasons.append(f"ADVERSE_EVIDENCE:{evidence_id}")',
        'else:\n            positive += 1\n            reasons.append(f"ADVERSE_EVIDENCE:{evidence_id}")',
        "Valid adverse evidence must not be counted as positive evidence.",
    ),
    Mutation(
        "conflicting_evidence_abstains",
        "adjudication.py",
        'criterion.criterion_id,\n            ABSTAIN,\n            tuple(sorted(set(reasons))),\n            cited.evidence_ids,\n        )\n    if negative:',
        'criterion.criterion_id,\n            PASS,\n            tuple(sorted(set(reasons))),\n            cited.evidence_ids,\n        )\n    if negative:',
        "Conflicting positive/adverse evidence must ABSTAIN.",
    ),
    Mutation(
        "required_evidence_count_enforced",
        "adjudication.py",
        "if positive < criterion.required_establishing_records:",
        "if False and positive < criterion.required_establishing_records:",
        "The locked minimum number of establishing records must be enforced.",
    ),
    Mutation(
        "required_veto_controls_overall",
        "adjudication.py",
        'if any(item.decision == VETO for item in required):\n        overall = VETO',
        'if any(item.decision == VETO for item in required):\n        overall = PASS',
        "A VETO on a required criterion must control the overall verdict.",
    ),
    Mutation(
        "candidate_sha_must_be_exact",
        "target.py",
        'require_exact_sha(self.candidate_sha, "candidate_sha")',
        'require_id(self.candidate_sha, "candidate_sha")',
        "Candidate identity must be an exact commit, not a branch-like label.",
    ),
    Mutation(
        "agent_assertion_cannot_be_admitted_by_policy",
        "criteria.py",
        "if AGENT_ASSERTION in self.admissible_evidence_classes:",
        "if False and AGENT_ASSERTION in self.admissible_evidence_classes:",
        "A criteria lock cannot declare agent assertions establishing.",
    ),
    Mutation(
        "duplicate_evidence_ids_rejected",
        "evidence.py",
        "if len(ids) != len(set(ids)):\n            raise MergeGateError(\"EVIDENCE_ID_COLLISION\")",
        "if False and len(ids) != len(set(ids)):\n            raise MergeGateError(\"EVIDENCE_ID_COLLISION\")",
        "Evidence identifiers must be unique in the trusted registry.",
    ),
    Mutation(
        "deterministic_evidence_requires_trusted_origin",
        "evidence.py",
        "if self.producer_kind != TRUSTED_SYSTEM:\n                raise MergeGateError(f\"TRUSTED_ORIGIN_REQUIRED: {self.evidence_id}\")",
        "if False and self.producer_kind != TRUSTED_SYSTEM:\n                raise MergeGateError(f\"TRUSTED_ORIGIN_REQUIRED: {self.evidence_id}\")",
        "Deterministic/primary evidence must come from a trusted system.",
    ),
    Mutation(
        "independent_review_requires_independent_origin",
        "evidence.py",
        "if self.producer_kind != INDEPENDENT_REVIEWER:\n                raise MergeGateError(f\"INDEPENDENT_ORIGIN_REQUIRED: {self.evidence_id}\")",
        "if False and self.producer_kind != INDEPENDENT_REVIEWER:\n                raise MergeGateError(f\"INDEPENDENT_ORIGIN_REQUIRED: {self.evidence_id}\")",
        "Independent-review evidence must have an independent-reviewer origin.",
    ),
    Mutation(
        "bundle_recomputes_decision",
        "bundle.py",
        "if self.decision.digest != expected.digest:",
        "if False and self.decision.digest != expected.digest:",
        "A bundle must reject a decision that does not match bound evidence/policy.",
    ),
    Mutation(
        "bundle_binds_criteria_hash",
        "bundle.py",
        "if self.manifest.criteria_lock_sha256 != self.criteria_lock.digest:",
        "if False and self.manifest.criteria_lock_sha256 != self.criteria_lock.digest:",
        "A bundle must reject a criteria lock different from the manifest hash.",
    ),
    Mutation(
        "bundle_binds_registry_hash",
        "bundle.py",
        "if self.manifest.evidence_registry_sha256 != self.evidence_registry.digest:",
        "if False and self.manifest.evidence_registry_sha256 != self.evidence_registry.digest:",
        "A bundle must reject an evidence registry different from the manifest hash.",
    ),
    Mutation(
        "bundle_binds_submission_hash",
        "bundle.py",
        "if self.manifest.submission_sha256 != self.submission.digest:",
        "if False and self.manifest.submission_sha256 != self.submission.digest:",
        "A bundle must reject a submission different from the manifest hash.",
    ),
)


def run_tests(work: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(work)
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "tests/test_phase1_core.py"],
        cwd=work,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=60,
        check=False,
    )


def prepare_workspace(work: Path) -> None:
    shutil.copytree(PACKAGE, work / "agent_merge_gate")
    (work / "tests").mkdir()
    shutil.copy2(FOCUSED_TEST, work / "tests" / FOCUSED_TEST.name)


def apply_mutation(work: Path, mutation: Mutation) -> None:
    path = work / "agent_merge_gate" / mutation.path
    text = path.read_text(encoding="utf-8")
    count = text.count(mutation.old)
    if count != 1:
        raise RuntimeError(
            f"{mutation.name}: expected mutation anchor exactly once in "
            f"{mutation.path}, found {count}"
        )
    path.write_text(text.replace(mutation.old, mutation.new, 1), encoding="utf-8")


def output_tail(text: str, lines: int = 12) -> str:
    return "\n".join(text.rstrip().splitlines()[-lines:])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="amg-mutation-baseline-") as raw:
        baseline_dir = Path(raw)
        prepare_workspace(baseline_dir)
        baseline = run_tests(baseline_dir)
        if baseline.returncode != 0:
            print("BASELINE FAILED")
            print(output_tail(baseline.stdout))
            return 1

    results: list[MutationResult] = []
    specification_errors: list[str] = []

    for mutation in MUTATIONS:
        with tempfile.TemporaryDirectory(prefix=f"amg-mut-{mutation.name}-") as raw:
            work = Path(raw)
            prepare_workspace(work)
            try:
                apply_mutation(work, mutation)
            except RuntimeError as exc:
                specification_errors.append(str(exc))
                continue
            proc = run_tests(work)
            killed = proc.returncode != 0
            results.append(
                MutationResult(
                    name=mutation.name,
                    invariant=mutation.invariant,
                    killed=killed,
                    returncode=proc.returncode,
                    output_tail=output_tail(proc.stdout),
                )
            )
            state = "KILLED" if killed else "SURVIVED"
            print(f"{state:8} {mutation.name}")

    killed_count = sum(item.killed for item in results)
    survived = [item for item in results if not item.killed]

    report = {
        "schema_version": "phase1-targeted-mutation-v1",
        "baseline_passed": True,
        "mutants_total": len(MUTATIONS),
        "mutants_executed": len(results),
        "mutants_killed": killed_count,
        "mutants_survived": len(survived),
        "specification_errors": specification_errors,
        "mutation_score": killed_count / len(results) if results else 0.0,
        "results": [asdict(item) for item in results],
    }

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    print(
        f"\nTargeted mutations: killed={killed_count}, "
        f"survived={len(survived)}, spec_errors={len(specification_errors)}"
    )
    if survived:
        print("\nSURVIVORS:")
        for item in survived:
            print(f"- {item.name}: {item.invariant}")
    if specification_errors:
        print("\nSPECIFICATION ERRORS:")
        for error in specification_errors:
            print(f"- {error}")

    if specification_errors:
        return 2
    return 1 if survived else 0


if __name__ == "__main__":
    raise SystemExit(main())
