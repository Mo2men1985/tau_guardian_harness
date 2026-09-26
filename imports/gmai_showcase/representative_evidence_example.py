"""Evidence a model may interpret, and may not create by describing.

PROVENANCE
    This is a sanitized representative implementation demonstrating the control
    pattern used in the private system. It is not a copy of the private module.
    The propositions, criteria and producers below are invented for this showcase.
    Standard library only.

WHAT THIS DEMONSTRATES

The first version of this control in the private system had a defect that a blind
review found immediately: an invented `evidence_id` labelled
`DETERMINISTIC_DERIVATION` produced a PASS. Nothing checked that the thing being
cited existed.

The obvious fix -- require the id to resolve -- was not enough either. A second
review cited a real, deterministic, correctly-bound record establishing
"a particular file is present with digest D" under a criterion about the test
suite. Nothing was forged. The reference resolved. The class was admissible. The
record simply had nothing to do with the claim.

So a record carries a PROPOSITION: what the observation is about, declared by the
producer that made it, not by the party citing it. And the criteria lock carries a
BINDING: which propositions may establish which criterion.

    CLAIM         model     "some evidence exists".        No weight.
    REFERENCE     model     an evidence_id.                A pointer, not a fact.
    RECORD        system    an observation, bound to a candidate SHA.
    PROPOSITION   system    what that observation is about.
    BINDING       lock      which propositions establish which criterion.
    INTERPRETATION model    what it means. The model's real contribution.
    VALIDATION    system    references resolve, bindings hold, policy is satisfied.

Two transitions are prohibited, and this module exists to make them unreachable:

    model prose      --X-->  deterministic evidence
    evidence for X   --X-->  evidence for Y

A producer here is a callable the trusted layer owns. It returns a record or it
returns nothing. It has no way to be persuaded, because nothing is asking it.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

SHA1_RE = re.compile(r"\A[0-9a-f]{40}\Z")


class EvidenceError(RuntimeError):
    """A producer could not observe what it was asked to observe."""


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    evidence_class: str      # PRIMARY_STATE | DETERMINISTIC_DERIVATION
    proposition: str         # what this observation is ABOUT
    method: str              # the instrument that produced it
    candidate_sha: str       # the exact state observed
    establishes: bool        # the producer's own answer, not the citer's
    detail: dict

    def digest(self) -> str:
        """A stable identity for the record, so a registry can be pinned as a whole."""
        payload = json.dumps(
            {
                "evidence_id": self.evidence_id,
                "evidence_class": self.evidence_class,
                "proposition": self.proposition,
                "method": self.method,
                "candidate_sha": self.candidate_sha,
                "establishes": self.establishes,
                "detail": self.detail,
            },
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return hashlib.sha256(payload).hexdigest()


# --------------------------------------------------------------------- producers

def produce_test_suite_record(
    repo_root: Path, candidate_sha: str, *,
    runner: Callable[[list[str], Path], subprocess.CompletedProcess] | None = None,
) -> EvidenceRecord:
    """Run the declared suite and record what was observed.

    `establishes` is False on a non-zero exit, and False is a real answer. A
    producer that raised instead would leave the criterion with no record at all,
    which reads to the layer above as "not yet observed" rather than "observed and
    failed" -- and those must not be the same state.

    An expected inventory is DECLARED, not discovered. Discovery cannot tell "this
    test does not exist" from "there is nothing to run", and most runners call both
    success: `unittest discover` exits 0 when it finds no tests. A vanished test has
    to be a failure, or deletion becomes the cheapest way to pass.
    """
    _require_exact(candidate_sha)
    manifest_path = repo_root / "trusted_test_manifest.json"
    if not manifest_path.is_file():
        raise EvidenceError("MANIFEST_ABSENT: the expected inventory is not declared")
    expected = json.loads(manifest_path.read_text()).get("expected_tests")
    if not isinstance(expected, list) or not expected:
        # An empty inventory is not an easy inventory. It is a malformed one, and
        # a control with nothing to examine has already failed.
        raise EvidenceError("MANIFEST_EMPTY: an expected inventory of zero tests "
                            "cannot establish anything")

    run = runner or _default_runner
    completed = run(["python3", "-m", "unittest", "-v", *expected], repo_root)
    observed = _parse_executed(completed.stderr)
    missing = sorted(set(expected) - observed)

    return EvidenceRecord(
        evidence_id="TE-TEST-SUITE",
        evidence_class="DETERMINISTIC_DERIVATION",
        proposition="P-TEST-SUITE-PASSES-ON-CANDIDATE",
        method="V3_DETERMINISTIC_VERIFICATION",
        candidate_sha=candidate_sha,
        # Silence is not success: a skipped test is not an executed one, and a
        # test that vanished is a failure rather than an absence.
        establishes=(completed.returncode == 0 and not missing),
        detail={
            "exit_code": completed.returncode,
            "expected": len(expected),
            "executed": len(observed),
            "missing": missing,
        },
    )


def produce_branch_head_record(repo_root: Path, candidate_sha: str,
                               branch: str) -> EvidenceRecord:
    """Resolve a branch head from primary Git state.

    PRIMARY_STATE, not DETERMINISTIC_DERIVATION: this is an observation of what a
    service says right now, not a computation anyone can repeat offline.
    """
    _require_exact(candidate_sha)
    completed = _default_runner(["git", "rev-parse", branch], repo_root)
    if completed.returncode != 0:
        # A tool failure is a failure, not an unknown that resolves in our favour.
        raise EvidenceError(f"PRIMARY_STATE_UNAVAILABLE: git rev-parse {branch} "
                            f"exited {completed.returncode}")
    head = completed.stdout.strip()
    return EvidenceRecord(
        evidence_id=f"TE-HEAD-{branch}",
        evidence_class="PRIMARY_STATE",
        proposition="P-BRANCH-HEAD-IS-CANDIDATE",
        method="PRIMARY_STATE_INSPECTION",
        candidate_sha=candidate_sha,
        establishes=(head == candidate_sha),
        detail={"branch": branch, "observed_head": head},
    )


# --------------------------------------------------------------------- registry

def build_registry(records: list[EvidenceRecord], candidate_sha: str) -> dict[str, EvidenceRecord]:
    """Collect producer output into the registry the adjudicator reads.

    Two rules, both of which exist because their absence was exploitable:

    A record bound to a different candidate is dropped rather than carried
    forward. Evidence from candidate A cannot establish candidate B, and a
    registry that quietly mixes them turns staleness into a silent property.

    A duplicate id is an error, not a last-write-wins. If two producers claim one
    id, the registry cannot say which observation a citation refers to, and a
    citation that is ambiguous is not a citation.
    """
    _require_exact(candidate_sha)
    registry: dict[str, EvidenceRecord] = {}
    for record in records:
        if record.candidate_sha != candidate_sha:
            continue
        if record.evidence_id in registry:
            raise EvidenceError(f"EVIDENCE_ID_COLLISION: {record.evidence_id}")
        registry[record.evidence_id] = record
    return registry


def registry_digest(registry: dict[str, EvidenceRecord]) -> str:
    """One identity over the whole registry, so it can be bound like any artifact."""
    joined = "\n".join(f"{k}:{registry[k].digest()}" for k in sorted(registry))
    return hashlib.sha256(joined.encode()).hexdigest()


# ----------------------------------------------------------------------- helpers

def _require_exact(candidate_sha: str) -> None:
    if not SHA1_RE.match(candidate_sha or ""):
        raise EvidenceError(
            f"CANDIDATE_NOT_EXACT: {candidate_sha!r} is not a 40-hex commit. "
            f"Evidence is bound to a state, and a label is not a state.")


def _default_runner(argv: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=600)


_EXECUTED = re.compile(r"^(\S+) \((\S+?)\)(?: \S+)? \.\.\. (ok|FAIL|ERROR|skipped.*)$",
                       re.MULTILINE)


def _parse_executed(stderr: str) -> set[str]:
    """Which declared tests actually ran and passed.

    A skip is recorded as executed=False on purpose. "It was skipped" and "it
    passed" are different observations, and a producer that flattens them has
    thrown away the only thing that distinguishes a green suite from a silent one.
    """
    executed: set[str] = set()
    for name, dotted, outcome in _EXECUTED.findall(stderr or ""):
        if outcome == "ok":
            executed.add(f"{dotted}.{name}")
    return executed
