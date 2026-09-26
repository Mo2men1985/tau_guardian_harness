# Controlled Defect Baseline v1

This benchmark measures the **actual Agent Merge Gate**, not the developer,
control tower, or automated PR reviewer.

## Freeze rule

`manifest.json` is the ground-truth oracle for baseline v1. It is committed
before any listed candidate is executed. Once the first candidate is run, case
ground truth, invariants, mutations, expected observable failures, and causal
attribution rules are frozen.

Corrections after execution require a new benchmark version. Baseline-v1
results remain intact.

## Target population

Defective cases must plausibly survive the repository's existing ordinary test
suite. A mutation already directly asserted by an existing regression test is
not useful for the primary incremental-value question and must not be selected
as a baseline-v1 defect.

The frozen manifest records the inspected existing-suite gap for every defect.
This is a pre-execution design claim; the actual ordinary-CI outcome is still
recorded and controls the interpretation.

## Separation of roles

### Benchmark designer

May select written requirements, define clean controls and defect mutations,
create candidate commits, launch runs, and diagnose infrastructure failures
after results are recorded.

May **not** manually mark a defect as detected, feed the known defect answer
into the system under test, alter ground truth after seeing a verdict, or
discard misses.

### Automated PR review

Codex/GitHub automated review is a development-control input. It may find flaws
in the benchmark or implementation, but its observations do **not** count as
Agent Merge Gate detections.

### System under test

The current system is the Phase-3 deterministic Agent Merge Gate. Only its
candidate-bound Evidence Bundle determines its machine verdict.

## Baseline conditions

For each candidate record:

1. exact candidate SHA;
2. ordinary repository CI outcome;
3. Agent Merge Gate PASS / ABSTAIN / VETO;
4. evidence bundle SHA and semantic fingerprint when available;
5. adverse evidence responsible for any VETO;
6. causal-attribution classification;
7. runtime where available;
8. final benchmark classification.

Evidence collection should be retained even when an earlier ordinary-CI step
fails; a CI failure must not erase the gate's evidence. If workflow control
flow prevents collection, record an infrastructure/protocol failure rather
than guessing a gate result.

## Causal attribution

An aggregate VETO is **not automatically a detection**.

For a defective case to count as DETECTED, the adverse evidence that caused the
VETO must materially correspond to the frozen invariant, mutation, or expected
observable failure. Examples include a failing test that exercises the seeded
failure, or a scanner finding that identifies the seeded unsafe behavior.

If VETO is caused only by an unrelated test/scanner finding, classify it as
`INCIDENTAL_BLOCK`. It is not a true positive.

If both defect-linked and unrelated adverse evidence exist, the case may count
as DETECTED, but both evidence classes must be retained.

Attribution is a benchmark-labeling step over immutable machine evidence; it
must never change the Agent Merge Gate's original PASS/ABSTAIN/VETO verdict.

## Interpretation

Defective candidates:

- causally linked VETO = DETECTED;
- unrelated-only VETO = INCIDENTAL_BLOCK;
- PASS = MISS;
- ABSTAIN = ABSTAIN.

Clean controls:

- PASS = CORRECT_ACCEPT;
- VETO = FALSE_POSITIVE;
- ABSTAIN = ABSTAIN.

A human observation, Codex review, or scanner warning does not count unless it
is present in the actual system evidence and participates in the system
verdict.

## Important limitation

These cases are small and drawn from existing repository fixtures. They are an
early product-value diagnostic, not a representative industry benchmark.
Results must not be generalized to arbitrary repositories, languages, defect
distributions, or production environments.
