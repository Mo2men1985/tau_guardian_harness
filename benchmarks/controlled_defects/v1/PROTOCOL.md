# Controlled Defect Baseline v1

This benchmark exists to measure the **actual Agent Merge Gate**, not the
developer or control tower.

## Freeze rule

`manifest.json` is the ground-truth oracle for baseline v1. It is committed
before any listed candidate is executed. Once the first candidate is run, case
ground truth, invariants, mutations and expected observable failures are frozen.

Corrections are allowed only by creating a new benchmark version with an
explicit explanation; baseline-v1 results must remain intact.

## Separation of roles

### Benchmark designer

May:

- select an existing requirement;
- define a clean control;
- define a defect mutation;
- create the candidate commit;
- launch the ordinary-CI and Agent Merge Gate runs;
- diagnose product infrastructure failures after the result is recorded.

May **not**:

- manually mark a defect as detected on behalf of Agent Merge Gate;
- feed the known defect answer into the system under test;
- change ground truth after seeing the verdict;
- discard misses.

### System under test

The current system is the Phase-3 deterministic Agent Merge Gate.

Only its emitted, candidate-bound `Evidence Bundle` counts as its verdict.

## Baseline conditions

For each candidate record:

1. exact candidate SHA;
2. ordinary repository CI outcome;
3. Agent Merge Gate PASS / ABSTAIN / VETO;
4. evidence bundle SHA and semantic fingerprint when available;
5. runtime where available;
6. benchmark classification derived mechanically from frozen ground truth and
   system verdict.

## Interpretation

For defective cases:

- VETO = detected;
- PASS = miss;
- ABSTAIN = abstention, not detection.

For clean controls:

- PASS = correct acceptance;
- VETO = false positive;
- ABSTAIN = abstention.

A scanner warning or a human observation does not count unless it changes the
actual system verdict under the frozen policy.

## Important limitation

These cases are intentionally small and are drawn from existing repository
fixtures. They are an early product-value diagnostic, not a representative
industry benchmark. Results must not be generalized to arbitrary repositories,
languages, defect distributions, or production environments.
