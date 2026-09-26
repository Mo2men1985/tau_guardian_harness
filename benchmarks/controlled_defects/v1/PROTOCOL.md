# Controlled Defect Baseline v1

This benchmark measures the **actual Agent Merge Gate**, not the developer,
control tower, or automated code reviewer.

## Freeze rule

`manifest.json` is the ground-truth oracle for baseline v1. It is committed
before any listed candidate is executed. Once the first candidate is run, case
ground truth, invariants, mutations and expected observable failures are frozen.

Corrections after execution require a new benchmark version with an explicit
explanation. Baseline-v1 results remain intact.

## Target population

The primary incremental-value subset is deliberately limited to seeded defects
that **ordinary repository CI actually permits**.

Cases are selected because their frozen mutation is plausibly outside existing
test assertions. That selection is only a hypothesis until ordinary CI runs on
the exact candidate.

If ordinary CI rejects a defective candidate, preserve the result but classify
the candidate as `INELIGIBLE_FOR_INCREMENTAL_VALUE_SUBSET`. Do not count it as
evidence that Agent Merge Gate adds value beyond ordinary CI.

## Separation of roles

### Benchmark designer

May select an existing explicit requirement, define clean/defective candidates,
create candidate commits, launch runs, and diagnose infrastructure failures
after results are preserved.

May **not** manually mark a defect as detected on behalf of Agent Merge Gate,
feed the known answer into the system under test, change ground truth after
seeing a verdict, or discard misses.

### Automated repository review

Codex or another automated PR reviewer is an independent design/review signal.
Its comments can cause benchmark or product changes **before** candidate
execution, but its observations do not count as Agent Merge Gate detections.

### System under test

The current system is the Phase-3 deterministic Agent Merge Gate. Only its
candidate-bound Evidence Bundle counts as its verdict.

## Independent execution paths

Ordinary CI and Agent Merge Gate must both be attempted for every benchmark
candidate. Benchmark orchestration must not rely on a workflow ordering where a
failure in ordinary pytest prevents the system-under-test from running.

This separation must be implemented before executing the frozen candidates.
Normal repository merge policy does not need to be weakened to achieve it.

## Causal attribution

An aggregate VETO is **not** automatically a detection.

For a defective candidate:

- `DETECTED`: Agent Merge Gate emits VETO **and** the adverse evidence is
  causally attributable to the frozen seeded defect / expected observable
  failure.
- `INCIDENTAL_BLOCK`: Agent Merge Gate emits VETO, but the blocking evidence is
  unrelated to the seeded defect.
- `MISS`: Agent Merge Gate emits PASS.
- `ABSTAIN`: Agent Merge Gate emits ABSTAIN.

Attribution must cite the concrete EvidenceRecord/finding/test observation that
corresponds to the frozen defect. Human knowledge of the mutation is not
evidence that the gate detected it.

For clean controls:

- PASS = `CORRECT_ACCEPT`;
- VETO = `FALSE_POSITIVE`;
- ABSTAIN = `ABSTAIN`.

## Recorded evidence

For each candidate record:

1. exact candidate SHA;
2. frozen manifest SHA-256;
3. ordinary repository CI outcome and evidence;
4. Agent Merge Gate PASS / ABSTAIN / VETO;
5. evidence bundle hash and semantic fingerprint when available;
6. causal-attribution evidence when claiming DETECTED;
7. runtime where available;
8. benchmark classification derived from frozen ground truth plus actual
   execution evidence.

## Important limitation

These cases are intentionally small and derived from existing repository
fixtures. They are an early product-value diagnostic, not a representative
industry benchmark. Results must not be generalized to arbitrary repositories,
languages, defect distributions, or production environments.
