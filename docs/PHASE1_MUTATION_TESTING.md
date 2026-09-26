# Phase 1 Mutation Hardening

## Purpose

Ordinary unit tests can pass even when they do not strongly constrain the
implementation. This gate deliberately corrupts critical Phase 1 acceptance
logic and verifies that the focused Phase 1 test suite fails against every
observable corruption.

This is targeted semantic mutation testing, not random syntax damage.

## Permanent CI gate

CI runs:

```bash
python tools/mutation_test_phase1.py --json-out mutation_reports/phase1.json
```

The step returns success only when:

1. the unmodified Phase 1 suite passes;
2. every configured mutation applies exactly once;
3. every configured semantic mutant causes the focused Phase 1 suite to fail.

The JSON report is uploaded as the `phase1-mutation-report` workflow artifact.

## Initial hardening result

The first enforced run exposed weaknesses rather than being tuned to pass.

### First mutation run

- targeted mutants configured: 19;
- killed: 14;
- survived: 5;
- specification errors: 0.

The surviving mutations were:

1. agent assertion rejection duplicated in adjudication;
2. bundle decision recomputation disabled;
3. criteria-lock hash binding disabled;
4. evidence-registry hash binding disabled;
5. submission hash binding disabled.

### Interpretation

The four bundle survivors were genuine test gaps. The existing suite built valid
bundles but did not directly attempt to construct tampered bundles.

The agent-assertion survivor was different: `CriteriaLock` already prohibits
`AGENT_ASSERTION` from being admissible, so the separate adjudication branch was
unreachable defense duplication. Disabling it did not alter externally reachable
behavior. The redundant branch was removed rather than counting an equivalent
mutation as a test failure.

## Remediation

Four explicit tamper tests were added:

- forged decision rejection;
- criteria-lock hash mismatch rejection;
- evidence-registry hash mismatch rejection;
- submission hash mismatch rejection.

The redundant adjudication branch was removed.

## Verified result

GitHub Actions run #50 / run id `36226234958`:

- repository tests: **77 passed**;
- targeted semantic mutants: **18**;
- killed: **18**;
- survived: **0**;
- mutation specification errors: **0**;
- targeted mutation score: **100% (18/18)**;
- Ruff correctness gate: PASS;
- Bandit medium/high gate: PASS;
- fixed runner image build: PASS;
- hardened sandbox smoke test: PASS.

## Current mutation set

The gate verifies that tests detect corruption of:

- missing-evidence fail-closed behavior;
- stale-evidence rejection;
- evidence-class admissibility;
- proposition binding;
- incomplete-evidence rejection;
- adverse-evidence handling;
- conflicting-evidence handling;
- required evidence-count enforcement;
- required-criterion VETO propagation;
- exact candidate SHA validation;
- policy rejection of agent assertions;
- evidence ID uniqueness;
- trusted origin for deterministic evidence;
- independent origin for independent-review evidence;
- bundle decision recomputation;
- criteria-lock hash binding;
- evidence-registry hash binding;
- submission hash binding.

## Limitation

A 100% score on this targeted set does not prove the system is correct. It proves
that these 18 explicitly selected critical corruptions are detected by the current
focused suite.

The next stronger evidence layers remain:

- property-based invariant testing;
- broader mutation generation;
- seeded-defect PR benchmark;
- real-repository evaluation;
- independent external review.
