# Phase 3 — Deterministic Evidence Vertical Slice

## Purpose

Connect a real exact Git candidate to real deterministic evidence and then into
the Phase-1 adjudicator.

The Phase-3 acceptance path is:

```text
exact PR candidate
  -> candidate snapshot
  -> isolated pytest / Ruff / Bandit
  -> raw evidence artifacts
  -> trusted EvidenceRecords
  -> locked criteria
  -> Evidence Bundle
  -> PASS / ABSTAIN / VETO
```

## Exact candidate materialization

The collector first reuses Phase-2 Git intake to resolve the exact base and
candidate commits and deterministic diff hash.

The candidate tree is then exported with `git archive` from the exact candidate
SHA. The live checkout and working tree are not used as the execution source.

The archive extractor rejects:

- absolute paths;
- parent-directory traversal;
- symlinks and hardlinks;
- non-file/non-directory archive members.

The raw Git archive is SHA-256 hashed and included in execution metadata.

## Isolation boundary

Candidate execution occurs in the fixed runner image:

`guardian-evidence-runner:py311`

The container uses:

- no network;
- read-only root filesystem;
- read-only candidate source;
- non-root UID/GID;
- all Linux capabilities dropped;
- `no-new-privileges`;
- PID, memory and CPU limits;
- isolated tmpfs;
- disabled Python bytecode writes;
- disabled third-party pytest plugin autoload.

Only one dedicated ephemeral evidence directory is writable for JUnit output.
It contains no source, credentials, or persistent host state.

The exact local Docker image ID is captured in the run evidence.

## Pytest policy

For the current Python vertical slice, the trusted runner executes:

```text
python -m pytest -q -o addopts= tests --junitxml=/evidence/pytest.xml
```

This deliberately:

- targets the repository `tests/` tree explicitly;
- ignores repository-controlled pytest `addopts`;
- requires a JUnit artifact;
- treats zero collected tests as incomplete evidence.

Decision semantics:

- completed tests + one or more failures/errors -> adverse evidence -> VETO;
- timeout/missing JUnit/zero collected tests -> incomplete evidence -> ABSTAIN;
- completed, non-empty, zero-failure test run -> establishing evidence.

Candidate tests are not treated as independent semantic proof. A candidate can
still modify its own tests or runtime behavior. Later requirements/invariant,
base-test comparison, adversarial reproduction, and benchmark phases must
address that deeper trust problem.

## Ruff policy

Ruff runs only against changed Python files from the exact candidate.

It uses:

```text
ruff check --isolated --select E9,F63,F7,F82 --output-format=json ...
```

`--isolated` prevents candidate-controlled Ruff configuration from weakening
the gate.

Any structured diagnostic under this deliberately narrow correctness ruleset is
adverse evidence.

Missing, timed-out, or malformed Ruff output is incomplete evidence.

## Bandit policy

Bandit runs against changed production Python files, excluding test files.

The collector preserves all structured findings but treats only findings with:

- severity MEDIUM or HIGH; and
- confidence MEDIUM or HIGH

as blocking adverse evidence.

This matches the existing repository security-gate posture and avoids
representing low-confidence/low-severity heuristic warnings as proven defects.

## Evidence artifacts

A successful collection may produce:

- `intake.json`;
- `pytest.xml`;
- `pytest.stdout.txt`;
- `ruff.json`;
- `bandit.json`;
- `execution.json`;
- `evidence-bundle.json`;
- `semantic-evidence.json`.

The execution record includes:

- exact base/candidate SHAs;
- diff SHA-256;
- candidate archive SHA-256;
- intake digest;
- runner image name and exact image ID;
- exact tool commands;
- tool versions;
- exit codes;
- completion and timeout state;
- durations;
- stdout/artifact hashes;
- structured findings;
- final bundle SHA-256 and verdict.

## Locked criteria

For the initial Python slice, criteria are created only when applicable:

1. `repository-tests` -> `pytest-pass`;
2. `changed-python-correctness` -> `ruff-no-findings`;
3. `changed-python-security` -> `bandit-no-blocking`.

All are deterministic evidence from a trusted runner. No model assertion can
establish them.

## CI behavior

On a real pull request:

1. Phase-2 intake runs first.
2. The fixed runner image is built and smoke-tested.
3. Phase-3 deterministic evidence is collected.
4. The complete evidence directory is uploaded even if the verdict is not PASS.
5. Existing mutation, Ruff and Bandit development gates still run.
6. A final step requires the Phase-3 Evidence Bundle verdict to equal PASS.

This preserves inspectability of VETO and ABSTAIN outcomes rather than losing
their artifacts when CI fails.

## Important trust limitation

This repository currently dogfoods the Phase-3 runner from its own workflow and
runner-image definition. That is useful end-to-end product evidence for this
controlled repository, but it is **not** proof that arbitrary untrusted customer
repositories can safely define the workflow or runner image.

A production hosted service must keep orchestration and trusted runner images
outside candidate control and pin/release them independently.

## Phase-3 completion rule

Phase 3 is not complete merely because the collector code or unit tests pass.

Completion requires a real pull request to:

- resolve to its exact Git candidate;
- execute the exact candidate in the hardened runner;
- produce real JUnit, Ruff and Bandit artifacts;
- create candidate-bound trusted EvidenceRecords;
- produce a hash-bound Evidence Bundle;
- return an adjudicated verdict;
- retain the artifact package for inspection;
- reproduce materially stable evidence on rerun, with expected exceptions such
  as durations and raw pytest timing metadata documented rather than hidden.


## Run provenance vs semantic reproducibility

Two independent executions of the same candidate are not expected to produce
byte-identical complete evidence bundles.

Legitimate per-run variation includes:

- execution durations;
- local Docker image IDs when an equivalent image is rebuilt;
- JUnit timing bytes;
- pytest timing output;
- Bandit `generated_at` timestamps;
- raw artifact hashes derived from those run-local values.

Those values remain preserved in the exact run evidence.

Phase 3 therefore also writes `semantic-evidence.json`. Its stable fingerprint
includes the substantive facts required to answer whether the rerun produced
the same result:

- repository/base/candidate/diff identity;
- intake digest;
- exact Git archive digest;
- runner specification digest;
- runner/tool versions and stable tool subcommands;
- pytest completion and result counts;
- Ruff structured findings;
- Bandit structured and blocking findings;
- locked criteria;
- final adjudicated decision.

It excludes run-local timings, ephemeral host mount paths, exact rebuilt image
IDs, and raw artifact hashes that legitimately contain timestamps.

A reproducibility claim requires matching semantic fingerprints on the same
exact candidate; a changed complete bundle hash by itself is not a failure of
reproducibility.
