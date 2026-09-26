# Phase 2 — Real Git / Pull Request Intake

## Purpose

Turn a real Git candidate into a deterministic, hash-bound audit target that can
feed the Phase-1 merge-gate core.

This phase uses Git itself as the source of repository truth. It does not infer
candidate identity from branch labels or mutable UI state.

## Inputs

- repository identity in `owner/name` form;
- repository working path;
- base ref or exact base commit;
- candidate ref or exact candidate commit.

Both refs are resolved to exact commit SHAs before any audit identity is created.

## PR semantics

Pull requests are normalized from the **merge base** of the base and candidate
commits to the candidate commit.

The intake therefore records separately:

- base SHA — the exact current base commit supplied for the PR;
- candidate SHA — the exact proposed commit;
- merge-base SHA — the common ancestor used for PR-style change inventory;
- diff SHA-256 — hash of the deterministic Git diff from merge base to candidate.

This avoids incorrectly treating unrelated changes that landed on the base
branch after the feature branch diverged as part of the candidate.

## Deterministic diff

The canonical diff uses:

```text
git diff --binary --full-index --no-ext-diff --no-renames <merge-base> <candidate> --
```

The raw bytes are SHA-256 hashed and bound into Phase 1's `AuditTarget`.

No timestamp is included in the normalized artifact.

## Candidate inventory

The exact candidate tree is inspected for:

- changed files and Git status;
- language counts for changed files;
- detected frameworks;
- dependency manifests present in the candidate;
- migration files changed;
- infrastructure files changed;
- security-sensitive files changed;
- test commands that can be derived without executing repository code;
- deterministic change classifications.

Initial classifications:

- `AUTH`
- `DATABASE`
- `MIGRATION`
- `API`
- `BUSINESS_LOGIC`
- `DEPENDENCY`
- `INFRA`
- `SECRETS`
- `PERFORMANCE`
- `TEST_ONLY`
- `DOCS`

These are routing metadata, not proof that a defect exists.

## Real integration evidence

GitHub Actions now checks out full history for pull requests and runs:

```text
python -m agent_merge_gate.intake_cli \
  --repository "$GITHUB_REPOSITORY" \
  --repo-path . \
  --base "$PR_BASE_SHA" \
  --candidate "$PR_HEAD_SHA" \
  --output phase2_reports/pr-intake.json
```

The machine-readable artifact is uploaded as:

`phase2-pr-intake`

The pull request that introduces Phase 2 is intended to be the first real
repository change processed through this path.

## Current scope

The intake is Git-native and Python-package-aware but deliberately conservative.

Not yet established:

- forked-PR fetch behavior across every GitHub topology;
- monorepo framework discovery beyond root-level framework metadata;
- execution of discovered test commands;
- deterministic scanner collection;
- semantic review;
- defect detection performance;
- customer value.

Those remain later vertical-slice steps rather than claims of this phase.
