# Phase 1 — Merge-Gate Core

## Purpose

Provide the product-neutral acceptance kernel for one exact candidate change.

This phase intentionally performs no GitHub API calls, model calls, code generation,
or hosted-service operations. Those belong to later roadmap phases.

## Trust boundaries

The core separates four inputs:

1. **Audit target** — repository, base commit, candidate commit, and diff SHA-256.
2. **Criteria lock** — trusted policy defining what must be established and which
   evidence classes and propositions may establish it.
3. **Evidence registry** — records produced outside the adjudicator and bound to
   an exact candidate, proposition, producer class, completion state, and outcome.
4. **Submission** — untrusted citations that point to registry records. A
   submission cannot define criteria or manufacture evidence.

## Decision semantics

- **PASS** — every required locked criterion has sufficient complete, admissible,
  candidate-bound establishing evidence.
- **VETO** — a required criterion has valid, complete, admissible adverse evidence.
- **ABSTAIN** — evidence is missing, unresolved, stale, incomplete, inadmissible,
  proposition-mismatched, conflicting, or otherwise insufficient.

VETO therefore means demonstrated adverse evidence. ABSTAIN means there is no
defensible basis to pass or to claim a demonstrated defect.

## Evidence-origin rules

- `PRIMARY_STATE` and `DETERMINISTIC_DERIVATION` require a
  `TRUSTED_SYSTEM` producer.
- `INDEPENDENT_REVIEW` requires an `INDEPENDENT_REVIEWER` producer.
- `AGENT_ASSERTION` requires an `AGENT` producer and cannot be admitted by a
  locked criterion.

This prevents model prose from being relabeled as deterministic evidence.

## Immutable identities

The target, criteria, registry, submission, decisions, run manifest, and evidence
bundle use frozen structures and canonical JSON SHA-256 identities.

The manifest binds the target to exact hashes of the criteria lock, registry, and
submission. The bundle recomputes adjudication and rejects a supplied decision
that does not match the bound policy and evidence.

## Negative-test contract

The Phase 1 focused suite verifies that these conditions cannot silently PASS:

- missing required evidence;
- unresolved evidence IDs;
- stale evidence;
- incomplete evidence;
- wrong proposition binding;
- inadmissible evidence class;
- conflicting evidence;
- unknown submitted criterion;
- insufficient establishing-record count;
- non-exact candidate label;
- duplicate evidence IDs;
- duplicate locked criteria;
- deterministic evidence attributed to an untrusted producer;
- criteria that attempt to admit an agent assertion.

It also verifies that valid adverse evidence produces VETO, optional unresolved
criteria do not block an otherwise valid PASS, and manifest/bundle identities
are stable.

## Not established by Phase 1

Phase 1 does not establish PR-ingestion correctness, semantic-review quality,
defect-detection performance, benchmark superiority, customer value, hosted
service security, or production readiness. Those remain later roadmap gates.
