# Agent Merge Gate V0 — Product Charter

## Problem

AI coding systems can generate more changes than teams can safely review. Existing tests and AI review comments do not necessarily establish that the exact proposed change satisfies requirements, preserves business/security invariants, or is safe to merge.

## V0 proposition

> Your coding agent writes the PR. Agent Merge Gate independently gathers evidence and decides whether that exact candidate is ready for merge.

## V0 is not

- a general coding agent;
- a replacement for GitHub;
- a replacement for all human review;
- a home-made quality score;
- a claim that static analysis proves software security.

## Core V0 pipeline

1. identify exact repository / base / candidate commit;
2. ingest PR diff and declared requirements;
3. build a locked acceptance/invariant set;
4. collect deterministic evidence;
5. run functional and security checks in isolation;
6. run independent semantic review for issues deterministic tools cannot establish;
7. require evidence references to resolve to trusted records;
8. reproduce high-impact findings where safe and feasible;
9. compute PASS / ABSTAIN / VETO from policy;
10. publish a commit-bound evidence bundle and GitHub check.

## First validation objective

Before building a full SaaS, evaluate the gate on deliberately defective PRs.

Initial defect families:

- authorization bypass;
- tenant-isolation failure;
- transaction-boundary error;
- race/concurrency failure;
- idempotency defect;
- unsafe migration;
- secret/credential handling failure;
- requirement mismatch;
- silent failure/error handling defect;
- measurable performance regression.

Primary measurements:

- seeded defects detected;
- seeded defects missed;
- false positives;
- findings with executable reproduction;
- time to verdict;
- model/tool cost per PR;
- infrastructure failure / ABSTAIN rate.

## Kill criterion

If the system does not add meaningful, reproducible detection signal beyond ordinary CI and existing review methods, do not productize it.

## V0 completion criterion

V0 is complete only when:

- its architecture and acceptance contract are implemented in this repository;
- benchmark fixtures are committed;
- results are reproducible from an exact commit;
- CI is green;
- limitations and false positives are reported;
- no claim relies on an unvalidated scalar score.
