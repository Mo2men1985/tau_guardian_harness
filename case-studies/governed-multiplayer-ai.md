# Governed Multiplayer AI - Sanitized Engineering Case Study

## Problem

AI coding agents can produce useful implementation work quickly, but a workflow becomes risky when the same agent can define success, change the candidate, interpret the evidence, and approve the result. The project explores a stricter model: use AI for speed while keeping authority, verification, and release evidence separated.

## My role

Founder / designer / control-tower operator for a private R&D project. I define the product thesis, workflow semantics, acceptance criteria, authority boundaries, evidence requirements, and review gates, then direct AI-assisted implementation and independent verification.

## Core architecture

The operating model separates four roles:

1. **Owner** - final human authority for scope, risk acceptance, merge, deployment, and release.
2. **Control Tower** - decomposes the mission, locks criteria, maintains project state, and evaluates whether evidence is sufficient to proceed.
3. **Builder** - typically Claude Code for implementation work. The builder may produce code, tests, and a builder report, but cannot independently certify its own candidate.
4. **Independent Verifier** - typically Codex or another isolated reviewer. It evaluates the exact candidate and can PASS, ABSTAIN, or VETO based on evidence.

The key rule is simple: **the agent that changes the candidate does not control acceptance of that candidate.**

## Engineering mechanisms explored

- Exact Git commit / candidate binding rather than reviewing a moving branch name.
- Criteria locks established before final evaluation.
- Evidence-backed handoffs between implementation and review stages.
- Fail-closed behavior when required evidence is missing or stale.
- Explicit invalidation of approvals when the candidate changes.
- Python governance and publisher components.
- Automated tests plus negative and mutation tests aimed at proving that controls actually cause the expected failure behavior.
- Security-focused testing around provenance, credential destinations, redirects, and producer/source identity.
- Bounded remediation: a failed candidate can be corrected, but previous blockers and the causal history are preserved rather than cosmetically rewritten.

## AI-native workflow

A typical iteration looks like this:

```text
Owner intent
  -> Control Tower mission + locked criteria
  -> Claude Code implementation
  -> exact Git candidate
  -> automated tests / negative controls
  -> independent Codex review
  -> PASS / ABSTAIN / VETO
  -> bounded remediation if needed
  -> re-review of the new exact candidate
```

## Why this matters

The project is not trying to remove human engineering judgment. It is trying to make AI-assisted engineering easier to inspect and harder to self-certify. This makes the workflow useful as both a product R&D direction and a practical method for coordinating coding agents on real repositories.

## What this demonstrates about my work

- I use Claude Code and Codex as working engineering tools, not only chat assistants.
- I can translate ambiguous product ideas into explicit workflows, data/evidence requirements, and testable acceptance criteria.
- I am comfortable reviewing Python, Git/GitHub state, tests, security boundaries, and failure evidence with AI agents in the loop.
- I deliberately distinguish implementation progress from verified readiness.
- I preserve uncertainty and blockers instead of converting incomplete evidence into a stronger claim.

## Current boundary

This is **private R&D**. The repository is not public and I do not claim the full platform is production-deployed. Sanitized technical artifacts, selected test/evidence excerpts, and controlled repository review can be provided when appropriate.
