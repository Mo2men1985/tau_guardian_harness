# Agent Merge Gate — Source of Truth

## Canonical working repository

All implementation, experiments, product specifications, evidence, logs, and future mutations for Agent Merge Gate happen only in:

`Mo2men1985/tau_guardian_harness`

No other repository may be modified as part of this project unless the Owner explicitly changes this rule in this file.

## Product objective

Build and validate an evidence-backed merge gate for AI-generated or AI-assisted software changes.

The product must answer:

> Is this exact code change sufficiently evidenced to merge?

It is not primarily a code-generation agent or generic PR-comment bot.

The acceptance model is based on direct evidence such as executable tests, structured static-analysis findings, security evidence, exact candidate identity, requirement/invariant checks, and independently produced review evidence.

## Production value doctrine

The primary objective is to build a **real product that reaches production and creates real user value**.

Tests, CI, mutation gates, benchmarks, audits, and other assurance mechanisms are **means of obtaining trustworthy evidence** about the product. They are not the project objective and must never be optimized merely to make a pipeline green.

The project must therefore prefer evidence that answers real production questions:

- Does the implementation solve a real user problem?
- Does it behave correctly under realistic and adversarial conditions?
- Does it fail safely?
- Does it integrate with real repositories, workflows, permissions, dependencies, and infrastructure?
- Does it create measurable value beyond simpler or existing alternatives?
- Is it secure, reliable, maintainable, observable, operable, and commercially usable?
- Can independent or external evidence reproduce the claimed behavior?

A test that only mirrors the implementation, exercises a toy path, or exists mainly to satisfy CI is weak evidence and must not be treated as proof of readiness.

Test counts are never a quality target. When test results are reported, distinguish their evidence class and relevance, such as:

- core contract tests;
- regression tests;
- mutation tests;
- integration tests;
- adversarial/negative tests;
- benchmark tests;
- real-repository tests;
- end-to-end tests;
- production/staging evidence.

The governing question for every engineering action is:

> Does this move Agent Merge Gate closer to a defensible, production-capable product that provides real value?

If an activity increases test counts or internal complexity without materially improving correctness, evidence, production readiness, user value, or commercial viability, it should be deprioritized or removed.

## Current canonical base

- Baseline branch at project start: `main`
- Baseline commit: `266e67db4d87ccecc3ff24e446a627c080c50e80`
- Working branch: `product/agent-merge-gate-v0`
- Foundation date: 2026-09-26

## Repository mutation boundary

### Writable

Only this repository.

### Read-only references

The following repositories may be inspected for reusable ideas or sanitized components, but must not be changed from this project:

- `Mo2men1985/gmai-engineering-showcase`
- `Mo2men1985/governed-multiplayer-ai`
- `Mo2men1985/isnad-assurance`
- `Mo2men1985/qabl-al-mithaq-3`
- any other user repository not explicitly added to the Writable section

Because this repository is public, private-repository implementation code must not be copied here directly. A private component must first be independently sanitized or rewritten before import.

## Import policy

Imported source is stored under `imports/`.

Every import must record:

1. source repository;
2. exact source commit;
3. exact source path;
4. source blob SHA when available;
5. local destination;
6. whether the local copy is verbatim or adapted;
7. why the component is relevant.

Imported reference copies are immutable. Product adaptations must be created outside `imports/`, so provenance remains inspectable.

## Initial imported source registry

Source repository:

`Mo2men1985/gmai-engineering-showcase`

Source commit:

`c46704255f7582f9a42bc212b27a660f321dae64`

| Source path | Source blob SHA | Local destination | Mode | Purpose |
|---|---|---|---|---|
| `code/representative_governance_example.py` | `99cc336a37a72d2144276fa3a971c8a8c14557bd` | `imports/gmai_showcase/representative_governance_example.py` | verbatim | fail-closed adjudication and exact-candidate governance |
| `code/representative_evidence_example.py` | `77b1df185397fbb2f202ec960e7098c082289bd1` | `imports/gmai_showcase/representative_evidence_example.py` | verbatim | evidence provenance, proposition binding, registry integrity |
| `code/representative_credential_destination.py` | `a7bf210e36c7ff1b3ad983992dd8c12bee1e317f` | `imports/gmai_showcase/representative_credential_destination.py` | verbatim | credential-destination and redirect safety pattern |
| `code/representative_mutation_test_example.py` | `a5ec3bbe174db535e71be196fae26a3b9982b031` | `imports/gmai_showcase/representative_mutation_test_example.py` | verbatim | causal mutation-test pattern |

These files came from the owner's own sanitized public showcase. Their source repository notice restricts third-party reuse; this project is an owner-authorized reuse inside another repository owned by the same author. Provenance is retained here regardless.

## Evidence discipline

No component is considered proven merely because it exists or because an AI reviewer approves it.

Claims must distinguish:

- designed;
- implemented;
- unit tested;
- integration tested;
- benchmarked;
- independently reviewed;
- staged;
- deployed;
- production proven.

PASS / ABSTAIN / VETO remain decision states, not quality scores.

## Logbook requirement

`LOGBOOK.md` is the append-only project action ledger.

Every meaningful repository mutation, import, experiment, CI run, audit, decision, failure, remediation, benchmark, or release action must be recorded there with the exact branch/commit or workflow evidence available.

Past log entries must not be silently rewritten to improve the history. Corrections are appended as new entries.

## Change-control rule

A change to this Source of Truth, including the repository mutation boundary, import policy, or product objective, is itself a governed project action and must be recorded in `LOGBOOK.md`.
