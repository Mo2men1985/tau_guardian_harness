# Agent Merge Gate — Full Roadmap

## Mission

Build and validate an evidence-backed merge gate for AI-generated or AI-assisted software changes.

The product must answer one question:

> Is this exact code change sufficiently evidenced to merge?

The system is not primarily a code-generation agent, generic PR-comment bot, home-made quality score, or replacement for all human review.

Its differentiator is evidence-backed acceptance: exact candidate identity, deterministic evidence, explicit requirements/invariants, independent semantic review, reproduction where feasible, and fail-closed PASS / ABSTAIN / VETO decisions.

---

## Roadmap principles

1. **This repository is the only writable project home.**
2. **Other repositories are read-only sources.**
3. **No unvalidated scalar score may determine acceptance.**
4. **Missing evidence must not become PASS.**
5. **The generator cannot certify its own output.**
6. **AI hypotheses are not deterministic evidence.**
7. **High-impact findings should be reproduced when safe and feasible.**
8. **Every meaningful project action is recorded in `LOGBOOK.md`.**
9. **Every imported component is recorded in `SOURCE_OF_TRUTH.md`.**
10. **Do not build the SaaS until the benchmark proves the core auditor adds real value.**
11. **Tests and CI are evidence, not the objective.** Never optimize for green pipelines at the expense of realistic behavior, production readiness, or user value.
12. **Production value is the governing target.** Each phase must move the system toward a secure, reliable, operable, commercially useful product under real conditions.

---

# Phase 0 — Foundation

**Status: COMPLETE**

Established:

- canonical writable repository;
- `SOURCE_OF_TRUTH.md`;
- append-only `LOGBOOK.md`;
- evidence-based Guardian Evidence Gate foundation;
- structured pytest/JUnit evidence;
- Ruff correctness evidence;
- Bandit evidence;
- hardened Docker runner;
- PASS / ABSTAIN / VETO decision contract;
- removal of the retired experimental scoring concepts;
- sanitized GMAI reference imports;
- CI coverage for `product/**` branches.

### Gate

The existing foundation must remain green before later phases may be treated as valid.

---

# Phase 1 — Merge-Gate Core

**Status: COMPLETE**

Build the product-neutral engine that accepts an exact candidate change and produces an evidence-backed verdict.

## Core objects

- repository identity;
- base SHA;
- candidate SHA;
- PR diff;
- requirements;
- acceptance criteria;
- invariants;
- evidence registry;
- findings;
- decision;
- evidence bundle.

## Implement

- exact candidate identity;
- criteria lock;
- evidence registry;
- evidence admissibility;
- proposition binding;
- stale-evidence rejection;
- PASS / ABSTAIN / VETO adjudication;
- machine-readable reason codes;
- immutable run manifest;
- evidence bundle generation.

## Required properties

A candidate must not PASS when any required condition is unresolved, including:

- wrong candidate SHA;
- missing tests;
- missing required criteria;
- stale evidence;
- unresolved evidence references;
- incomplete required tools;
- malformed evidence;
- contradictory required evidence.

### Exit gate

Unit and negative tests demonstrate there is no accepted path from missing or stale evidence to PASS.

**Completion evidence (2026-09-26):**
- Phase 1 core implemented under `agent_merge_gate/`;
- repository test suite after mutation hardening: 77 passed;
- targeted semantic mutation gate: 18/18 mutants killed, 0 survived;
- mutation report is emitted as a CI artifact;
- Ruff correctness gate: PASS;
- Bandit medium/high gate: PASS;
- fixed runner image build: PASS;
- hardened sandbox smoke test: PASS;
- CI expansion exposed one independent-review path typo, which was fixed and regression-tested before completion.

---

# Phase 2 — Git / PR Intake

Turn a GitHub pull request or local Git candidate into a normalized audit target.

## Normalize

- repository;
- base SHA;
- candidate SHA;
- changed files;
- unified diff;
- language/framework inventory;
- test commands;
- dependency manifests;
- database migrations;
- infrastructure/config files;
- security-sensitive files.

## Change classification

Initial classes:

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

The classification determines which evidence collectors and invariants are required.

### Exit gate

The same exact PR/candidate produces the same normalized change inventory and candidate identity.

---

# Phase 3 — Deterministic Evidence Layer

Expand Guardian Evidence Gate into the PR evidence collector.

## Python-first evidence

- pytest + JUnit XML;
- Ruff structured diagnostics;
- Bandit structured findings;
- Semgrep;
- pip-audit / OSV-style dependency evidence;
- dependency-diff inspection;
- secrets scanning;
- migration checks;
- expected-test inventory;
- changed-code coverage where practical;
- sandbox execution.

## Later language support

Add only after the Python path is reliable:

- TypeScript / JavaScript;
- SQL;
- common web frameworks;
- additional build/test ecosystems.

## Evidence contract

All tool evidence must preserve:

- tool identity/version;
- command;
- exit code;
- completion state;
- timeout state;
- structured findings;
- artifact hash;
- execution duration;
- candidate binding.

Tool failure or missing required evidence leads to **ABSTAIN**, not PASS.

### Exit gate

A reproducible structured evidence record can be generated from an exact candidate without text-only inference.

---

# Phase 4 — Requirements & Invariant Engine

This is a central differentiation layer.

The gate must ask:

> What must remain true after this PR?

## Example invariants

- only admins may delete users;
- one tenant may never read another tenant's records;
- retrying a payment request must not double-charge;
- a migration must preserve existing rows unless data loss is explicitly authorized;
- a failed multi-step operation must not partially commit;
- an unauthenticated caller must not trigger protected state change;
- a retry must not duplicate an external side effect.

## Possible sources

- issue;
- PR description;
- explicit repository policy file;
- product specification;
- developer-supplied criteria;
- test suite;
- schema/security configuration.

## Design requirement

Acceptance criteria are locked before semantic evaluation.

The AI reviewer may not silently rewrite criteria to fit the implementation.

### Exit gate

Required invariants can be represented, versioned, bound to a candidate audit, and checked for evidence completeness.

---

# Phase 5 — Independent Semantic Auditor

Introduce an AI reviewer for questions deterministic tools cannot fully establish.

The semantic auditor does **not** directly create deterministic evidence and does **not** directly grant PASS.

## Typical hypotheses

- possible tenant bypass;
- possible TOCTOU race;
- requirement only partially implemented;
- unsafe migration behavior;
- retry path may duplicate side effects;
- authorization occurs after state mutation;
- error path leaves partial state;
- performance degradation from changed query structure;
- implementation contradicts declared behavior.

## Finding schema

Each finding should include:

- finding ID;
- candidate SHA;
- affected file/range;
- invariant/criterion involved;
- hypothesis;
- severity hypothesis;
- reasoning;
- evidence references already available;
- reproduction proposal;
- model/provider/version;
- prompt/output hashes;
- confidence as metadata only.

### Exit gate

A semantic finding cannot become an established defect solely because the model says it is true.

---

# Phase 6 — Finding Reproduction

Convert important hypotheses into executable evidence whenever safe and feasible.

Instead of only:

> Possible authorization issue.

attempt to produce something such as:

```text
test_cross_tenant_delete
Expected: 403
Observed: 204
```

## Reproduction outcomes

- `CONFIRMED`
- `NOT_REPRODUCED`
- `INCONCLUSIVE`
- `UNSAFE_TO_TEST`

## Techniques

- generated adversarial tests;
- targeted regression tests;
- mutation testing;
- controlled fixture construction;
- local/sandbox reproduction;
- deterministic query/state checks.

Temporary reproduction code must be isolated from production code unless explicitly promoted.

### Exit gate

High-impact findings can carry reproducible evidence rather than commentary alone, wherever technically and safely feasible.

---

# Phase 7 — Seeded-Defect Benchmark

Do not build the SaaS before this phase establishes value.

Create approximately 30–50 controlled defective PR fixtures with known ground truth.

## Initial defect families

- authorization bypass;
- tenant-isolation failure;
- race condition;
- transaction-boundary error;
- idempotency failure;
- migration/data-loss defect;
- secret/credential handling failure;
- validation bypass;
- requirement mismatch;
- exception swallowing;
- dependency vulnerability;
- measurable performance regression.

## Ground-truth requirement

Every seeded case must declare:

- intended invariant;
- inserted defect;
- expected detection path;
- expected reproduction where applicable;
- expected severity class;
- exact clean and defective candidate identities.

## Measure

- true positives;
- false positives;
- false negatives;
- precision;
- recall;
- reproduction rate;
- ABSTAIN rate;
- infrastructure failure rate;
- time to verdict;
- model/tool cost per PR.

## Compare four conditions

1. ordinary CI;
2. deterministic scanners only;
3. AI reviewer only;
4. full Agent Merge Gate.

### Kill gate

If the combined system does not materially add reproducible detection signal beyond simpler alternatives, stop, narrow, or redesign the product.

---

# Phase 8 — Real Repository Evaluation

Test the validated mechanism outside handcrafted benchmark fixtures.

## Initial strategy

Use controlled copies or fixtures derived from repositories the Owner controls.

Do **not** modify the source repositories.

Possible sources include historical defects, reconstructed failure modes, or intentionally vulnerable variants copied into this repository's benchmark area.

Later, evaluate appropriate public open-source changes offline.

## Measure

Use the same metrics from Phase 7 and add:

- repository setup failure rate;
- framework/language compatibility;
- time spent on configuration;
- finding usefulness to a reviewer.

### Exit gate

Performance remains useful outside the seeded benchmark and does not depend on hand-crafted assumptions.

---

# Phase 9 — GitHub Action V0

Only after the core validation succeeds.

Provide a minimal GitHub Action interface before building a hosted platform.

Example conceptual integration:

```yaml
- uses: agent-merge-gate/action@<pinned-version>
```

## PR output

Prefer one concise check result rather than a large volume of AI comments.

Example:

```text
Agent Merge Gate

VETO

Candidate: 84b3...
Required test suites: PASS
Security tools: PASS

Invariant failure:
TENANT_ISOLATION

Reproduction:
tests/generated/test_cross_tenant_access.py

Observed:
tenant A accessed tenant B resource
```

### Exit gate

The same commit-bound evidence can be surfaced through a GitHub check without changing the underlying adjudication semantics.

---

# Phase 10 — Human Review Workflow

Support ambiguity explicitly.

## Decision states

- `PASS`
- `ABSTAIN — REVIEW REQUIRED`
- `VETO`

The human reviewer should be able to inspect:

- evidence;
- exact candidate;
- reproduction;
- diff;
- AI analysis;
- affected invariant;
- unresolved evidence.

Human decisions must be logged separately and must not overwrite the original machine evidence.

### Exit gate

Human intervention is auditable and cannot silently transform an incomplete machine run into retroactive evidence.

---

# Phase 11 — GitHub App / Service

Build only after GitHub Action V0 and benchmark evidence justify the additional complexity.

## Responsibilities

- installation;
- webhook intake;
- PR/check-run events;
- encrypted credentials;
- repository policy;
- isolated workers;
- usage records;
- evidence storage policy.

## Conceptual architecture

```text
GitHub
  ↓
intake
  ↓
isolated worker
  ↓
evidence collectors
  ↓
semantic auditor
  ↓
reproduction worker
  ↓
adjudicator
  ↓
Evidence Bundle
  ↓
GitHub Check
```

### Exit gate

A private repository can be audited through least-privilege installation without exposing credentials or mixing tenant state.

---

# Phase 12 — Product Hardening

## Security

- least-privilege GitHub App permissions;
- no customer source retention by default where feasible;
- credential isolation;
- restricted outbound networking;
- tenant isolation;
- immutable/auditable records;
- signed or hash-bound evidence artifacts;
- dependency/supply-chain controls;
- secret handling;
- authorization checks on every protected action.

## Reliability

- idempotency;
- retry discipline;
- worker isolation;
- timeouts;
- queueing;
- stale-run invalidation;
- exact candidate binding;
- degraded modes;
- reproducible reruns.

## Operations

- structured observability;
- cost accounting;
- usage accounting;
- backup/restore where state requires it;
- incident response;
- versioned policies;
- release provenance.

### Exit gate

Operational readiness is evidenced, not inferred from a working demo.

---

# Phase 13 — Competitive Validation

Compare the product honestly with current alternatives available at the time of testing.

Possible comparison set:

- normal GitHub CI;
- GitHub-native AI review;
- CodeRabbit;
- Qodo;
- Codex review/security where accessible;
- Semgrep/CodeQL or equivalent deterministic tooling alone.

The product does not need to win every category.

## Core hypothesis

> Execution-backed acceptance and reproduction catch meaningful failures that comment-oriented review and conventional CI leave unresolved.

### Exit gate

There is measured evidence of a useful differentiation, or the proposition is revised.

---

# Phase 14 — First Commercial Wedge

Do not initially position this as a broad enterprise AI governance platform.

## Initial proposition

> Independent Merge Gate for AI-generated PRs.

## Initial target buyer

A software team that:

- has roughly 10–100 developers;
- heavily uses Cursor, Claude, Codex, Copilot or similar coding systems;
- is seeing PR volume increase;
- has senior-review bottlenecks;
- cares about security or correctness regressions.

## Possible pricing experiments

Only after value validation:

### Free

- limited public-repository runs;
- capped PR volume.

### Team

- per repository/month;
- included usage.

### Usage

- per audited PR;
- compute/model pass-through or tiered inclusion.

### Higher tier

- private/self-hosted runners;
- custom invariants;
- organization policy packs;
- extended audit retention;
- controlled integrations.

### Exit gate

At least one target buyer demonstrates willingness to pay for the validated mechanism.

---

# Phase 15 — Expansion

Only after the merge-gate wedge works.

Possible progression:

```text
Agent Merge Gate
       ↓
Agent Release Gate
       ↓
MCP / tool permission gate
       ↓
AI workflow regression testing
       ↓
general agent assurance
```

This is where the broader governance work may become commercially relevant.

Do not broaden before the initial merge-gate wedge is validated.

---

# Dependency chain

The intended sequence is:

```text
FOUNDATION
    ↓
MERGE-GATE CORE
    ↓
PR INGESTION
    ↓
DETERMINISTIC EVIDENCE
    ↓
REQUIREMENT / INVARIANT MODEL
    ↓
SEMANTIC HYPOTHESES
    ↓
REPRODUCTION
    ↓
ADJUDICATION
    ↓
SEEDED BENCHMARK
    ↓
REAL-WORLD BENCHMARK
    ↓
GITHUB ACTION
    ↓
FIRST USERS
    ↓
GITHUB APP
    ↓
PAID PRODUCT
    ↓
CONTROLLED EXPANSION
```

---

# Canonical completion rule

A roadmap phase is not complete merely because code was written.

For each phase, status must distinguish as applicable:

- designed;
- implemented;
- unit tested;
- integration tested;
- benchmarked;
- independently reviewed;
- staged;
- deployed;
- production proven.

Evidence must be bound to the exact candidate/version it supports.

---

# Immediate next phase

The next authorized product phase is:

## Phase 2 — Git / PR Intake

The first production-value milestone is a thin real vertical slice, not an isolated parser:

1. resolve a real repository base and candidate to exact commits;
2. compute the PR merge-base and deterministic binary-capable diff hash;
3. inventory real changed files, languages, manifests, migrations, infrastructure and security-sensitive paths;
4. classify the change deterministically;
5. emit a Phase-1 `AuditTarget` bound to the exact candidate and diff;
6. run the intake on the actual pull request introducing Phase 2 and retain its machine-readable artifact;
7. immediately connect the normalized target to real deterministic evidence collection rather than polishing abstractions in isolation.

Phase 2 is not complete merely because unit tests pass. Its meaningful exit evidence is that the same exact real PR produces the same normalized intake and candidate identity on rerun.

No SaaS, dashboard, billing, or broad hosted-service work is required before this real vertical slice and early benchmark path function.
