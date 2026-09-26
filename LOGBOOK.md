# Agent Merge Gate — Logbook

This is the append-only action ledger for the project.

## Entry format

Each entry should record, when applicable:

- timestamp/date;
- actor;
- repository and branch;
- starting commit;
- action performed;
- files/components affected;
- source provenance for imports;
- resulting commit/workflow/PR;
- verification result;
- unresolved issues;
- next authorized step.

Corrections are added as later entries rather than silently rewriting historical facts.

---

## 2026-09-26 — Project repository lock established

**Actor:** ChatGPT / Owner-authorized repository operation

**Repository:** `Mo2men1985/tau_guardian_harness`

**Starting main commit:** `266e67db4d87ccecc3ff24e446a627c080c50e80`

**Working branch created:** `product/agent-merge-gate-v0`

**Decision:**
- this repository is the only writable repository for Agent Merge Gate work;
- all other repositories are read-only inputs;
- private repository code will not be copied into this public repository without a separate sanitization/rewrite step;
- source provenance will be retained for every imported component.

**External repository mutations:** none.

**Verification:** branch creation confirmed by GitHub.

**Next:** establish source registry, import sanitized reference components, run CI, and record results.


---

## 2026-09-26 — Source registry and sanitized reference import

**Actor:** ChatGPT / Owner-authorized repository operation

**Repository:** `Mo2men1985/tau_guardian_harness`

**Branch:** `product/agent-merge-gate-v0`

**Actions:**
- created `SOURCE_OF_TRUTH.md`;
- created this append-only `LOGBOOK.md`;
- created `docs/AGENT_MERGE_GATE_V0.md`;
- created `imports/gmai_showcase/README.md`;
- imported four verbatim sanitized reference files from `Mo2men1985/gmai-engineering-showcase`.

**Read-only source commit:** `c46704255f7582f9a42bc212b27a660f321dae64`

**Imports:**
- governance reference — source blob `99cc336a37a72d2144276fa3a971c8a8c14557bd`;
- evidence reference — source blob `77b1df185397fbb2f202ec960e7098c082289bd1`;
- credential-destination reference — source blob `a7bf210e36c7ff1b3ad983992dd8c12bee1e317f`;
- mutation-test reference — source blob `a5ec3bbe174db535e71be196fae26a3b9982b031`.

**Import commits in this repository:**
- `eb320c3f499121f5b0743136f00e5305684e3a66`;
- `0cd8d751ca39a090883f27a150e2ae287dd4aa2d`;
- `bb50fd27c3f940b7b4f448b262eecb6294078054`;
- `9490c4d7e2a915f28563ef0ea9733460e4f2b446`.

**External repository mutations:** none.

**Verification status:** CI pending at the time of this entry.

**Next:** run/inspect branch CI and append the exact result.


---

## 2026-09-26 — Foundation verification

**Actor:** ChatGPT / Owner-authorized repository operation

**Branch head tested:** `ab726275feb9c29b1b3bd32ae917ce16d3cf1cfd`

**GitHub Actions:** Evidence Gate CI run #19, run id `36224096173`

**Result:** PASS

**Completed gates:**
- dependency installation — PASS;
- unit and policy tests — PASS;
- correctness-class Ruff gate — PASS;
- Bandit medium/high gate — PASS;
- fixed runner image build — PASS;
- hardened sandbox smoke test — PASS.

**Import integrity verification:** PASS

Each imported destination Git blob exactly matched its recorded source blob:

- governance: `99cc336a37a72d2144276fa3a971c8a8c14557bd`;
- evidence: `77b1df185397fbb2f202ec960e7098c082289bd1`;
- credential destination: `a7bf210e36c7ff1b3ad983992dd8c12bee1e317f`;
- mutation harness: `a5ec3bbe174db535e71be196fae26a3b9982b031`.

**CI maintenance action:** `.github/workflows/ci.yml` was extended to run on `product/**` branches so ongoing Agent Merge Gate work is continuously checked.

**External repository mutations:** none.

**Status:** foundation is suitable for merge into `main`.

**Logging note:** this entry records the substantive actions and their verification. The commit that appends a log entry is itself tracked by Git history; CI generated solely by that append is tracked by GitHub Actions and can be referenced by the next substantive entry, avoiding recursive log-only commits.


---

## 2026-09-26 — Foundation merged into canonical main

**Actor:** ChatGPT / Owner-authorized repository operation

**Pull request:** #23 — `Establish Agent Merge Gate source registry and action logbook`

**Verified PR head:** `86cf8157bb1f96af3da1c4919f8904e39edafbef`

**Pre-merge verification:**
- branch push CI run #20 — PASS;
- pull-request CI run #21 — PASS.

**Merge method:** squash

**Canonical main commit:** `8220bc95c8452bdb3e59bfd26aeb9f7c02d7b690`

**Post-merge GitHub Actions:** Evidence Gate CI run #22, run id `36224211169` — PASS.

**Post-merge completed gates:**
- dependency installation — PASS;
- unit and policy tests — PASS;
- correctness-class Ruff gate — PASS;
- Bandit medium/high gate — PASS;
- fixed runner image build — PASS;
- hardened sandbox smoke test — PASS.

**External repository mutations:** none.

**Canonical project state:** `main` now contains the source-of-truth file, append-only logbook, V0 product charter, provenance-preserving sanitized imports, and CI coverage for ongoing `product/**` branches.

**Next authorized product step:** implement the first Agent Merge Gate V0 product modules and seeded-defect validation fixtures in this repository only.


---

## 2026-09-26 — Canonical full roadmap committed

**Actor:** ChatGPT / Owner-authorized repository operation

**Repository:** `Mo2men1985/tau_guardian_harness`

**Starting main commit:** `32d89051d913a72e92538681b30464488a42c696`

**Working branch:** `product/save-full-roadmap`

**Action:** added `ROADMAP.md` as the canonical end-to-end Agent Merge Gate roadmap.

**Roadmap commit:** `63dbbe3b3e51945edc8d68cc8e6bde15fa40c160`

**Roadmap scope:** phases 0–15 covering foundation, merge-gate core, PR intake, deterministic evidence, requirements/invariants, semantic audit, reproduction, seeded benchmark, real-repository validation, GitHub Action, human review, GitHub App/service, product hardening, competitive validation, commercial wedge, and controlled expansion.

**Key sequencing rule:** do not build the SaaS before the seeded/real benchmark demonstrates material value beyond simpler alternatives.

**External repository mutations:** none.

**Verification status:** CI pending at the time of this entry.

**Next:** verify the exact roadmap branch with CI and merge into `main`.


---

## 2026-09-26 — Canonical roadmap merged into main

**Actor:** ChatGPT / Owner-authorized repository operation

**Pull request:** #24 — `Add canonical Agent Merge Gate full roadmap`

**Verified PR head:** `c35d4b3a566bf8e6df4282a667c75eae998014e4`

**Verification before merge:**
- branch CI run #25 — PASS;
- branch CI run #26 — PASS;
- pull-request CI run #27 — PASS.

**Merge method:** squash

**Roadmap merge commit:** `740f9199f9bd8940da7a3376f19c105203f5f522`

**Canonical artifact:** `ROADMAP.md`

**External repository mutations:** none.

**Status:** the full Agent Merge Gate roadmap is now canonical on `main`.

**Next authorized implementation phase:** Phase 1 — Merge-Gate Core.


---

## 2026-09-26 — Phase 1 Merge-Gate Core implemented and verified

**Actor:** ChatGPT / Owner-authorized repository operation

**Repository:** `Mo2men1985/tau_guardian_harness`

**Branch:** `product/phase1-merge-gate-core`

**Phase:** 1 — Merge-Gate Core

**Implemented:**
- exact audit-target identity;
- immutable criteria lock;
- trusted evidence registry;
- evidence-class and producer-origin enforcement;
- proposition binding;
- stale-evidence rejection;
- untrusted criterion-evidence submission model;
- fail-closed PASS / ABSTAIN / VETO adjudication;
- machine-readable reason codes;
- immutable run manifest;
- evidence-bundle hashing and integrity checks;
- bundle decision recomputation;
- focused negative test suite;
- Phase 1 technical contract documentation;
- CI coverage expanded to scan `agent_merge_gate/`.

**Verification defect found during CI hardening:**
Ruff found a misspelled independent-review producer constant on the newly scanned path. The path had not been exercised by the original tests. The constant was corrected and a dedicated independent-review origin regression test was added before Phase 1 completion.

**Verified candidate:** `94d8b90ba1175ed93b0e1b9e7494f410c2111f4b`

**GitHub Actions:** run #39, run id `36225623694` — PASS.

**Observed test result:** 73 passed.

**Completed gates:**
- unit and policy tests — PASS;
- Ruff correctness gate including `agent_merge_gate/` — PASS;
- Bandit medium/high gate including `agent_merge_gate/` — PASS;
- fixed runner image build — PASS;
- hardened sandbox smoke test — PASS.

**External repository mutations:** none.

**Roadmap:** Phase 1 marked COMPLETE on this branch.

**Next:** verify the roadmap/logbook head, open Phase 1 PR to `main`, run PR CI, and merge only if the exact PR head remains green.


---

## 2026-09-26 — Phase 1 merged into canonical main

**Actor:** ChatGPT / Owner-authorized repository operation

**Pull request:** #25 — `Implement Phase 1 evidence-bound merge-gate core`

**Verified PR head:** `ff7be5e3140b72fc92b49ab4763020bbc5ba1e67`

**Pre-merge verification:**
- corrected implementation run #39 — PASS, 73 tests passed;
- exact branch-head run #41 — PASS;
- pull-request run #42, run id `36225756932` — PASS.

**Merge method:** squash

**Phase 1 merge commit:** `09ecc20ce0b633ee8f0dca587deac08d01aabf29`

**Post-merge GitHub Actions:** run #43, run id `36225796476` — PASS.

**Post-merge completed gates:**
- unit and policy tests — PASS;
- Ruff correctness gate including `agent_merge_gate/` — PASS;
- Bandit medium/high gate including `agent_merge_gate/` — PASS;
- fixed runner image build — PASS;
- hardened sandbox smoke test — PASS.

**Material defect discovered during implementation:** when CI coverage was widened to the new package, Ruff exposed a misspelled independent-review producer constant in an otherwise unexercised path. The defect was fixed and a dedicated regression test was added before merge. Failed intermediate CI runs remain in GitHub Actions history as part of the evidence trail.

**Canonical Phase 1 status:** IMPLEMENTED + TESTED + CI VERIFIED.

**Not established:** independent external audit, seeded-defect benchmark performance, real-repository performance, hosted-service readiness, deployment, or production proof.

**External repository mutations:** none.

**Next canonical roadmap phase:** Phase 2 — Git / PR Intake.


---

## 2026-09-26 — Phase 1 mutation hardening

**Actor:** ChatGPT / Owner-authorized repository operation

**Repository:** `Mo2men1985/tau_guardian_harness`

**Branch:** `product/phase1-mutation-hardening`

**Starting main commit:** `58673e2e6b9681a7776664257147a0aca796d2fc`

**Purpose:** verify that the Phase 1 test suite detects deliberate semantic corruption of critical merge-gate invariants rather than merely passing the intended implementation.

**Actions:**
- added `tools/mutation_test_phase1.py`;
- added a permanent targeted mutation gate to GitHub Actions;
- added upload of a machine-readable mutation report artifact;
- added explicit bundle-tamper regression tests;
- removed one unreachable duplicate agent-assertion adjudication branch;
- added `docs/PHASE1_MUTATION_TESTING.md`;
- updated Phase 1 completion evidence in `ROADMAP.md`.

**First enforced mutation run:** GitHub Actions run #47, run id `36226155921` — FAILED as intended by the gate.

First-run result:
- configured mutants: 19;
- killed: 14;
- survived: 5;
- specification errors: 0.

Survivors:
- one redundant/unreachable agent-assertion adjudication defense;
- forged bundle decision not directly tested;
- criteria-lock hash tamper not directly tested;
- evidence-registry hash tamper not directly tested;
- submission hash tamper not directly tested.

**Remediation:**
- the redundant unreachable adjudication branch was removed;
- four direct tamper tests were added.

**Corrected verification:** GitHub Actions run #50, run id `36226234958` — PASS.

Observed corrected result:
- repository tests: 77 passed;
- targeted semantic mutants: 18;
- killed: 18;
- survived: 0;
- mutation specification errors: 0;
- targeted mutation score: 100% for the configured 18-mutant set;
- Ruff correctness gate — PASS;
- Bandit medium/high gate — PASS;
- fixed runner image build — PASS;
- hardened sandbox smoke test — PASS.

**Evidence artifact:** `phase1-mutation-report` uploaded by run #50.

**Interpretation:** the current focused Phase 1 suite now detects all 18 deliberately selected critical semantic corruptions. This does not prove correctness and is not a substitute for broader mutation generation, property-based testing, seeded-defect benchmarking, real-repository evaluation, or independent external audit.

**External repository mutations:** none.

**Next:** verify the exact documentation/logbook branch head, open a hardening PR, run PR CI, and merge only if the mutation gate remains green.


---

## 2026-09-26 — Phase 1 mutation hardening merged into canonical main

**Actor:** ChatGPT / Owner-authorized repository operation

**Pull request:** #26 — `Harden Phase 1 with semantic mutation testing`

**Verified PR head:** `b9a72e5b522beca0d56a0390b6d3716b17bce8c2`

**Mutation-hardening evidence before merge:**
- first enforced mutation run #47 — FAILED by design;
- first-run mutation result: 14 killed / 5 survived / 0 specification errors;
- four survivors were genuine bundle-integrity test gaps;
- one survivor was redundant unreachable agent-assertion adjudication logic;
- redundant logic removed;
- four direct bundle-tamper tests added;
- corrected run #50 — PASS, 18/18 targeted semantic mutants killed, 0 survived;
- exact branch-head run #53 — PASS;
- pull-request run #54 — PASS.

**Merge method:** squash

**Mutation-hardening merge commit:** `9e51e93981b96827d1e843d567f6db49dd7cc8ed`

**Post-merge GitHub Actions:** run #55, run id `36226427832` — PASS.

**Canonical verified test posture after hardening:**
- repository tests: 77 passed;
- targeted Phase 1 semantic mutations: 18;
- killed: 18;
- survived: 0;
- mutation specification errors: 0;
- targeted mutation score: 100% for the configured set;
- mutation report uploaded as workflow artifact;
- Ruff correctness gate — PASS;
- Bandit medium/high gate — PASS;
- fixed runner image build — PASS;
- hardened sandbox smoke test — PASS.

**Interpretation:** the 77-test count is no longer reported as a single undifferentiated proof claim. The important added evidence is that the focused Phase 1 suite detects all 18 deliberately selected critical semantic corruptions. This remains targeted evidence, not proof of total correctness.

**Not established:** broad mutation coverage, property-based invariant coverage, seeded-defect benchmark performance, real-repository performance, independent external audit, hosted-service readiness, deployment, or production proof.

**External repository mutations:** none.

**Next canonical roadmap phase:** Phase 2 — Git / PR Intake, with Phase 1 mutation testing retained as a permanent CI regression gate.


---

## 2026-09-26 — Production value doctrine established

**Actor:** Owner + ChatGPT

**Repository:** `Mo2men1985/tau_guardian_harness`

**Branch:** `product/production-value-doctrine`

**Owner directive:** the project goal is not to pass tests. The goal is to build a real Agent Merge Gate product that eventually reaches production, performs serious work, and provides real user value. Tests must therefore be real and serve as evidence about actual product behavior rather than as vanity metrics or pipeline targets.

**Canonical changes:**
- added `Production value doctrine` to `SOURCE_OF_TRUTH.md`;
- updated `ROADMAP.md` principles so tests/CI are explicitly evidence rather than the objective;
- established production readiness and real customer value as the governing engineering target.

**Practical consequence:** future work must favor realistic integrations, adverse conditions, externally meaningful benchmarks, real repository behavior, independent evidence, reliability, security, operability, and measurable customer value. Test counts alone are not accepted as a readiness claim.

**External repository mutations:** none.

**Next:** merge this doctrine into canonical `main` and apply it to every subsequent phase.
