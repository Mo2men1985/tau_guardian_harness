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


---

## 2026-09-26 — Phase 2 real Git intake implementation

**Actor:** ChatGPT / Owner-authorized repository operation

**Repository:** `Mo2men1985/tau_guardian_harness`

**Branch:** `product/phase2-real-pr-intake`

**Starting main commit:** `ef47a04f154641e5574a770e891325bb365e28bc`

**Production objective:** establish the first real vertical slice from an actual Git candidate into the Phase-1 audit-target identity. The target is real repository behavior, not an isolated parser or an increased test count.

**Implemented:**
- exact Git ref-to-commit resolution;
- PR-style merge-base calculation;
- deterministic binary-capable full-index diff hashing;
- real changed-file inventory from Git;
- exact candidate-tree inventory;
- changed-file language detection;
- candidate dependency-manifest inventory;
- root framework detection for initial Python/JavaScript cases;
- migration, infrastructure and security-sensitive path detection;
- deterministic change classification;
- non-executing test-command discovery;
- direct construction of the Phase-1 `AuditTarget`;
- canonical JSON intake artifact with no timestamps;
- CLI for real repository execution;
- real Git integration tests using actual temporary Git repositories, commits and diverged base/head histories;
- GitHub Actions full-history checkout;
- pull-request-only normalization of exact GitHub base/head SHAs;
- upload of `phase2-pr-intake` machine-readable evidence artifact.

**Branch verification:** GitHub Actions run #72, run id `36227195301` — PASS.

**Observed repository test result:** 81 passed on the Phase-2 branch.

**Phase-1 mutation regression gate:** 18/18 targeted semantic mutants killed.

**Governance corrections:**
- removed stale working-branch metadata from `SOURCE_OF_TRUTH.md`;
- updated the immediate roadmap step from Phase 1 to Phase 2;
- documented that `main` branch protection remains disabled.

**Branch-protection limitation:** the connected GitHub capability does not expose repository-administration write access, so branch protection / required-status-check enforcement could not be enabled from this session. This remains an explicit governance gap rather than being represented as fixed.

**External repository mutations:** none.

**Phase status:** IN PROGRESS.

**Next:** open the Phase-2 pull request. That PR itself must be processed by the new real-PR intake step, producing a machine-readable artifact bound to its exact base/head commits. Phase 2 will not be called complete until that real PR path is verified.


---

## 2026-09-26 — Phase 2 real Git / PR intake completed

**Actor:** ChatGPT / Owner-authorized repository operation

**Pull request:** #28 — `Implement Phase 2 real Git and PR intake`

**Verified final PR head:** `9e0050107b99654fa59846c1b2ae9c1e3b19e147`

**GitHub base SHA:** `ef47a04f154641e5574a770e891325bb365e28bc`

**Real PR intake evidence:**
- pull-request workflow run #76, run id `36227338848` — PASS;
- exact PR intake step — PASS;
- machine-readable `phase2-pr-intake` artifact — generated;
- resolved repository: `Mo2men1985/tau_guardian_harness`;
- resolved base SHA: `ef47a04f154641e5574a770e891325bb365e28bc`;
- resolved candidate SHA: `9e0050107b99654fa59846c1b2ae9c1e3b19e147`;
- merge-base SHA: `ef47a04f154641e5574a770e891325bb365e28bc`;
- canonical diff SHA-256: `033df49bb248da9835b96848e3cd66a01ecbf8449d414412719457ee98feccf6`;
- changed files: 9;
- classifications: `BUSINESS_LOGIC`, `INFRA`;
- dependency manifests: `pyproject.toml`, `requirements.txt`;
- discovered test command: `python -m pytest -q`.

**Determinism rerun:** the same exact PR head was rerun as workflow attempt 2.

The two independently produced internal `pr-intake.json` files were byte-identical.

**Canonical intake JSON SHA-256:** `851caaf2db746fd097eb572b44292b8ece933f6fb9c8a4b36868818579d50093`

The outer ZIP artifact digests differed because workflow artifact archives contain packaging metadata; determinism was evaluated on the canonical JSON payload itself, not the ZIP wrapper.

**Repository test result on Phase-2 implementation:** 81 passed.

**Phase-1 targeted mutation regression:** 18/18 killed, 0 survived.

**Merge method:** squash

**Phase-2 merge commit:** `bedf14d49171a72e7b3c83acfd2200b890e0617e`

**Post-merge GitHub Actions:** run #77 — PASS.

**Governance limitation retained:** `main` branch protection remains disabled because repository-administration write access is unavailable through the connected GitHub capability. This is not considered resolved.

**External repository mutations:** none.

**Canonical Phase 2 status:** IMPLEMENTED + REAL-GIT INTEGRATION TESTED + REAL-PR VERIFIED + DETERMINISM VERIFIED + CI VERIFIED.

**Not established:** forked-PR compatibility across all GitHub topologies, broad monorepo discovery, deterministic evidence collection, semantic auditing, defect-detection advantage, deployment, or production proof.

**Next canonical roadmap phase:** Phase 3 — deterministic evidence vertical slice from the exact PR candidate into a real Evidence Bundle and verdict.


---

## 2026-09-26 — Phase 3 deterministic evidence implementation started

**Actor:** ChatGPT / Owner-authorized repository operation

**Repository:** `Mo2men1985/tau_guardian_harness`

**Branch:** `product/phase3-deterministic-evidence`

**Starting main commit:** `b80ad00d04cbd3ce7db28e5be9d31afcf74c88d6`

**Production objective:** make one real pull request flow from exact Git identity through isolated deterministic execution into trusted Phase-1 evidence, a hash-bound Evidence Bundle, and an enforceable PASS / ABSTAIN / VETO verdict.

**Implemented on branch:**
- exact-candidate materialization via `git archive`;
- safe archive extraction rejecting traversal, links, and special members;
- fixed non-root Docker runner with pinned pytest/Ruff/Bandit/PyYAML/defusedxml tooling and Git;
- network-disabled, read-only, capability-dropped candidate execution;
- dedicated ephemeral JUnit evidence mount;
- explicit pytest policy targeting `tests/` and overriding candidate `addopts`;
- isolated Ruff correctness rules independent of candidate configuration;
- structured Bandit collection with medium/high severity+confidence blocking policy;
- candidate-bound deterministic `EvidenceRecord` construction;
- dynamic minimal locked criteria for applicable evidence;
- Phase-1 Evidence Bundle creation and verdict mapping;
- raw intake/JUnit/stdout/Ruff/Bandit/execution/bundle artifact retention;
- PR workflow upload before verdict enforcement;
- unit/integration tests for exact Git snapshot materialization and evidence semantics;
- `docs/PHASE3_DETERMINISTIC_EVIDENCE.md`.

**Important trust limitation:** this repository dogfoods its own workflow and runner-image definition. That is useful controlled end-to-end evidence, but it is not proof of safe orchestration for arbitrary customer-controlled repositories. A hosted production service must keep orchestration and trusted runner images outside candidate control.

**External repository mutations:** none.

**Phase status:** IN PROGRESS.

**Completion condition:** a real PR must execute the exact candidate in the hardened runner, retain real structured artifacts, create a candidate-bound Evidence Bundle, produce an adjudicated verdict, and demonstrate materially reproducible evidence on rerun.


---

## 2026-09-26 — Phase 3 first real PR evidence exposed incomplete static-tool transport

**Actor:** ChatGPT / evidence-gate execution

**Pull request:** #30 — `Implement Phase 3 deterministic evidence vertical slice`

**First real PR candidate:** `01e18b7110f5a2eebdeec8f79846ac2c4d39b9fd`

**Observed evidence:**
- exact candidate executed in the fixed isolated runner;
- pytest: 91 collected / 91 passed / 0 failed / 0 errors;
- pytest criterion: PASS;
- Ruff criterion: ABSTAIN;
- Bandit criterion: ABSTAIN;
- overall verdict: ABSTAIN.

**Root causes:**
1. Ruff attempted to initialize its cache under the read-only candidate workspace, causing exit code 2 and incomplete structured evidence.
2. Bandit emitted diagnostic warnings on stderr, but the generic runner merged stderr into stdout, contaminating the JSON artifact and making parsing fail.

**Response:** the policy was not weakened and the ABSTAIN was not converted manually.

**Remediation:**
- moved Ruff cache to isolated container tmpfs;
- separated structured-tool stdout and stderr;
- retained stderr as its own hashed artifact;
- moved pytest cache to tmpfs;
- reran the same real PR path.

**Corrected evidence on later candidate `edaddb15dfd25c3a8895b8c8a7e669babc2e74b9`:**
- pytest: 91/91 PASS;
- Ruff: valid structured JSON, 0 findings, criterion PASS;
- Bandit: valid structured JSON, 8 low-severity findings, 0 blocking findings, criterion PASS;
- overall deterministic Evidence Bundle verdict: PASS.

**Reproducibility observation:** two independent executions of that exact candidate produced the same candidate/diff/archive identity, test counts, tool versions, Ruff findings, Bandit findings/blocking set, criteria decisions, and overall PASS, but exact bundle hashes differed due run-local image IDs, timings and timestamp-bearing artifacts.

**Follow-up:** a separate semantic evidence fingerprint was added so substantive reproducibility is measured without discarding exact per-run provenance.

**External repository mutations:** none.

**Phase status:** IN PROGRESS pending final exact-head PASS and matching semantic fingerprints across independent reruns.


---

## 2026-09-26 — Phase 3 deterministic evidence vertical slice completed

**Actor:** ChatGPT / Owner-authorized repository operation

**Pull request:** #30 — `Implement Phase 3 deterministic evidence vertical slice`

**Final verified PR candidate:** `72593cb4f5d717dd29a378437966bf52475a4e2c`

**Base SHA:** `b80ad00d04cbd3ce7db28e5be9d31afcf74c88d6`

**Real PR workflow:** run #115, run id `36230023445` — PASS.

**Final real deterministic evidence:**
- exact candidate archive SHA-256: `19a2a656e51c1d7d5fc48783f554dc21e0e7354067c6a6da4be8528b839d3306`;
- diff SHA-256: `8f4e9fb98ec1c03769eb5d6234a6e537a5a6ad8e2dd1dc8357e42625bdd26a5b`;
- pytest: 93 collected / 93 passed / 0 failed / 0 errors / 0 skipped;
- Ruff: structured evidence complete, 0 findings;
- Bandit: structured evidence complete, 8 low-severity findings, 0 blocking medium/high severity+confidence findings;
- all three locked deterministic criteria: PASS;
- overall Evidence Bundle verdict: PASS;
- runner spec SHA-256: `044d0f54fee7e028040f96a6d02f3bd05035fc7ad595dcb5b1c5d0555d7acb66`.

**Independent rerun evidence:** two executions of the exact candidate produced the same substantive semantic evidence and the same semantic fingerprint:

`0a934a2533d2e33448580aa54162475a98b24e572919095d0f149d8883e505db`

The exact Evidence Bundle hashes differed (`22ec246e...` vs `3d679519...`) because exact run provenance intentionally includes run-local data such as timing and timestamp-bearing JUnit output. This is not represented as byte-identical full-run reproducibility. Semantic reproducibility is measured separately and matched exactly.

**Merge commit:** `df7ac3dda872dc3b64decd8514150c11f1ed7c84` (signed/verified).

**Post-merge main CI:** run #116, run id `36230239928` — PASS.

**What Phase 3 proves:** for the controlled Python repository topology, a real PR can flow from exact Git identity through isolated deterministic execution into retained pytest/Ruff/Bandit evidence, trusted candidate-bound EvidenceRecords, locked criteria, a hash-bound Evidence Bundle, and an enforced PASS/ABSTAIN/VETO decision.

**What Phase 3 does not prove:** arbitrary customer-repository safety, semantic/business-logic correctness, independence of candidate-supplied tests, defect-detection advantage over ordinary CI, forked-PR compatibility, broad language/framework support, production deployment, or commercial value.

**Governance gap retained:** `main` remains unprotected because repository-administration write access is unavailable through the connected capability.

**External repository mutations:** none.

**Canonical Phase 3 status:** COMPLETE FOR CONTROLLED PYTHON VERTICAL SLICE.

**Next:** early controlled defect baseline. Measure whether the deterministic gate catches meaningful seeded defects that ordinary CI misses before expanding the semantic-auditor architecture.
