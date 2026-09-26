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
