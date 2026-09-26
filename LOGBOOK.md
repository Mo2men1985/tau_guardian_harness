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
