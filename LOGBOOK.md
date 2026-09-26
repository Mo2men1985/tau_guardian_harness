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
