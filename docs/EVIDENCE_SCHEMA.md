# Evidence Schema v2

Every active result record declares `schema_version: "2.0"`.

The schema is intentionally factual. It records execution outcomes and provenance rather than collapsing unrelated evidence into a synthetic score.

Core fields include:

```json
{
  "schema_version": "2.0",
  "model": "...",
  "task": "...",
  "candidate_identity": {
    "repo_commit_sha": "...",
    "candidate_sha256": "...",
    "task_spec_sha256": "...",
    "starter_sha256": "...",
    "tests_sha256": "...",
    "policy_version": "evidence-gate-v2"
  },
  "tests": {
    "exit_code": 0,
    "completed": true,
    "timed_out": false,
    "collected": 42,
    "passed": 42,
    "failed": 0,
    "errors": 0,
    "skipped": 0,
    "report_sha256": "..."
  },
  "tools": {
    "ruff": {"completed": true, "findings": []},
    "bandit": {"completed": true, "findings": []}
  },
  "decision": {
    "state": "PASS",
    "reason_codes": [
      "ALL_REQUIRED_TESTS_PASS",
      "NO_BLOCKING_FINDINGS",
      "REQUIRED_EVIDENCE_COMPLETE"
    ]
  }
}
```

A required tool that fails, times out, or is absent results in ABSTAIN. A demonstrated blocking failure results in VETO. PASS requires complete mandatory evidence.
