# Post-Apply Full-File Delta Security Scan

The post-apply scanner is an **advisory custom heuristic layer** for external
SWE-bench runs. It applies a model patch to a clean worktree at the benchmark
base commit, scans the full changed Python files before and after the patch, and
records only newly introduced heuristic findings.

It does not replace the official SWE-bench outcome, Bandit, Semgrep, dependency
scanning, or human security review.

## Generate advisory reports

```bash
python tg_post_apply_security_scan.py \
  --preds msa_outputs/preds.json \
  --dataset princeton-nlp/SWE-bench_Lite \
  --split test \
  --dataset-revision <exact-dataset-commit> \
  --outdir msa_outputs/security_reports \
  --only example__repo-123
```

Full run:

```bash
python tg_post_apply_security_scan.py \
  --preds msa_outputs/preds.json \
  --dataset princeton-nlp/SWE-bench_Lite \
  --split test \
  --dataset-revision <exact-dataset-commit> \
  --outdir msa_outputs/security_reports \
  --force
```

Reports use scope `postapply_fullfile_delta_v2` and contain structured fields
for patch validation, changed files, scan failures, and advisory findings.

## Join with official benchmark evidence

```bash
python analyze_mini_swe_results.py \
  --predictions msa_outputs/preds.json \
  --instance-results msa_outputs/instance_results.jsonl \
  --output msa_outputs/evaluation.jsonl \
  --security-reports-dir msa_outputs/security_reports \
  --model-id my-model
```

The official resolved/unresolved result remains independent evidence. Missing or
failed required security evidence causes ABSTAIN; it is never converted into a
synthetic success score.

The dataset revision is mandatory. Record the exact revision alongside the evaluation artifacts so later reruns use the same dataset state.
