# Guardian Evidence Gate

Guardian Evidence Gate is an experimental, evidence-driven acceptance harness for AI-generated code.

It does **not** use a home-made reliability score. It does **not** treat model confidence, a custom scalar, or an arbitrary iteration formula as proof. A candidate can pass only when required evidence exists and the configured policy is satisfied.

## What the project does

For each generated candidate, the harness can collect:

- executable behavioral-test evidence from pytest/JUnit XML;
- Ruff diagnostics in JSON form;
- Bandit findings in JSON form;
- optional Semgrep findings;
- optional dependency-vulnerability evidence from pip-audit;
- advisory custom AST heuristics;
- model-call provenance and hashes;
- candidate/spec/test hashes;
- an explicit PASS / ABSTAIN / VETO decision with reason codes.

The repair loop is bounded by an ordinary `max_attempts` count. That count is operational bookkeeping only.

## Decision contract

### PASS

Only when all mandatory evidence is complete, tests actually ran and collected at least one test, pytest exited successfully with zero failures/errors, required scanners completed, and there are no blocking findings under the configured policy.

### VETO

Used for a demonstrated blocking failure, such as a functional regression or a confirmed blocking scanner finding.

### ABSTAIN

Used when evidence is insufficient: a required tool is missing, a scan fails, Docker is unavailable, the test run times out, no tests are collected, provenance is incomplete, or another required check cannot be established.

## Isolation model

Generated code is treated as untrusted. Sandbox execution is the default path. Host execution requires the explicit development override:

```bash
export GUARDIAN_UNSAFE_LOCAL_EXECUTION=1
```

For Docker execution, build the fixed runner image in advance:

```bash
docker build -f Dockerfile.runner -t guardian-evidence-runner:py311 .
```

The runtime container is launched without network access, with a read-only root filesystem, dropped capabilities, no-new-privileges, resource limits, a non-root user, and a temporary writable evidence mount.

Ordinary Docker is a useful containment layer, not a claim of complete isolation against fully hostile multi-tenant workloads.

## Install

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
```

Optional Semgrep support:

```bash
pip install -r requirements-security.txt
```

## Run the internal regression task suite

Local model through Ollama:

```bash
export LLM_PROVIDER=ollama
export LLM_MODEL_NAME=qwen3:8b
python auto_runs.py internal --model qwen3:8b --provider ollama --max-attempts 3
```

Cloud providers are supported through environment variables and the provider SDKs.

The 11 included tasks are an **internal regression task suite**, not a validated public benchmark.

## SWE-bench

This repository no longer maintains a second custom benchmark runner. Run the official SWE-bench / mini-SWE-agent path, preserve its native outcome artifact, then join that artifact with separate security evidence:

```bash
python analyze_mini_swe_results.py \
  --predictions preds.json \
  --instance-results instance_results.jsonl \
  --security-reports-dir security_reports \
  --model-id your-model \
  --output evaluation.jsonl
```

See `docs/SWE_BENCH.md`.

## Evidence schema

Active result records use `schema_version: "2.0"` and expose direct facts rather than a synthetic score. See `docs/EVIDENCE_SCHEMA.md`.

## Custom heuristics

`ast_security.py` contains small custom heuristic checks. They are advisory unless and until each rule is measured against labeled positive and negative fixtures. They must not be described as proving that code is secure.

Primary blocking evidence should come from executable tests and established tooling configured by policy.

## Historical results

Pre-rewrite generated result files and build dumps were removed from the active repository because they were produced under an invalid evidence model. They should not be cited as current performance proof.

## CI

The repository includes GitHub Actions checks for:

- unit/policy tests;
- patch-normalization regression tests;
- retired-concept guard;
- Ruff;
- Bandit;
- runner-image build and sandbox smoke test where Docker is available.

A release claim should point to an actual successful workflow run bound to an exact commit SHA.

## Current boundary

This is an engineering prototype for AI-code acceptance and evidence collection. It is not presented as a validated scientific metric, a proof of software security, or a production-certified commercial service.
