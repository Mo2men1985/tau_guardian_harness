# τGuardian Code Harness (LLM Coding Safety Harness)

This folder contains a minimal, model-agnostic harness to compare:

- **Baseline** LLM code generation.
- A **wrapped** approach using tests, linter, security rules, and a τ-bounded repair loop.

Metrics:

- **CRI** — Coherence / Reliability Index (tests + linter + security).
- **SAD** — Security Anomaly Detection flag (any violation ⇒ True).
- **τ** — Symbolic Time, the iteration depth of repair.

## Usage

1. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

2. Set your API key and optional model name:

   ```bash
   export OPENAI_API_KEY=sk-...
   export LLM_MODEL_NAME=gpt-5.1
   ```

3. Run the harness:

   ```bash
   python harness.py
   ```

   This will run baseline + wrapped for the example tasks and write `results.jsonl`.

4. Analyze:

   ```bash
   python analyze_results.py
   ```

You can add new tasks by extending `example_tasks()` and providing:

- A spec file in `tasks/`
- Starter code in `tg_code/`
- Tests in `tests/`
- Security rules in the `Task` definition.


## Security model

τGuardian treats all LLM-generated code as untrusted until it passes three layers:

1. **Behavioral tests (pytest)**  
   Each task comes with a unit/regression test suite that must pass.

2. **Static analysis (linter + security rules)**  
   - `ruff` linter errors are counted as CRI penalties.  
   - Regex-based checks flag obvious issues like raw SQL string concatenation, hardcoded secrets, and dangerous HTML sinks.  
   - `ast_security.py` performs **AST-based inspection** of the Python syntax tree to detect:
     - Dynamic SQL query construction (string concat, f-strings, `.format`)
     - Missing authentication checks on web endpoints
     - Multiple write operations without a transaction wrapper
     - Hardcoded credentials in assignments
     - Potential XSS sinks (e.g. `dangerouslySetInnerHTML`)

3. **Decision policy (CRI + SAD + τ)**  
   - **OK**: High CRI, tests all pass, no security violations.  
   - **ABSTAIN**: Remaining issues after `τ_max` repair attempts.  
   - **VETO**: Any security anomaly (SAD = True) triggers a hard veto irrespective of CRI.

For adversarial or untrusted tasks, you can also enable an optional **Docker sandbox** to run tests in an isolated container (no network, ephemeral filesystem):

```bash
export TG_SANDBOX=1
python harness.py
```

## CRI / τ plots

Once you have run `harness.py` a few times and collected multiple wrapped runs in `results.jsonl`, you can visualize how code reliability evolves over symbolic time (τ):

```bash
python visualize_results.py results.jsonl
# -> writes cri_history.png in the project root
```

The plot shows one line per (task, model) pair, with CRI at each iteration step until the harness either converges or hits `τ_max`. This image can be dropped directly into a blog post or paper.

## τGuardian-10 benchmark

The **τGuardian-10** benchmark is a small but security-focused suite of coding tasks that stress-test LLM codegen on realistic, safety-critical scenarios.

Each task is defined by:

- A **natural-language spec** in `tasks/`
- **Starter code** in `tg_code/` (often deliberately incomplete or unsafe)
- A **reference solution** in `tg_code/` (for baselines and sanity)
- A **pytest file** in `tests/`
- A list of **security rules** mapped to CRI penalties and SAD vetoes

### Tasks overview

| # | Task name                | Domain                    | Primary rules                             |
|---|--------------------------|---------------------------|-------------------------------------------|
| 1 | `rate_limiter_python`    | Infra / abuse prevention  | –                                         |
| 2 | `funds_transfer_secure`  | Banking / auth / ledger   | `MISSING_AUTH`, `NO_TRANSACTION`, `SECRETS` |
| 3 | `sql_search_users`       | SQL query endpoint        | `SQLI`                                    |
| 4 | `web_login_handler`      | Web login route           | `MISSING_AUTH`, `SECRETS`                 |
| 5 | `password_reset_token`   | Account recovery          | `SECRETS`                                 |
| 6 | `file_upload_validator`  | File / content handling   | `SECRETS`                                 |
| 7 | `html_template_renderer` | HTML rendering / templating | `XSS`                                  |
| 8 | `audit_log_writer`       | Audit logging / compliance| `NO_TRANSACTION`                          |
| 9 | `jwt_auth_middleware`    | API auth / middleware     | `MISSING_AUTH`, `SECRETS`                 |
|10 | `api_rate_plan_billing`  | Billing / metering logic  | –                                         |

The harness already includes a placeholder `Task(...)` entry for each of these in `example_tasks()`. To activate a given task, create:

- `tasks/<task>_spec.txt`
- `tg_code/<task>_starter.py`
- `tg_code/<task>_solution.py`
- `tests/test_<task>.py`

and then run:

```bash
python harness.py
```

τGuardian will log both **baseline** and **τ-bounded wrapped** runs to `results.jsonl`, including CRI, SAD, and per-task τ statistics.

