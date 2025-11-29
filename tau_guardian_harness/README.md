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
- Starter code in `code/`
- Tests in `tests/`
- Security rules in the `Task` definition.
