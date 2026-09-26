# SWE-bench integration

The project deliberately does not implement its own competing benchmark executor.

1. Run the official SWE-bench or mini-SWE-agent evaluation path.
2. Preserve the original predictions and official instance result artifact.
3. Optionally run separate post-apply security tooling.
4. Join the artifacts with `analyze_mini_swe_results.py`.

The official resolved/unresolved outcome remains separate from security evidence. The project does not convert a resolved instance into a fake one-test pytest result.

Patch text is normalized only to remove outer prose/fences. Diff prefixes and indentation are preserved exactly, and patches should be validated with `git apply --check` before application.
