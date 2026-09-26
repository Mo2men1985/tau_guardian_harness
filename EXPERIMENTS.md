# Experiments and Reporting Plan

## Internal regression suite

The included 11 tasks are engineering fixtures for regression testing. They are not described as a validated benchmark.

For each model/task/config, report direct outcomes:

- first-attempt PASS rate;
- repair success conditional on an initial non-PASS outcome;
- attempt count;
- model calls, latency, token usage when available;
- functional failures;
- scanner/tool failures;
- blocking findings;
- infrastructure failure rate.

For comparative experiments, freeze the task set and prompts, record model/provider versions and parameters, repeat trials, and report uncertainty rather than a home-made scalar.

## External benchmarks

Use externally maintained benchmarks through their official evaluation harness. Keep their native outcome fields intact and report local security evidence separately.

## Claims discipline

A historical run is not proof unless its candidate, task inputs, tool outputs, environment, and exact code revision are bound by hashes or equivalent immutable identifiers.
