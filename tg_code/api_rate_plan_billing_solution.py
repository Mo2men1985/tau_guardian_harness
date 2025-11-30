"""Reference implementation for API rate plan billing.

The billing model matches the test expectations:

* ``free`` plan: first 1,000 calls are free, overage is $0.01 per call.
* ``pro`` plan: flat $49 covers up to 100,000 calls, overage is $0.001 per
  call.
* ``enterprise`` plan: flat $499 covers up to 5,000,000 calls, overage is
  $0.20 per call.

Validation mirrors the tests: negative call counts and unknown plans raise a
``ValueError``.
"""

from __future__ import annotations


def calculate_monthly_bill(calls: int, plan: str) -> float:
    if calls < 0:
        raise ValueError("calls must be non-negative")

    plan = plan.lower()

    if plan == "free":
        included = 1000
        overage_rate = 0.01
        overage_calls = max(0, calls - included)
        return round(overage_calls * overage_rate, 2)

    if plan == "pro":
        base_fee = 49.0
        included = 100_000
        overage_rate = 0.001
        overage_calls = max(0, calls - included)
        return round(base_fee + overage_calls * overage_rate, 2)

    if plan == "enterprise":
        base_fee = 499.0
        included = 5_000_000
        overage_rate = 0.20
        overage_calls = max(0, calls - included)
        return round(base_fee + overage_calls * overage_rate, 2)

    raise ValueError("unknown plan")
