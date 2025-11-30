import os
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from tg_code.api_rate_plan_billing_solution import calculate_monthly_bill


def test_free_plan_under_limit():
    assert calculate_monthly_bill(500, "free") == 0.0
    assert calculate_monthly_bill(1000, "free") == 0.0


def test_free_plan_over_limit():
    assert calculate_monthly_bill(1001, "free") == 0.01
    assert calculate_monthly_bill(1500, "free") == 5.0


def test_pro_plan_base_and_overage():
    assert calculate_monthly_bill(50_000, "pro") == 49.0
    assert calculate_monthly_bill(100_000, "pro") == 49.0
    assert calculate_monthly_bill(100_100, "pro") == 49.10


def test_enterprise_plan():
    assert calculate_monthly_bill(5_000_000, "enterprise") == 499.0
    assert calculate_monthly_bill(5_000_100, "enterprise") == 519.0


def test_invalid_inputs():
    try:
        calculate_monthly_bill(-1, "free")
    except ValueError:
        pass
    else:
        assert False, "Expected ValueError for negative calls"

    try:
        calculate_monthly_bill(1000, "unknown")
    except ValueError:
        pass
    else:
        assert False, "Expected ValueError for unknown plan"

