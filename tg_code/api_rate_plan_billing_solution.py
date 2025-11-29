def calculate_monthly_bill(calls: int, plan: str) -> float:
    """Compute the monthly bill for a simple API plan structure."""
    if calls < 0:
        raise ValueError("calls must be non-negative")

    plan = plan.lower()
    if plan == "free":
        included = 1000
        extra_rate = 0.01
        base = 0.0
    elif plan == "pro":
        included = 100_000
        extra_rate = 0.001
        base = 49.0
    elif plan == "enterprise":
        included = 5_000_000
        extra_rate = 0.2
        base = 499.0
    else:
        raise ValueError("unknown plan")

    if calls <= included:
        return float(base)

    extra = calls - included
    total = base + extra * extra_rate
    return round(total, 2)
