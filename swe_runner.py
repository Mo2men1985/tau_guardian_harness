"""Deprecated custom SWE execution path.

The project no longer implements a second benchmark runner. Use the official
SWE-bench / mini-SWE-agent execution path, retain its native resolved outcome,
and join that artifact with separate evidence using analyze_mini_swe_results.py.
"""


def main() -> None:
    raise SystemExit(
        "Custom SWE execution has been retired. Use official SWE-bench/mini-SWE-agent artifacts "
        "and analyze_mini_swe_results.py."
    )


if __name__ == "__main__":
    main()
