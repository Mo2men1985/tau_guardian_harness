from pathlib import Path
from harness import _pytest_counts_from_junit


def test_junit_mixed_failure_is_not_misread_as_pass(tmp_path: Path):
    report = tmp_path / "report.xml"
    report.write_text(
        '<testsuites><testsuite tests="2" failures="1" errors="0" skipped="0"></testsuite></testsuites>',
        encoding="utf-8",
    )
    collected, passed, failed, errors, skipped = _pytest_counts_from_junit(report)
    assert (collected, passed, failed, errors, skipped) == (2, 1, 1, 0, 0)
