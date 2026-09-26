import harness


def make_test_evidence(*, exit_code=0, completed=True, timed_out=False, collected=3, passed=3, failed=0, errors=0):
    return harness.TestEvidence(
        command=["pytest"], exit_code=exit_code, completed=completed, timed_out=timed_out,
        collected=collected, passed=passed, failed=failed, errors=errors, skipped=0,
        duration_ms=1, report_sha256="a", stdout_sha256="b", stdout="", error=None,
    )


def tool(name: str, *, completed=True, findings=None, exit_code=0):
    return harness.ToolEvidence(
        tool=name, command=[name], exit_code=exit_code, completed=completed, timed_out=False,
        findings=findings or [], duration_ms=1, artifact_sha256="c", version="test", error=None,
    )


def test_pass_requires_real_tests_and_required_tools():
    result = harness.evaluate_policy(make_test_evidence(), {"ruff": tool("ruff"), "bandit": tool("bandit")})
    assert result.state == "PASS"


def test_failed_test_is_veto():
    result = harness.evaluate_policy(
        make_test_evidence(exit_code=1, passed=2, failed=1),
        {"ruff": tool("ruff"), "bandit": tool("bandit")},
    )
    assert result.state == "VETO"
    assert "FUNCTIONAL_TEST_FAILURE" in result.reason_codes


def test_zero_tests_is_abstain():
    result = harness.evaluate_policy(
        make_test_evidence(collected=0, passed=0),
        {"ruff": tool("ruff"), "bandit": tool("bandit")},
    )
    assert result.state == "ABSTAIN"


def test_missing_required_tool_is_abstain():
    result = harness.evaluate_policy(make_test_evidence(), {"ruff": tool("ruff")})
    assert result.state == "ABSTAIN"


def test_blocking_bandit_finding_is_veto():
    finding = {"issue_severity": "HIGH", "issue_confidence": "HIGH"}
    result = harness.evaluate_policy(
        make_test_evidence(),
        {"ruff": tool("ruff"), "bandit": tool("bandit", findings=[finding])},
    )
    assert result.state == "VETO"
