from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from defusedxml import ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple

from ast_security import run_custom_heuristic_checks
from docker_sandbox import run_tests_in_sandbox
from llm_client import ModelCallEvidence, generate_code_with_evidence_from_env

SCHEMA_VERSION = "2.0"
POLICY_VERSION = "evidence-gate-v2"
DecisionState = Literal["PASS", "ABSTAIN", "VETO"]


@dataclass(frozen=True)
class Task:
    name: str
    description_path: str
    starter_path: str
    solution_path: str
    tests_path: str
    security_rules: List[str]
    language: str = "python"


@dataclass
class TestEvidence:
    command: List[str]
    exit_code: int
    completed: bool
    timed_out: bool
    collected: int
    passed: int
    failed: int
    errors: int
    skipped: int
    duration_ms: int
    report_sha256: Optional[str]
    stdout_sha256: str
    stdout: str = field(repr=False, default="")
    error: Optional[str] = None


@dataclass
class ToolEvidence:
    tool: str
    command: List[str]
    exit_code: Optional[int]
    completed: bool
    timed_out: bool
    findings: List[Dict[str, Any]]
    duration_ms: int
    artifact_sha256: Optional[str]
    version: Optional[str] = None
    error: Optional[str] = None


@dataclass
class CandidateIdentity:
    repo_commit_sha: Optional[str]
    candidate_sha256: str
    task_spec_sha256: str
    starter_sha256: str
    tests_sha256: str
    policy_version: str = POLICY_VERSION


@dataclass
class EvaluationDecision:
    state: DecisionState
    reason_codes: List[str]


@dataclass
class AttemptRecord:
    attempt_index: int
    code_path: str
    model_call: ModelCallEvidence
    identity: CandidateIdentity
    tests: TestEvidence
    tools: Dict[str, ToolEvidence]
    custom_heuristic_findings: List[str]
    decision: EvaluationDecision


@dataclass
class BaselineResult:
    model_name: str
    task_name: str
    attempt: AttemptRecord


@dataclass
class WrappedResult:
    model_name: str
    task_name: str
    attempts: List[AttemptRecord]
    final_decision: EvaluationDecision
    final_code_path: Optional[str]


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def _sha256_file(path: str | Path) -> str:
    return _sha256_bytes(Path(path).read_bytes())


def read_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def write_file(path: str, content: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _repo_commit_sha() -> Optional[str]:
    env_sha = os.getenv("GITHUB_SHA")
    if env_sha:
        return env_sha
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=5,
        )
        if proc.returncode == 0:
            value = proc.stdout.strip()
            return value or None
    except Exception:
        return None
    return None


def build_candidate_identity(task: Task, candidate_text: str) -> CandidateIdentity:
    return CandidateIdentity(
        repo_commit_sha=_repo_commit_sha(),
        candidate_sha256=_sha256_text(candidate_text),
        task_spec_sha256=_sha256_file(task.description_path),
        starter_sha256=_sha256_file(task.starter_path),
        tests_sha256=_sha256_file(task.tests_path),
    )


def run_shell_command(
    cmd: Sequence[str], cwd: Optional[str] = None, timeout: int = 60
) -> Tuple[int, str]:
    """Compatibility helper used by auxiliary scripts.

    New policy decisions must not rely on parsing this text. Structured runners
    below preserve exit codes and machine-readable artifacts.
    """
    try:
        proc = subprocess.run(
            list(cmd),
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout
    except subprocess.TimeoutExpired:
        return 124, f"[ERROR] command timed out after {timeout}s"
    except FileNotFoundError as exc:
        return 127, f"[ERROR] command not found: {cmd[0]} ({exc})"


def _pytest_counts_from_junit(path: Path) -> Tuple[int, int, int, int, int]:
    """Return collected, passed, failed, errors, skipped from JUnit XML."""
    root = ET.parse(path).getroot()
    suites: Iterable[Any]
    if root.tag == "testsuite":
        suites = [root]
    else:
        suites = root.findall(".//testsuite")

    tests = failures = errors = skipped = 0
    for suite in suites:
        tests += int(suite.attrib.get("tests", "0") or 0)
        failures += int(suite.attrib.get("failures", "0") or 0)
        errors += int(suite.attrib.get("errors", "0") or 0)
        skipped += int(suite.attrib.get("skipped", "0") or 0)
    passed = max(0, tests - failures - errors - skipped)
    return tests, passed, failures, errors, skipped


def _run_pytest_host(test_path: str, timeout: int = 120) -> TestEvidence:
    report_fd, report_name = tempfile.mkstemp(prefix="guardian-pytest-", suffix=".xml")
    os.close(report_fd)
    report_path = Path(report_name)
    cmd = ["pytest", "-q", test_path, f"--junitxml={report_path}"]
    started = time.monotonic()
    timed_out = False
    error: Optional[str] = None
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=timeout,
        )
        exit_code = proc.returncode
        output = proc.stdout
        completed = True
    except subprocess.TimeoutExpired as exc:
        exit_code = 124
        output = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        completed = False
        timed_out = True
        error = f"pytest timed out after {timeout}s"
    except FileNotFoundError as exc:
        exit_code = 127
        output = str(exc)
        completed = False
        error = "pytest executable not found"

    duration_ms = int((time.monotonic() - started) * 1000)
    collected = passed = failed = errors = skipped = 0
    report_hash: Optional[str] = None
    if report_path.exists() and report_path.stat().st_size:
        report_hash = _sha256_file(report_path)
        try:
            collected, passed, failed, errors, skipped = _pytest_counts_from_junit(report_path)
        except Exception as exc:
            completed = False
            error = f"invalid JUnit XML: {exc}"
    else:
        completed = False
        if error is None:
            error = "pytest did not produce JUnit XML"
    try:
        report_path.unlink(missing_ok=True)
    except OSError:
        pass

    return TestEvidence(
        command=cmd,
        exit_code=exit_code,
        completed=completed,
        timed_out=timed_out,
        collected=collected,
        passed=passed,
        failed=failed,
        errors=errors,
        skipped=skipped,
        duration_ms=duration_ms,
        report_sha256=report_hash,
        stdout_sha256=_sha256_text(output),
        stdout=output,
        error=error,
    )


def run_tests_for_task(task: Task, timeout: int = 120) -> TestEvidence:
    """Run candidate tests with isolation by default.

    Set GUARDIAN_UNSAFE_LOCAL_EXECUTION=1 only for a trusted development
    environment. If the sandbox is unavailable, this function returns incomplete
    evidence; policy evaluation will ABSTAIN rather than silently run untrusted
    code on the host.
    """
    if os.getenv("GUARDIAN_UNSAFE_LOCAL_EXECUTION", "0") == "1":
        return _run_pytest_host(task.tests_path, timeout=timeout)

    project_root = str(Path(__file__).resolve().parent)
    sandbox = run_tests_in_sandbox(task.tests_path, project_root, timeout=timeout)
    return TestEvidence(
        command=sandbox.command,
        exit_code=sandbox.exit_code,
        completed=sandbox.completed,
        timed_out=sandbox.timed_out,
        collected=sandbox.collected,
        passed=sandbox.passed,
        failed=sandbox.failed,
        errors=sandbox.errors,
        skipped=sandbox.skipped,
        duration_ms=sandbox.duration_ms,
        report_sha256=sandbox.report_sha256,
        stdout_sha256=sandbox.stdout_sha256,
        stdout=sandbox.stdout,
        error=sandbox.error,
    )


def _tool_version(executable: str) -> Optional[str]:
    try:
        proc = subprocess.run(
            [executable, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=10,
        )
        line = proc.stdout.strip().splitlines()
        return line[0] if line else None
    except Exception:
        return None


def _run_json_tool(
    tool: str,
    cmd: List[str],
    parser,
    cwd: Optional[str] = None,
    timeout: int = 120,
    acceptable_exit_codes: Sequence[int] = (0, 1),
) -> ToolEvidence:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=timeout,
        )
        output = proc.stdout
        completed = proc.returncode in acceptable_exit_codes
        error = None if completed else f"{tool} exited with code {proc.returncode}"
        findings: List[Dict[str, Any]] = []
        if completed:
            try:
                findings = parser(output)
            except Exception as exc:
                completed = False
                error = f"unable to parse {tool} structured output: {exc}"
        return ToolEvidence(
            tool=tool,
            command=cmd,
            exit_code=proc.returncode,
            completed=completed,
            timed_out=False,
            findings=findings,
            duration_ms=int((time.monotonic() - started) * 1000),
            artifact_sha256=_sha256_text(output),
            version=_tool_version(cmd[0]),
            error=error,
        )
    except subprocess.TimeoutExpired:
        return ToolEvidence(
            tool=tool,
            command=cmd,
            exit_code=124,
            completed=False,
            timed_out=True,
            findings=[],
            duration_ms=int((time.monotonic() - started) * 1000),
            artifact_sha256=None,
            version=_tool_version(cmd[0]),
            error=f"{tool} timed out after {timeout}s",
        )
    except FileNotFoundError:
        return ToolEvidence(
            tool=tool,
            command=cmd,
            exit_code=127,
            completed=False,
            timed_out=False,
            findings=[],
            duration_ms=int((time.monotonic() - started) * 1000),
            artifact_sha256=None,
            version=None,
            error=f"{tool} executable not found",
        )


def _parse_json_list(output: str) -> List[Dict[str, Any]]:
    data = json.loads(output or "[]")
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    raise ValueError("expected a JSON list")


def _parse_bandit(output: str) -> List[Dict[str, Any]]:
    data = json.loads(output or "{}")
    results = data.get("results", []) if isinstance(data, dict) else []
    return [x for x in results if isinstance(x, dict)]


def _parse_semgrep(output: str) -> List[Dict[str, Any]]:
    data = json.loads(output or "{}")
    results = data.get("results", []) if isinstance(data, dict) else []
    return [x for x in results if isinstance(x, dict)]


def _parse_pip_audit(output: str) -> List[Dict[str, Any]]:
    data = json.loads(output or "[]")
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict) and x.get("vulns")]
    if isinstance(data, dict):
        deps = data.get("dependencies", [])
        return [x for x in deps if isinstance(x, dict) and x.get("vulns")]
    raise ValueError("unexpected pip-audit JSON")


def run_tools_for_task(task: Task) -> Dict[str, ToolEvidence]:
    if task.language != "python":
        return {}
    target = task.solution_path
    return {
        "ruff": _run_json_tool(
            "ruff",
            ["ruff", "check", "--output-format=json", target],
            _parse_json_list,
            acceptable_exit_codes=(0, 1),
        ),
        "bandit": _run_json_tool(
            "bandit",
            ["bandit", "-q", "-f", "json", target],
            _parse_bandit,
            acceptable_exit_codes=(0, 1),
        ),
        "semgrep": _run_json_tool(
            "semgrep",
            ["semgrep", "--json", "--config", "auto", target],
            _parse_semgrep,
            acceptable_exit_codes=(0, 1),
        ),
        "pip-audit": _run_json_tool(
            "pip-audit",
            ["pip-audit", "-f", "json"],
            _parse_pip_audit,
            acceptable_exit_codes=(0, 1),
        ),
    }


def _blocking_findings(tool: ToolEvidence) -> List[Dict[str, Any]]:
    if tool.tool == "ruff":
        # Ruff is a correctness/lint gate: any configured diagnostic blocks.
        return tool.findings
    if tool.tool == "bandit":
        return [
            f
            for f in tool.findings
            if str(f.get("issue_severity", "")).upper() in {"HIGH", "MEDIUM"}
            and str(f.get("issue_confidence", "")).upper() in {"HIGH", "MEDIUM"}
        ]
    if tool.tool == "semgrep":
        blocking: List[Dict[str, Any]] = []
        for f in tool.findings:
            sev = str((f.get("extra") or {}).get("severity", "")).upper()
            if sev in {"ERROR", "HIGH", "CRITICAL"}:
                blocking.append(f)
        return blocking
    if tool.tool == "pip-audit":
        return tool.findings
    return []


def evaluate_policy(
    tests: TestEvidence,
    tools: Dict[str, ToolEvidence],
    *,
    required_tools: Sequence[str] = ("ruff", "bandit"),
) -> EvaluationDecision:
    reasons: List[str] = []

    if not tests.completed:
        return EvaluationDecision("ABSTAIN", ["TEST_EXECUTION_INCOMPLETE"])
    if tests.timed_out:
        return EvaluationDecision("ABSTAIN", ["TEST_TIMEOUT"])
    if tests.collected <= 0:
        return EvaluationDecision("ABSTAIN", ["NO_TESTS_COLLECTED"])
    if tests.failed > 0 or tests.errors > 0 or tests.exit_code != 0:
        return EvaluationDecision("VETO", ["FUNCTIONAL_TEST_FAILURE"])

    for name in required_tools:
        ev = tools.get(name)
        if ev is None or not ev.completed:
            reasons.append(f"REQUIRED_TOOL_INCOMPLETE:{name}")
    if reasons:
        return EvaluationDecision("ABSTAIN", reasons)

    blocking: List[str] = []
    for name, ev in tools.items():
        for _ in _blocking_findings(ev):
            blocking.append(f"BLOCKING_FINDING:{name}")
    if blocking:
        return EvaluationDecision("VETO", sorted(set(blocking)))

    return EvaluationDecision(
        "PASS",
        ["ALL_REQUIRED_TESTS_PASS", "NO_BLOCKING_FINDINGS", "REQUIRED_EVIDENCE_COMPLETE"],
    )


def build_prompt_for_task(
    task: Task,
    is_repair: bool,
    previous_code: Optional[str],
    previous_attempt: Optional[AttemptRecord],
) -> str:
    spec = read_file(task.description_path)
    starter = read_file(task.starter_path)
    if not is_repair:
        return (
            f"Task: {task.name}\nLanguage: {task.language}\n\n"
            f"Specification:\n{spec}\n\n"
            f"Starter code:\n```{task.language}\n{starter}\n```\n\n"
            "Write a complete working solution in one file. Return only the final code."
        )

    assert previous_code is not None and previous_attempt is not None
    tool_summary = {
        name: {
            "completed": ev.completed,
            "exit_code": ev.exit_code,
            "findings": ev.findings,
            "error": ev.error,
        }
        for name, ev in previous_attempt.tools.items()
    }
    return (
        f"Task: {task.name}\nLanguage: {task.language}\n\n"
        f"Specification:\n{spec}\n\n"
        f"Previous candidate:\n```{task.language}\n{previous_code}\n```\n\n"
        f"Pytest output:\n{previous_attempt.tests.stdout}\n\n"
        f"Structured tool evidence:\n{json.dumps(tool_summary, ensure_ascii=False)}\n\n"
        "Repair the candidate to satisfy the specification and the concrete evidence above. "
        "Return only the corrected code."
    )


def extract_code_from_response(text: str) -> str:
    """Extract one fenced code block without rewriting its internal whitespace."""
    if not text:
        return ""
    stripped = text.strip()
    if stripped.startswith("```"):
        first_nl = stripped.find("\n")
        if first_nl != -1:
            body = stripped[first_nl + 1 :]
            if body.endswith("```"):
                body = body[:-3]
            return body.strip("\n") + "\n"
    return stripped + ("" if stripped.endswith("\n") else "\n")


def _evaluate_candidate(task: Task, attempt_index: int, model_call: ModelCallEvidence, code: str) -> AttemptRecord:
    write_file(task.solution_path, code)
    identity = build_candidate_identity(task, code)
    tests = run_tests_for_task(task)
    tools = run_tools_for_task(task)
    custom_findings = run_custom_heuristic_checks(code, task.security_rules)
    decision = evaluate_policy(tests, tools)
    return AttemptRecord(
        attempt_index=attempt_index,
        code_path=task.solution_path,
        model_call=model_call,
        identity=identity,
        tests=tests,
        tools=tools,
        custom_heuristic_findings=custom_findings,
        decision=decision,
    )


def run_baseline(model_name: str, task: Task) -> BaselineResult:
    prompt = build_prompt_for_task(task, False, None, None)
    model_call = generate_code_with_evidence_from_env(prompt, model_name=model_name)
    code = extract_code_from_response(model_call.text)
    attempt = _evaluate_candidate(task, 1, model_call, code)
    return BaselineResult(model_name=model_name, task_name=task.name, attempt=attempt)


def run_wrapped(model_name: str, task: Task, max_attempts: int = 3) -> WrappedResult:
    attempts: List[AttemptRecord] = []
    previous_code: Optional[str] = None
    previous_attempt: Optional[AttemptRecord] = None

    for attempt_index in range(1, max_attempts + 1):
        prompt = build_prompt_for_task(
            task,
            is_repair=attempt_index > 1,
            previous_code=previous_code,
            previous_attempt=previous_attempt,
        )
        model_call = generate_code_with_evidence_from_env(prompt, model_name=model_name)
        code = extract_code_from_response(model_call.text)
        current = _evaluate_candidate(task, attempt_index, model_call, code)
        attempts.append(current)
        previous_code = code
        previous_attempt = current
        if current.decision.state in {"PASS", "VETO"}:
            break

    if attempts:
        final = attempts[-1].decision
        path = attempts[-1].code_path
    else:
        final = EvaluationDecision("ABSTAIN", ["NO_ATTEMPT_EXECUTED"])
        path = None
    return WrappedResult(
        model_name=model_name,
        task_name=task.name,
        attempts=attempts,
        final_decision=final,
        final_code_path=path,
    )


def _tool_to_dict(ev: ToolEvidence) -> Dict[str, Any]:
    return asdict(ev)


def summarize_attempt(attempt: AttemptRecord) -> Dict[str, Any]:
    return {
        "attempt_index": attempt.attempt_index,
        "candidate_identity": asdict(attempt.identity),
        "model_call": asdict(attempt.model_call),
        "tests": {k: v for k, v in asdict(attempt.tests).items() if k != "stdout"},
        "tools": {name: _tool_to_dict(ev) for name, ev in attempt.tools.items()},
        "custom_heuristic_findings": attempt.custom_heuristic_findings,
        "decision": asdict(attempt.decision),
    }


def summarize_baseline(result: BaselineResult) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "model": result.model_name,
        "task": result.task_name,
        "type": "baseline",
        **summarize_attempt(result.attempt),
    }


def summarize_wrapped(result: WrappedResult) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "model": result.model_name,
        "task": result.task_name,
        "type": "repair_loop",
        "attempts": [summarize_attempt(a) for a in result.attempts],
        "attempt_count": len(result.attempts),
        "final_decision": asdict(result.final_decision),
    }


def write_results_jsonl(path: str, records: List[Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n")


def example_tasks() -> List[Task]:
    here = Path(__file__).resolve().parent
    defs = [
        ("rate_limiter_python", "rate_limiter", []),
        ("funds_transfer_secure", "funds_transfer", ["NO_TRANSACTION"]),
        ("sql_search_users", "sql_search_users", ["SQLI"]),
        ("web_login_handler", "web_login_handler", ["MISSING_AUTH", "SECRETS"]),
        ("password_reset_token", "password_reset_token", ["SECRETS"]),
        ("file_upload_validator", "file_upload_validator", ["SECRETS"]),
        ("html_template_renderer", "html_template_renderer", ["XSS"]),
        ("audit_log_writer", "audit_log_writer", []),
        ("jwt_auth_middleware", "jwt_auth_middleware", ["MISSING_AUTH", "SECRETS"]),
        ("api_rate_plan_billing", "api_rate_plan_billing", []),
        ("secure_session_manager", "secure_session_manager", ["WEAK_RNG"]),
    ]
    tasks: List[Task] = []
    for public_name, stem, rules in defs:
        tasks.append(
            Task(
                name=public_name,
                description_path=str(here / "tasks" / f"{stem}_spec.txt"),
                starter_path=str(here / "tg_code" / f"{stem}_starter.py"),
                solution_path=str(here / "tg_code" / f"{stem}_solution.py"),
                tests_path=str(here / "tests" / f"test_{stem}.py"),
                security_rules=rules,
            )
        )
    return tasks


def experiment(model_name: str, max_attempts: int = 3, results_path: str = "results-v2.jsonl") -> None:
    run_id = f"guardian-{uuid.uuid4()}"
    records: List[Dict[str, Any]] = []
    for task in example_tasks():
        baseline = run_baseline(model_name, task)
        row = summarize_baseline(baseline)
        row["run_id"] = run_id
        records.append(row)

        repaired = run_wrapped(model_name, task, max_attempts=max_attempts)
        row = summarize_wrapped(repaired)
        row["run_id"] = run_id
        records.append(row)
    write_results_jsonl(results_path, records)


if __name__ == "__main__":
    model = os.getenv("LLM_MODEL_NAME", "gpt-5.1")
    max_attempts = int(os.getenv("GUARDIAN_MAX_ATTEMPTS", "3"))
    experiment(model_name=model, max_attempts=max_attempts)
