import os
import re
import json
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any, Literal

# --- Task + result models -------------------------------------------------

@dataclass
class Task:
    name: str
    description_path: str
    starter_path: str
    solution_path: str
    tests_path: str
    security_rules: List[str]
    language: str = "python"

@dataclass
class CheckResults:
    total_tests: int = 0
    tests_failed: int = 0
    tests_output: str = ""
    security_violations: List[str] = None
    linter_errors: List[str] = None

    def __post_init__(self):
        if self.security_violations is None:
            self.security_violations = []
        if self.linter_errors is None:
            self.linter_errors = []

@dataclass
class Metrics:
    cri: float
    sad_flag: bool
    tau: int

Decision = Literal["OK", "ABSTAIN", "VETO"]

@dataclass
class BaselineResult:
    model_name: str
    task_name: str
    checks: CheckResults
    metrics: Metrics

@dataclass
class IterationRecord:
    tau_step: int
    code_path: str
    checks: CheckResults
    metrics: Metrics
    decision: Decision

@dataclass
class WrappedResult:
    model_name: str
    task_name: str
    iterations: List[IterationRecord]
    final_decision: Decision
    final_code_path: Optional[str]


# --- Utilities ------------------------------------------------------------

def read_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write_file(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def run_shell_command(cmd: List[str], cwd: Optional[str] = None, timeout: int = 60) -> Tuple[int, str]:
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
        return proc.returncode, proc.stdout
    except subprocess.TimeoutExpired:
        return 1, f"[ERROR] Command timed out after {timeout}s"
    except FileNotFoundError as e:
        return 1, f"[ERROR] Command not found: {cmd[0]} ({e})"


# --- Model call -----------------------------------------------------------

def call_model_for_code(model_name: str, prompt: str) -> str:
    """Concrete example for GPT-5.1-style models using the OpenAI client.

    Requires:
      - pip install openai>=1.0.0
      - OPENAI_API_KEY set in env
    """
    try:
        from openai import OpenAI
    except ImportError:
        raise RuntimeError("openai package not installed. Run `pip install openai`.")

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set in environment.")

    client = OpenAI(api_key=api_key)

    resp = client.chat.completions.create(
        model=model_name,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an expert software engineer. "
                    "Return ONLY the final code, inside a single fenced code block. "
                    "No explanations, no comments outside code."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        temperature=0.1,
    )
    text = resp.choices[0].message.content or ""
    return text


# --- Parsing helpers ------------------------------------------------------

def extract_code_from_response(text: str) -> str:
    """Extract code from LLM response, handling fenced and unfenced formats."""
    if "```" in text:
        start = text.find("```")
        end = text.find("```", start + 3)
        if end != -1:
            fenced = text[start + 3:end]
            lines = fenced.splitlines()
            if lines and re.match(r"^[a-zA-Z0-9_+\-]+$", lines[0].strip()):
                code_body = "\n".join(lines[1:])
            else:
                code_body = "\n".join(lines)
            return code_body.strip() + "\n"

    markers = [
        r"(?:here(?:'s| is) the (?:complete |final )?(?:code|implementation|solution):?\s*\n)(.*)",
        r"(?:```\w*\n)?(.*?)(?:\n```)?$",
    ]
    for pattern in markers:
        m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        if m:
            return m.group(1).strip() + "\n"

    return text.strip() + "\n"


def parse_pytest_output(output: str) -> Tuple[int, int]:
    """Return (total_tests, tests_failed) from pytest / jest-like output."""
    # Pattern: "5 passed, 2 failed in 1.23s"
    m = re.search(r"(\d+)\s+passed(?:,\s+(\d+)\s+failed)?", output)
    if m:
        passed = int(m.group(1))
        failed = int(m.group(2)) if m.group(2) else 0
        return passed + failed, failed

    # Pattern: "FAILED (failures=2)"
    m = re.search(r"FAILED.*failures=(\d+)", output)
    if m:
        failed = int(m.group(1))
        m2 = re.search(r"(\d+)\s+passed", output)
        passed = int(m2.group(1)) if m2 else 0
        return passed + failed, failed

    # Jest-like: "Tests: 2 failed, 5 passed, 7 total"
    m = re.search(r"(\d+)\s+failed,\s+(\d+)\s+passed", output)
    if m:
        failed = int(m.group(1))
        passed = int(m.group(2))
        return passed + failed, failed

    if "passed" in output.lower() and "fail" not in output.lower():
        return 1, 0
    return 1, 1


# --- Checks ---------------------------------------------------------------

def run_tests_for_task(task: Task) -> CheckResults:
    cmd = ["pytest", "-q", task.tests_path]
    code, out = run_shell_command(cmd)
    total, failed = parse_pytest_output(out)
    return CheckResults(
        total_tests=total,
        tests_failed=failed,
        tests_output=out,
    )


def run_linter_for_task(task: Task) -> List[str]:
    if task.language != "python":
        return []
    cmd = ["ruff", "check", task.solution_path]
    code, out = run_shell_command(cmd)
    if code == 0 and not out.strip():
        return []
    return [line for line in out.splitlines() if line.strip()]


def run_security_rules(task: Task) -> List[str]:
    code = read_file(task.solution_path)
    violations: List[str] = []

    if "SQLI" in task.security_rules:
        if re.search(r"(?:SELECT|INSERT|UPDATE|DELETE).*?\$\{[^}]+\}", code, re.IGNORECASE):
            violations.append("SQLI_TEMPLATE_INTERPOLATION")
        if re.search(r"(?:SELECT|INSERT|UPDATE|DELETE).*?['\"].*?\+.*?['\"]", code, re.IGNORECASE):
            violations.append("SQLI_STRING_CONCAT")
        if re.search(r"f['\"](?:SELECT|INSERT|UPDATE|DELETE).*?\{[^}]+\}", code, re.IGNORECASE):
            violations.append("SQLI_FSTRING")
        has_params = re.search(r"\?|\$\d+|execute\([^,]+,\s*\[", code)
        has_query = re.search(r"SELECT|INSERT|UPDATE|DELETE", code, re.IGNORECASE)
        if has_query and not has_params:
            violations.append("SQLI_NO_PARAMETERIZATION")

    if "MISSING_AUTH" in task.security_rules:
        is_endpoint = re.search(r"@app\.\w+|app\.get\(|app\.post\(", code)
        mentions_user = re.search(r"user_id|userId|current_user", code)
        has_auth = re.search(r"@login_required|require_auth|verify_token|current_user", code)
        if is_endpoint and mentions_user and not has_auth:
            violations.append("MISSING_AUTH_CHECK")

    if "NO_TRANSACTION" in task.security_rules:
        writes = re.findall(r"\b(?:INSERT|UPDATE|DELETE|\.save\(\)|\.create\(\)|\.update\(\))", code, re.IGNORECASE)
        has_tx = re.search(r"transaction|BEGIN|COMMIT|db\.session\.begin", code, re.IGNORECASE)
        if len(writes) >= 2 and not has_tx:
            violations.append("NO_TRANSACTION_FOR_MULTI_WRITE")

    if "XSS" in task.security_rules:
        if re.search(r"innerHTML|dangerouslySetInnerHTML|\.html\(", code):
            violations.append("POTENTIAL_XSS")

    if "SECRETS" in task.security_rules:
        secrets = re.findall(r"(?:password|secret|api_key|token)\s*=\s*['\"][^'\"]+['\"]", code, re.IGNORECASE)
        if secrets:
            violations.append("HARDCODED_SECRETS")

    return violations


def aggregate_checks(task: Task) -> CheckResults:
    tests = run_tests_for_task(task)
    lint_errors = run_linter_for_task(task)
    sec_violations = run_security_rules(task)
    tests.linter_errors = lint_errors
    tests.security_violations = sec_violations
    return tests


# --- Metrics + decision ---------------------------------------------------

def compute_metrics(checks: CheckResults, tau_step: int) -> Metrics:
    if checks.total_tests > 0:
        pass_rate = (checks.total_tests - checks.tests_failed) / checks.total_tests
    else:
        pass_rate = 0.0

    sec_penalty = 0.1 * len(checks.security_violations)
    lint_penalty = 0.02 * len(checks.linter_errors)

    cri = max(0.0, min(1.0, pass_rate - sec_penalty - lint_penalty))
    sad_flag = len(checks.security_violations) > 0
    return Metrics(cri=cri, sad_flag=sad_flag, tau=tau_step)


def decide(metrics: Metrics, checks: CheckResults, cri_ok_threshold: float = 0.9) -> Decision:
    if metrics.sad_flag:
        return "VETO"
    if metrics.cri >= cri_ok_threshold and checks.tests_failed == 0:
        return "OK"
    return "ABSTAIN"


# --- Baseline / wrapped runs ---------------------------------------------

def build_prompt_for_task(task: Task, is_repair: bool, previous_code: Optional[str], checks: Optional[CheckResults]) -> str:
    spec = read_file(task.description_path)
    starter = read_file(task.starter_path)

    if not is_repair:
        return (
            f"Task: {task.name}\n"
            f"Language: {task.language}\n\n"
            f"Specification:\n{spec}\n\n"
            f"Starter code (you MAY reuse or refactor):\n```{task.language}\n{starter}\n```\n\n"
            "Write a complete, working solution in one file. Return ONLY the final code."
        )

    assert previous_code is not None and checks is not None
    return (
        f"Task: {task.name}\n"
        f"Language: {task.language}\n\n"
        f"Specification:\n{spec}\n\n"
        "You wrote the following code which FAILED tests or checks:\n"
        f"```{task.language}\n{previous_code}\n```\n\n"
        "Test / linter / security output:\n"
        f"{checks.tests_output}\n"
        f"Linter errors: {checks.linter_errors}\n"
        f"Security violations: {checks.security_violations}\n\n"
        "Repair the code. Focus on fixing failing tests and security issues. "
        "Return ONLY the corrected code."
    )


def run_baseline(model_name: str, task: Task) -> BaselineResult:
    prompt = build_prompt_for_task(task, is_repair=False, previous_code=None, checks=None)
    raw = call_model_for_code(model_name, prompt)
    code = extract_code_from_response(raw)
    write_file(task.solution_path, code)
    checks = aggregate_checks(task)
    metrics = compute_metrics(checks, tau_step=0)
    return BaselineResult(
        model_name=model_name,
        task_name=task.name,
        checks=checks,
        metrics=metrics,
    )


def run_wrapped(
    model_name: str,
    task: Task,
    tau_max: int = 3,
    cri_ok_threshold: float = 0.9,
    early_stop_plateau: bool = True,
) -> WrappedResult:
    iterations: List[IterationRecord] = []
    previous_code: Optional[str] = None
    previous_metrics: Optional[Metrics] = None
    final_decision: Decision = "ABSTAIN"
    final_code_path: Optional[str] = None

    for tau_step in range(1, tau_max + 1):
        is_repair = tau_step > 1
        checks_for_prompt = iterations[-1].checks if iterations else None
        prompt = build_prompt_for_task(
            task,
            is_repair=is_repair,
            previous_code=previous_code,
            checks=checks_for_prompt,
        )
        raw = call_model_for_code(model_name, prompt)
        code = extract_code_from_response(raw)
        write_file(task.solution_path, code)

        checks = aggregate_checks(task)
        metrics = compute_metrics(checks, tau_step=tau_step)
        decision = decide(metrics, checks, cri_ok_threshold=cri_ok_threshold)

        iterations.append(
            IterationRecord(
                tau_step=tau_step,
                code_path=task.solution_path,
                checks=checks,
                metrics=metrics,
                decision=decision,
            )
        )

        previous_code = code
        previous_metrics = metrics

        if decision in ("OK", "VETO"):
            final_decision = decision
            final_code_path = task.solution_path
            break

        if early_stop_plateau and len(iterations) >= 2:
            last_two = [iterations[-2].metrics.cri, iterations[-1].metrics.cri]
            if abs(last_two[1] - last_two[0]) < 0.05:
                final_decision = decision
                final_code_path = task.solution_path
                break

    if final_code_path is None and iterations:
        final_code_path = iterations[-1].code_path
        final_decision = iterations[-1].decision

    return WrappedResult(
        model_name=model_name,
        task_name=task.name,
        iterations=iterations,
        final_decision=final_decision,
        final_code_path=final_code_path,
    )


# --- Results export -------------------------------------------------------

def summarize_baseline(b: BaselineResult) -> Dict[str, Any]:
    return {
        "model": b.model_name,
        "task": b.task_name,
        "type": "baseline",
        "tests_passed": b.checks.total_tests - b.checks.tests_failed,
        "tests_failed": b.checks.tests_failed,
        "total_tests": b.checks.total_tests,
        "test_pass_rate": (
            (b.checks.total_tests - b.checks.tests_failed) / b.checks.total_tests
            if b.checks.total_tests
            else None
        ),
        "security_violations": b.checks.security_violations,
        "security_violation_count": len(b.checks.security_violations),
        "linter_errors_count": len(b.checks.linter_errors),
        "cri": b.metrics.cri,
        "sad_flag": b.metrics.sad_flag,
        "tau": b.metrics.tau,
    }


def summarize_wrapped(w: WrappedResult) -> Dict[str, Any]:
    last = w.iterations[-1] if w.iterations else None
    cri_history = [it.metrics.cri for it in w.iterations]
    return {
        "model": w.model_name,
        "task": w.task_name,
        "type": "wrapped",
        "final_decision": w.final_decision,
        "iterations": len(w.iterations),
        "cri_history": cri_history,
        "cri_improvement": (
            cri_history[-1] - cri_history[0] if len(cri_history) > 1 else 0.0
        ),
        "last_tau": last.metrics.tau if last else None,
        "last_cri": last.metrics.cri if last else None,
        "last_sad": last.metrics.sad_flag if last else None,
        "last_tests_passed": (
            last.checks.total_tests - last.checks.tests_failed if last else None
        ),
        "last_tests_failed": last.checks.tests_failed if last else None,
        "last_total_tests": last.checks.total_tests if last else None,
        "last_test_pass_rate": (
            (last.checks.total_tests - last.checks.tests_failed) / last.checks.total_tests
            if last and last.checks.total_tests
            else None
        ),
        "last_security_violations": last.checks.security_violations if last else None,
        "last_linter_errors_count": len(last.checks.linter_errors) if last else None,
    }


def write_results_jsonl(path: str, records: List[Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec))
            f.write("\n")


# --- Example tasks --------------------------------------------------------

def example_tasks() -> List[Task]:
    here = os.path.dirname(os.path.abspath(__file__))
    return [
        Task(
            name="rate_limiter_python",
            description_path=os.path.join(here, "tasks", "rate_limiter_spec.txt"),
            starter_path=os.path.join(here, "code", "rate_limiter_starter.py"),
            solution_path=os.path.join(here, "code", "rate_limiter_solution.py"),
            tests_path=os.path.join(here, "tests", "test_rate_limiter.py"),
            security_rules=[],
            language="python",
        ),
        Task(
            name="funds_transfer_secure",
            description_path=os.path.join(here, "tasks", "funds_transfer_spec.txt"),
            starter_path=os.path.join(here, "code", "funds_transfer_starter.py"),
            solution_path=os.path.join(here, "code", "funds_transfer_solution.py"),
            tests_path=os.path.join(here, "tests", "test_funds_transfer.py"),
            security_rules=["MISSING_AUTH", "NO_TRANSACTION", "SECRETS"],
            language="python",
        ),
    ]


# --- Main experiment ------------------------------------------------------

def experiment(model_name: str, tau_max: int = 3, results_path: str = "results.jsonl") -> None:
    tasks = example_tasks()
    all_records: List[Dict[str, Any]] = []

    for task in tasks:
        print(f"[INFO] Running baseline for {task.name} on {model_name}...")
        baseline = run_baseline(model_name, task)
        all_records.append(summarize_baseline(baseline))

        print(f"[INFO] Running wrapped (tau_max={tau_max}) for {task.name} on {model_name}...")
        wrapped = run_wrapped(model_name, task, tau_max=tau_max)
        all_records.append(summarize_wrapped(wrapped))

    write_results_jsonl(results_path, all_records)
    print(f"[INFO] Wrote results to {results_path}")


if __name__ == "__main__":
    model = os.getenv("LLM_MODEL_NAME", "gpt-5.1")
    experiment(model_name=model, tau_max=int(os.getenv("TAU_MAX", "3")))
