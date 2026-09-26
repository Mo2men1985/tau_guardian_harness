from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

DEFAULT_RUNNER_IMAGE = os.getenv("GUARDIAN_RUNNER_IMAGE", "guardian-evidence-runner:py311")


@dataclass
class SandboxTestResult:
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
    stdout: str
    error: Optional[str]


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_junit(path: Path) -> Tuple[int, int, int, int, int]:
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall(".//testsuite")
    tests = failures = errors = skipped = 0
    for suite in suites:
        tests += int(suite.attrib.get("tests", "0") or 0)
        failures += int(suite.attrib.get("failures", "0") or 0)
        errors += int(suite.attrib.get("errors", "0") or 0)
        skipped += int(suite.attrib.get("skipped", "0") or 0)
    passed = max(0, tests - failures - errors - skipped)
    return tests, passed, failures, errors, skipped


def run_tests_in_sandbox(
    test_file_path: str,
    project_root: str,
    docker_image: str = DEFAULT_RUNNER_IMAGE,
    timeout: int = 120,
) -> SandboxTestResult:
    """Run generated-code tests in a constrained Docker container.

    The runner image must be built in advance; runtime package installation is
    intentionally forbidden because networking is disabled.
    """
    project_root_path = Path(project_root).resolve()
    test_path = Path(test_file_path).resolve()
    try:
        rel_test_path = test_path.relative_to(project_root_path)
    except ValueError:
        return SandboxTestResult(
            command=[], exit_code=2, completed=False, timed_out=False,
            collected=0, passed=0, failed=0, errors=0, skipped=0,
            duration_ms=0, report_sha256=None, stdout_sha256=_sha256_bytes(b""),
            stdout="", error="test path is outside project root"
        )

    with tempfile.TemporaryDirectory(prefix="guardian-sandbox-") as tmpdir:
        tmp_path = Path(tmpdir)
        report_host = tmp_path / "pytest.xml"
        command = [
            "docker", "run", "--rm",
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", os.getenv("GUARDIAN_PIDS_LIMIT", "128"),
            "--memory", os.getenv("GUARDIAN_MEMORY_LIMIT", "1g"),
            "--cpus", os.getenv("GUARDIAN_CPU_LIMIT", "1.0"),
            "--user", os.getenv("GUARDIAN_CONTAINER_USER", "65534:65534"),
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m",
            "-v", f"{project_root_path}:/workspace:ro",
            "-v", f"{tmp_path}:/evidence:rw",
            "-w", "/workspace",
            docker_image,
            "pytest", "-q", str(rel_test_path), "--junitxml=/evidence/pytest.xml",
        ]

        started = time.monotonic()
        try:
            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
                timeout=timeout,
            )
            output = proc.stdout
            exit_code = proc.returncode
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            output = exc.stdout if isinstance(exc.stdout, str) else ""
            exit_code = 124
            timed_out = True
        except FileNotFoundError:
            output = "docker executable not found"
            exit_code = 127
            timed_out = False

        duration_ms = int((time.monotonic() - started) * 1000)
        completed = not timed_out and exit_code != 127 and report_host.exists()
        collected = passed = failed = errors = skipped = 0
        report_hash: Optional[str] = None
        error: Optional[str] = None
        if completed:
            try:
                report_bytes = report_host.read_bytes()
                report_hash = _sha256_bytes(report_bytes)
                collected, passed, failed, errors, skipped = _parse_junit(report_host)
            except Exception as exc:
                completed = False
                error = f"invalid sandbox JUnit XML: {exc}"
        else:
            if timed_out:
                error = f"sandbox timed out after {timeout}s"
            elif exit_code == 127:
                error = "Docker unavailable"
            else:
                error = "sandbox did not produce JUnit XML"

        return SandboxTestResult(
            command=command,
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
            stdout_sha256=_sha256_bytes(output.encode("utf-8")),
            stdout=output,
            error=error,
        )
