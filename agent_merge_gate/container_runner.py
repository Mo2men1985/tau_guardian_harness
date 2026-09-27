"""Container-isolated deterministic tool execution.

This module executes an exact candidate snapshot with no network, a read-only
source mount, dropped Linux capabilities, no-new-privileges, process/memory/CPU
limits, and a non-root user. Raw evidence is copied/captured outside the
candidate workspace before it becomes an EvidenceRecord.

The current runner image is an operator-controlled compatibility image for this
repository. General customer repositories will require explicit trusted runner
policies rather than runtime installation from candidate-controlled manifests.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
import subprocess
import tempfile
import time
from typing import Any

from defusedxml import ElementTree as ET

from .common import MergeGateError

DEFAULT_IMAGE = os.getenv("AGENT_MERGE_GATE_RUNNER_IMAGE", "guardian-evidence-runner:py311")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _decode(data: bytes) -> str:
    return data.decode("utf-8", "replace")


@dataclass(frozen=True)
class ContainerCommandResult:
    command: tuple[str, ...]
    exit_code: int | None
    completed: bool
    timed_out: bool
    duration_ms: int
    stdout: bytes
    stdout_sha256: str
    stderr: bytes
    stderr_sha256: str
    version: str | None
    error: str | None

    def metadata(self) -> dict[str, Any]:
        return {
            "command": list(self.command),
            "exit_code": self.exit_code,
            "completed": self.completed,
            "timed_out": self.timed_out,
            "duration_ms": self.duration_ms,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "version": self.version,
            "error": self.error,
        }


@dataclass(frozen=True)
class PytestContainerResult:
    command: tuple[str, ...]
    exit_code: int | None
    completed: bool
    timed_out: bool
    duration_ms: int
    collected: int
    passed: int
    failed: int
    errors: int
    skipped: int
    junit: bytes | None
    junit_sha256: str | None
    stdout: bytes
    stdout_sha256: str
    version: str | None
    error: str | None

    def metadata(self) -> dict[str, Any]:
        return {
            "command": list(self.command),
            "exit_code": self.exit_code,
            "completed": self.completed,
            "timed_out": self.timed_out,
            "duration_ms": self.duration_ms,
            "collected": self.collected,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "skipped": self.skipped,
            "junit_sha256": self.junit_sha256,
            "stdout_sha256": self.stdout_sha256,
            "version": self.version,
            "error": self.error,
        }


def _docker_base(snapshot: Path, image: str) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        os.getenv("AGENT_MERGE_GATE_PIDS_LIMIT", "128"),
        "--memory",
        os.getenv("AGENT_MERGE_GATE_MEMORY_LIMIT", "1g"),
        "--cpus",
        os.getenv("AGENT_MERGE_GATE_CPU_LIMIT", "1.0"),
        "--user",
        os.getenv("AGENT_MERGE_GATE_CONTAINER_USER", "10001:10001"),
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=256m",  # nosec B108 - container tmpfs, not host /tmp
        "-e",
        "HOME=/tmp",
        "-e",
        "PYTHONDONTWRITEBYTECODE=1",
        "-e",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
        "-e",
        "RUFF_CACHE_DIR=/tmp/ruff-cache",
        "-v",
        f"{snapshot}:/workspace:ro",
        "-w",
        "/workspace",
        image,
    ]


def image_id(image: str = DEFAULT_IMAGE) -> str:
    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", "--format={{.Id}}", image],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=15,
        )
    except FileNotFoundError as exc:
        raise MergeGateError("DOCKER_NOT_AVAILABLE") from exc
    except subprocess.TimeoutExpired as exc:
        raise MergeGateError("DOCKER_IMAGE_INSPECT_TIMEOUT") from exc
    if proc.returncode != 0 or not proc.stdout.strip().startswith("sha256:"):
        raise MergeGateError(f"RUNNER_IMAGE_UNAVAILABLE: {image}")
    return proc.stdout.strip()


def _tool_version(snapshot: Path, image: str, command: list[str]) -> str | None:
    result = _run_command(snapshot, image, command, timeout=20, resolve_version=False)
    if not result.completed:
        return None
    text = _decode(result.stdout).strip().splitlines()
    return text[0] if text else None


def _run_command(
    snapshot: Path,
    image: str,
    tool_command: list[str],
    *,
    timeout: int,
    resolve_version: bool = True,
    version_command: list[str] | None = None,
    acceptable_exit_codes: tuple[int, ...] = (0,),
) -> ContainerCommandResult:
    command = _docker_base(snapshot, image) + tool_command
    started = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
        stdout = proc.stdout
        stderr = proc.stderr
        exit_code: int | None = proc.returncode
        timed_out = False
        completed = proc.returncode in acceptable_exit_codes
        error = None if completed else f"container command exited with {proc.returncode}"
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, bytes) else b""
        stderr = exc.stderr if isinstance(exc.stderr, bytes) else b""
        exit_code = 124
        timed_out = True
        completed = False
        error = f"container command timed out after {timeout}s"
    except FileNotFoundError:
        stdout = b"docker executable not found"
        stderr = b""
        exit_code = 127
        timed_out = False
        completed = False
        error = "Docker unavailable"

    version = None
    if resolve_version and version_command:
        version = _tool_version(snapshot, image, version_command)

    return ContainerCommandResult(
        command=tuple(command),
        exit_code=exit_code,
        completed=completed,
        timed_out=timed_out,
        duration_ms=int((time.monotonic() - started) * 1000),
        stdout=stdout,
        stdout_sha256=_sha256_bytes(stdout),
        stderr=stderr,
        stderr_sha256=_sha256_bytes(stderr),
        version=version,
        error=error,
    )


def run_ruff(
    snapshot: Path,
    targets: tuple[str, ...],
    *,
    image: str = DEFAULT_IMAGE,
    timeout: int = 120,
) -> ContainerCommandResult:
    if not targets:
        return ContainerCommandResult(
            command=(),
            exit_code=None,
            completed=False,
            timed_out=False,
            duration_ms=0,
            stdout=b"",
            stdout_sha256=_sha256_bytes(b""),
            stderr=b"",
            stderr_sha256=_sha256_bytes(b""),
            version=_tool_version(snapshot, image, ["ruff", "--version"]),
            error="no Python targets for Ruff",
        )
    command = [
        "ruff",
        "check",
        "--isolated",
        "--select",
        "E9,F63,F7,F82",
        "--output-format=json",
        *targets,
    ]
    return _run_command(
        snapshot,
        image,
        command,
        timeout=timeout,
        version_command=["ruff", "--version"],
        acceptable_exit_codes=(0, 1),
    )


def run_bandit(
    snapshot: Path,
    targets: tuple[str, ...],
    *,
    image: str = DEFAULT_IMAGE,
    timeout: int = 120,
) -> ContainerCommandResult:
    if not targets:
        return ContainerCommandResult(
            command=(),
            exit_code=None,
            completed=False,
            timed_out=False,
            duration_ms=0,
            stdout=b"",
            stdout_sha256=_sha256_bytes(b""),
            stderr=b"",
            stderr_sha256=_sha256_bytes(b""),
            version=_tool_version(snapshot, image, ["bandit", "--version"]),
            error="no production Python targets for Bandit",
        )
    return _run_command(
        snapshot,
        image,
        ["bandit", "-q", "-f", "json", *targets],
        timeout=timeout,
        version_command=["bandit", "--version"],
        acceptable_exit_codes=(0, 1),
    )


def _parse_junit(data: bytes) -> tuple[int, int, int, int, int]:
    with tempfile.NamedTemporaryFile(suffix=".xml") as handle:
        handle.write(data)
        handle.flush()
        root = ET.parse(handle.name).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall(".//testsuite")
    tests = failures = errors = skipped = 0
    for suite in suites:
        tests += int(suite.attrib.get("tests", "0") or 0)
        failures += int(suite.attrib.get("failures", "0") or 0)
        errors += int(suite.attrib.get("errors", "0") or 0)
        skipped += int(suite.attrib.get("skipped", "0") or 0)
    passed = max(0, tests - failures - errors - skipped)
    return tests, passed, failures, errors, skipped


def run_pytest(
    snapshot: Path,
    *,
    image: str = DEFAULT_IMAGE,
    timeout: int = 180,
) -> PytestContainerResult:
    """Run repository tests with source read-only and evidence narrowly writable."""
    with tempfile.TemporaryDirectory(prefix="amg-pytest-evidence-") as tmp:
        evidence_dir = Path(tmp)
        # Dedicated ephemeral evidence directory; only this directory is writable
        # from the container. It contains no source, credentials, or host state.
        evidence_dir.chmod(0o777)  # nosec B103
        junit_path = evidence_dir / "pytest.xml"
        tool_command = [
            "python",
            "-m",
            "pytest",
            "-q",
            "-o",
            "addopts=",
            "-o",
            "cache_dir=/tmp/pytest-cache",
            "tests",
            "--junitxml=/evidence/pytest.xml",
        ]
        command = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            os.getenv("AGENT_MERGE_GATE_PIDS_LIMIT", "128"),
            "--memory",
            os.getenv("AGENT_MERGE_GATE_MEMORY_LIMIT", "1g"),
            "--cpus",
            os.getenv("AGENT_MERGE_GATE_CPU_LIMIT", "1.0"),
            "--user",
            os.getenv("AGENT_MERGE_GATE_CONTAINER_USER", "10001:10001"),
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=256m",  # nosec B108
            "-e",
            "HOME=/tmp",
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
            "-e",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
            "-e",
            "RUFF_CACHE_DIR=/tmp/ruff-cache",
            "-v",
            f"{snapshot}:/workspace:ro",
            "-v",
            f"{evidence_dir}:/evidence:rw",
            "-w",
            "/workspace",
            image,
            *tool_command,
        ]

        started = time.monotonic()
        try:
            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=timeout,
            )
            stdout = proc.stdout
            exit_code: int | None = proc.returncode
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, bytes) else b""
            exit_code = 124
            timed_out = True
        except FileNotFoundError:
            stdout = b"docker executable not found"
            exit_code = 127
            timed_out = False

        junit = junit_path.read_bytes() if junit_path.exists() else None
        collected = passed = failed = errors = skipped = 0
        completed = not timed_out and exit_code != 127 and junit is not None
        error = None
        if completed and junit is not None:
            try:
                collected, passed, failed, errors, skipped = _parse_junit(junit)
            except Exception as exc:
                completed = False
                error = f"invalid JUnit XML: {exc}"
        elif timed_out:
            error = f"pytest timed out after {timeout}s"
        elif exit_code == 127:
            error = "Docker unavailable"
        else:
            error = "pytest did not produce retrievable JUnit XML"

        version = _tool_version(snapshot, image, ["python", "-m", "pytest", "--version"])
        return PytestContainerResult(
            command=tuple(tool_command),
            exit_code=exit_code,
            completed=completed,
            timed_out=timed_out,
            duration_ms=int((time.monotonic() - started) * 1000),
            collected=collected,
            passed=passed,
            failed=failed,
            errors=errors,
            skipped=skipped,
            junit=junit,
            junit_sha256=_sha256_bytes(junit) if junit is not None else None,
            stdout=stdout,
            stdout_sha256=_sha256_bytes(stdout),
            version=version,
            error=error,
        )


def parse_json_list(result: ContainerCommandResult) -> list[dict[str, Any]]:
    if not result.completed:
        return []
    try:
        payload = json.loads(_decode(result.stdout) or "[]")
    except json.JSONDecodeError as exc:
        raise MergeGateError(f"STRUCTURED_TOOL_OUTPUT_INVALID: {exc}") from exc
    if not isinstance(payload, list):
        raise MergeGateError("STRUCTURED_TOOL_OUTPUT_NOT_LIST")
    return [item for item in payload if isinstance(item, dict)]


def parse_bandit(result: ContainerCommandResult) -> list[dict[str, Any]]:
    if not result.completed:
        return []
    try:
        payload = json.loads(_decode(result.stdout) or "{}")
    except json.JSONDecodeError as exc:
        raise MergeGateError(f"BANDIT_OUTPUT_INVALID: {exc}") from exc
    if not isinstance(payload, dict):
        raise MergeGateError("BANDIT_OUTPUT_NOT_OBJECT")
    if "errors" not in payload:
        raise MergeGateError("BANDIT_ERRORS_MISSING")
    errors = payload["errors"]
    if not isinstance(errors, list):
        raise MergeGateError("BANDIT_ERRORS_NOT_LIST")
    if errors:
        raise MergeGateError("BANDIT_SCAN_ERRORS_PRESENT")
    rows = payload.get("results", [])
    if not isinstance(rows, list):
        raise MergeGateError("BANDIT_RESULTS_NOT_LIST")
    if any(not isinstance(item, dict) for item in rows):
        raise MergeGateError("BANDIT_RESULT_ENTRY_INVALID")
    return rows
