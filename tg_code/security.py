"""Compatibility wrapper for the project's advisory custom security checks.

These checks emit heuristic findings only. They are not a proof of security and
are not sufficient by themselves for a release decision.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from ast_security import run_custom_heuristic_checks


@dataclass
class SecurityScanResult:
    findings: List[str]

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)


def scan_code_for_violations(
    code_str: str,
    active_rules: Optional[Iterable[str]] = None,
    verbose: bool = False,
) -> SecurityScanResult:
    del verbose
    findings = run_custom_heuristic_checks(
        code_str,
        active_rules=list(active_rules or []),
    )
    return SecurityScanResult(findings=list(findings))


def scan_file_for_violations(
    path: Path | str,
    active_rules: Optional[Iterable[str]] = None,
    encoding: str = "utf-8",
    verbose: bool = False,
) -> SecurityScanResult:
    p = Path(path)
    try:
        text = p.read_text(encoding=encoding)
    except FileNotFoundError:
        return SecurityScanResult(findings=[])
    return scan_code_for_violations(
        text,
        active_rules=active_rules,
        verbose=verbose,
    )
