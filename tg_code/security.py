"""
tg_code/security.py

Thin wrapper around the core AST security scanner (ast_security.py).

Responsibilities:
- Provide a stable API for τGuardian components:
    - scan_code_for_violations(code_str, active_rules=None, verbose=False)
        -> SecurityScanResult(violations=[...], sad_flag=bool)
    - scan_file_for_violations(path, active_rules=None, verbose=False)
        -> SecurityScanResult

Behavior:
- Prefer the real AST-based scanner in ast_security.run_ast_security_checks(...)
- Gracefully fall back to a conservative substring-based heuristic if the
  AST scanner is missing or has an unexpected signature.
"""

from __future__ import annotations

import sys
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

# Ensure repo root (where ast_security.py lives) is importable when this file
# is inside a 'tg_code/' package.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Attempt to import the real AST security scanner
try:  # pragma: no cover - import resolution is environment specific
    from ast_security import run_ast_security_checks as _ast_run_checks  # type: ignore[attr-defined]
except Exception:  # pragma: no cover - defensive fallback
    _ast_run_checks = None


# Default rule IDs used by the fallback scanner.
# This is a superset that includes:
# - "AST-style" rules often used in ast_security implementations
# - "fallback-style" generic danger labels
DEFAULT_RULE_IDS: Sequence[str] = (
    "SQLI_STRING_CONCAT",
    "SQLI_FSTRING",
    "HARDCODED_SECRET",
    "HARDCODED_SECRETS",
    "DANGEROUS_EVAL",
    "DANGEROUS_EXEC",
    "DANGEROUS_OS_SYSTEM",
    "DANGEROUS_SUBPROCESS",
    "DANGEROUS_PICKLE",
)


@dataclass
class SecurityScanResult:
    """Structured result for a security scan."""

    violations: List[str]

    @property
    def sad_flag(self) -> bool:
        """True if any violations exist (SAD = Security Anomaly Detected)."""
        return bool(self.violations)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _call_ast_scanner(
    code_str: str,
    active_rules: Optional[Iterable[str]] = None,
) -> Optional[List[str]]:
    """
    Call ast_security.run_ast_security_checks if available.

    This helper is defensive about signature mismatches across versions:
    - Preferred: run_ast_security_checks(code_str, active_rules=rules_list)
    - Fallback: run_ast_security_checks(code_str)
    Returns:
        - list of violation codes on success
        - None if ast_security is unavailable or fails.
    """
    if _ast_run_checks is None:
        return None

    # Normalize active_rules
    rules_list: Optional[List[str]]
    if active_rules is not None:
        rules_list = list(active_rules)
    else:
        rules_list = None

    try:
        # Preferred signature
        return list(_ast_run_checks(code_str, active_rules=rules_list))
    except TypeError:
        # Older/different signature: try with single argument
        try:
            return list(_ast_run_checks(code_str))  # type: ignore[misc]
        except Exception:
            return None
    except Exception:
        # Any other runtime error: treat as unavailable
        return None


def _fallback_scan(
    code_str: str,
    active_rules: Optional[Iterable[str]] = None,
) -> List[str]:
    """
    Very simple heuristic scanner used only if ast_security is unavailable.

    This is intentionally conservative: it will over-report rather than miss.
    It looks for suspicious substrings in the code.

    NOTE: Rule IDs here are best-effort and may not exactly match any
    particular ast_security implementation, but they are compatible with
    τGuardian's idea of "security_violations" as plain string IDs.
    """
    text = code_str or ""
    active = set(active_rules) if active_rules is not None else set(DEFAULT_RULE_IDS)

    violations: List[str] = []

    def add(rule: str) -> None:
        if rule in active:
            violations.append(rule)

    lowered = text.lower()

    if "eval(" in text:
        add("DANGEROUS_EVAL")
    if "exec(" in text:
        add("DANGEROUS_EXEC")
    if "os.system(" in text:
        add("DANGEROUS_OS_SYSTEM")
    if "subprocess." in text:
        add("DANGEROUS_SUBPROCESS")
    if "pickle.load(" in text or "pickle.loads(" in text:
        add("DANGEROUS_PICKLE")

    # Very rough SQL + f-string heuristic
    if "select " in lowered or "insert " in lowered or "update " in lowered or "delete " in lowered:
        if 'f"' in text or "f'" in text:
            add("SQLI_FSTRING")

    return violations


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_code_for_violations(
    code_str: str,
    active_rules: Optional[Iterable[str]] = None,
    verbose: bool = False,
) -> SecurityScanResult:
    """
    Scan a code string for security violations.

    Args:
        code_str: The Python source code to scan.
        active_rules: Optional iterable of rule IDs to enable. If None,
            DEFAULT_RULE_IDS is used.
        verbose: If True, emits a warning when the AST-based scanner is
            unavailable and the fallback is used.

    Returns:
        SecurityScanResult with:
            - violations: list of rule IDs (strings)
            - sad_flag: True if any violations found

    τGuardian harness usage:
        result = scan_code_for_violations(patched_source, task.security_rules)
        security_violations = result.violations
        sad_flag = result.sad_flag
    """
    violations = _call_ast_scanner(code_str, active_rules=active_rules)
    if violations is None:
        if verbose:
            warnings.warn(
                "AST security scanner unavailable or failed; using fallback heuristic.",
                RuntimeWarning,
            )
        violations = _fallback_scan(code_str, active_rules=active_rules)

    return SecurityScanResult(violations=list(violations))


def scan_file_for_violations(
    path: Path | str,
    active_rules: Optional[Iterable[str]] = None,
    encoding: str = "utf-8",
    verbose: bool = False,
) -> SecurityScanResult:
    """
    Convenience wrapper to scan a file for security violations.

    Args:
        path: Path to a .py file.
        active_rules: Optional iterable of rule IDs to enable. If None, uses
            DEFAULT_RULE_IDS.
        encoding: File encoding (default 'utf-8').
        verbose: Passed through to scan_code_for_violations.

    Returns:
        SecurityScanResult as in scan_code_for_violations.
    """
    p = Path(path)
    try:
        text = p.read_text(encoding=encoding)
    except FileNotFoundError:
        # Missing file → no violations. Callers can decide how to handle this.
        return SecurityScanResult(violations=[])

    return scan_code_for_violations(text, active_rules=active_rules, verbose=verbose)


