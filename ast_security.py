from __future__ import annotations

import ast
from typing import List


class HeuristicVisitor(ast.NodeVisitor):
    """Small custom heuristic scanner.

    These findings are advisory until each rule is validated against labeled
    positive/negative fixtures. They are not a proof of security.
    """

    def __init__(self) -> None:
        self.findings: List[str] = []
        self.in_transaction_block = False
        self.write_operations_count = 0
        self.sensitive_vars = {"password", "secret", "api_key", "token", "auth_token"}

    def visit_Import(self, node: ast.Import) -> None:  # type: ignore[override]
        for alias in node.names:
            if alias.name == "random":
                self.findings.append("WEAK_RNG_USAGE")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # type: ignore[override]
        if node.module == "random":
            self.findings.append("WEAK_RNG_USAGE")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # type: ignore[override]
        is_sql_exec = False
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "exec", "query"}:
            is_sql_exec = True
        elif isinstance(node.func, ast.Name) and node.func.id in {"execute", "exec", "query"}:
            is_sql_exec = True

        if is_sql_exec and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.BinOp):
                self.findings.append("SQLI_STRING_CONCAT")
            elif isinstance(first_arg, ast.JoinedStr):
                self.findings.append("SQLI_FSTRING")
            elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute):
                if first_arg.func.attr == "format":
                    self.findings.append("SQLI_STRING_FORMAT")

        if isinstance(node.func, ast.Attribute) and node.func.attr == "dangerouslySetInnerHTML":
            self.findings.append("POTENTIAL_XSS")

        if isinstance(node.func, ast.Attribute):
            name = node.func.attr.lower()
            if any(token in name for token in ["save", "create", "update", "delete", "insert"]):
                if not self.in_transaction_block:
                    self.write_operations_count += 1

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # type: ignore[override]
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(s in var_name for s in self.sensitive_vars):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        val = node.value.value
                        if val and len(val) > 4 and "env" not in val.lower():
                            self.findings.append("HARDCODED_SECRETS")
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:  # type: ignore[override]
        is_transaction = False
        for item in node.items:
            ctx = item.context_expr
            if isinstance(ctx, ast.Call):
                func = ctx.func
                if isinstance(func, ast.Attribute) and "transaction" in func.attr.lower():
                    is_transaction = True
                elif isinstance(func, ast.Name) and "transaction" in func.id.lower():
                    is_transaction = True
            elif isinstance(ctx, ast.Attribute) and "transaction" in ctx.attr.lower():
                is_transaction = True

        previous = self.in_transaction_block
        if is_transaction:
            self.in_transaction_block = True
        self.generic_visit(node)
        self.in_transaction_block = previous

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # type: ignore[override]
        is_endpoint = False
        has_auth_decorator = False
        for decorator in node.decorator_list:
            dec_name = ""
            if isinstance(decorator, ast.Name):
                dec_name = decorator.id
            elif isinstance(decorator, ast.Attribute):
                dec_name = decorator.attr
            elif isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Name):
                    dec_name = decorator.func.id
                elif isinstance(decorator.func, ast.Attribute):
                    dec_name = decorator.func.attr
            lowered = dec_name.lower()
            if any(x in lowered for x in ["get", "post", "put", "delete", "route"]):
                is_endpoint = True
            if any(x in lowered for x in ["login_required", "auth", "verify", "jwt"]):
                has_auth_decorator = True

        mentions_user = False
        manual_auth_check = False
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in {"user_id", "current_user", "userId"}:
                mentions_user = True
            if isinstance(child, ast.Call):
                func_name = ""
                if isinstance(child.func, ast.Name):
                    func_name = child.func.id
                elif isinstance(child.func, ast.Attribute):
                    func_name = child.func.attr
                lowered = func_name.lower()
                if "auth" in lowered or "verify" in lowered:
                    manual_auth_check = True

        if is_endpoint and mentions_user and not (has_auth_decorator or manual_auth_check):
            self.findings.append("MISSING_AUTH_CHECK")
        self.generic_visit(node)


def run_custom_heuristic_checks(code_str: str, active_rules: List[str] | None = None) -> List[str]:
    active_rules = active_rules or []
    try:
        tree = ast.parse(code_str)
    except SyntaxError:
        return ["SYNTAX_ERROR_PREVENTS_HEURISTIC_SCAN"]

    visitor = HeuristicVisitor()
    visitor.visit(tree)
    if visitor.write_operations_count > 1:
        visitor.findings.append("NO_TRANSACTION_FOR_MULTI_WRITE")

    relevant: List[str] = []
    for finding in sorted(set(visitor.findings)):
        if "SQLI" in active_rules and finding.startswith("SQLI"):
            relevant.append(finding)
        elif "SECRETS" in active_rules and finding == "HARDCODED_SECRETS":
            relevant.append(finding)
        elif "MISSING_AUTH" in active_rules and finding == "MISSING_AUTH_CHECK":
            relevant.append(finding)
        elif "NO_TRANSACTION" in active_rules and finding == "NO_TRANSACTION_FOR_MULTI_WRITE":
            relevant.append(finding)
        elif "XSS" in active_rules and finding == "POTENTIAL_XSS":
            relevant.append(finding)
        elif "WEAK_RNG" in active_rules and finding == "WEAK_RNG_USAGE":
            relevant.append(finding)
    return relevant
