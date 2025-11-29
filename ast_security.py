
import ast
import re
from typing import List


class SecurityVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.violations: List[str] = []
        self.in_transaction_block = False
        self.write_operations_count = 0
        self.sql_keywords = {"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER"}
        self.sensitive_vars = {"password", "secret", "api_key", "token", "auth_token"}

    def visit_Call(self, node: ast.Call) -> None:
        """Check for SQL Injection and specific function calls."""
        # 1. SQL Injection detection (very simple heuristic)
        is_sql_exec = False
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "exec", "query"):
            is_sql_exec = True
        elif isinstance(node.func, ast.Name) and node.func.id in ("execute", "exec", "query"):
            is_sql_exec = True

        if is_sql_exec and node.args:
            first_arg = node.args[0]
            # Detect dynamic query construction patterns
            if isinstance(first_arg, ast.BinOp):
                # e.g., "SELECT * FROM " + user_input
                self.violations.append("SQLI_STRING_CONCAT")
            elif isinstance(first_arg, ast.JoinedStr):
                # e.g., f"SELECT * FROM {user_input}"
                self.violations.append("SQLI_FSTRING")
            elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute):
                if first_arg.func.attr == "format":
                    # e.g., "SELECT * FROM {}".format(user_input)
                    self.violations.append("SQLI_STRING_FORMAT")

        # 2. XSS detection (Python backend generating HTML)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "dangerouslySetInnerHTML":
            self.violations.append("POTENTIAL_XSS")

        # 3. Transaction logic tracking (method calls that look like writes)
        if isinstance(node.func, ast.Attribute):
            name = node.func.attr.lower()
            if any(x in name for x in ["save", "create", "update", "delete", "insert"]):
                if not self.in_transaction_block:
                    self.write_operations_count += 1

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check for hardcoded secrets."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                # Check if variable name looks sensitive
                if any(s in var_name for s in self.sensitive_vars):
                    # Check if the value assigned is a string literal (hardcoded)
                    if isinstance(node.value, (ast.Constant, ast.Str)):  # ast.Str for python < 3.8
                        val = node.value.value if isinstance(node.value, ast.Constant) else node.value.s
                        if val and len(val) > 4 and "env" not in val:
                            self.violations.append("HARDCODED_SECRETS")
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        """Track transaction contexts."""
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

        if is_transaction:
            self.in_transaction_block = True
            self.generic_visit(node)
            self.in_transaction_block = False
        else:
            self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Check for missing authorization on endpoints."""
        is_endpoint = False
        has_auth_decorator = False

        # Decorators
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

            if any(x in dec_name for x in ["get", "post", "put", "delete", "route", "app"]):
                is_endpoint = True
            if any(x in dec_name for x in ["login_required", "auth", "verify", "jwt"]):
                has_auth_decorator = True

        mentions_user = False
        manual_auth_check = False

        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in ["user_id", "current_user", "userId"]:
                mentions_user = True
            if isinstance(child, ast.Call):
                func_name = ""
                if isinstance(child.func, ast.Name):
                    func_name = child.func.id
                elif isinstance(child.func, ast.Attribute):
                    func_name = child.func.attr
                if "auth" in func_name or "verify" in func_name:
                    manual_auth_check = True

        if is_endpoint and mentions_user and not (has_auth_decorator or manual_auth_check):
            self.violations.append("MISSING_AUTH_CHECK")

        self.generic_visit(node)


def run_ast_security_checks(code_str: str, active_rules: List[str] | None = None) -> List[str]:
    """
    Parse code_str into AST and run SecurityVisitor.

    Filters the raw visitor violations down to the rule family that is
    actually active for this task (SQLI, SECRETS, MISSING_AUTH, NO_TRANSACTION, XSS).
    """
    if active_rules is None:
        active_rules = []

    try:
        tree = ast.parse(code_str)
    except SyntaxError:
        return ["SYNTAX_ERROR_PREVENTS_SECURITY_SCAN"]

    visitor = SecurityVisitor()
    visitor.visit(tree)

    # Multi-write transaction heuristic
    if visitor.write_operations_count > 1:
        visitor.violations.append("NO_TRANSACTION_FOR_MULTI_WRITE")

    unique_violations = list(set(visitor.violations))
    relevant: List[str] = []

    for v in unique_violations:
        if "SQLI" in active_rules and v.startswith("SQLI"):
            relevant.append(v)
        elif "SECRETS" in active_rules and v == "HARDCODED_SECRETS":
            relevant.append(v)
        elif "MISSING_AUTH" in active_rules and v == "MISSING_AUTH_CHECK":
            relevant.append(v)
        elif "NO_TRANSACTION" in active_rules and v == "NO_TRANSACTION_FOR_MULTI_WRITE":
            relevant.append(v)
        elif "XSS" in active_rules and v == "POTENTIAL_XSS":
            relevant.append(v)

    return relevant
