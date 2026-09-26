"""Deterministic Git intake for an exact software candidate.

Phase 2 turns real Git state into a normalized, hash-bound audit target.
It intentionally does not run tests or semantic review; those are later evidence
layers. All Git commands use argv execution without a shell.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import subprocess
import tomllib
from typing import Any

from .common import MergeGateError, canonical_json, require_repository, sha256_json
from .target import AuditTarget

DEPENDENCY_BASENAMES = frozenset({
    "pyproject.toml", "requirements.txt", "requirements-dev.txt", "poetry.lock",
    "pdm.lock", "Pipfile", "Pipfile.lock", "uv.lock",
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "pnpm-lock.yaml", "Cargo.toml", "Cargo.lock", "go.mod", "go.sum",
    "Gemfile", "Gemfile.lock", "pom.xml", "build.gradle", "build.gradle.kts",
})
PYTEST_CONFIGS = frozenset({"pytest.ini", "pyproject.toml", "tox.ini", "setup.cfg"})
DOC_SUFFIXES = frozenset({".md", ".rst", ".txt", ".adoc"})
CODE_SUFFIXES = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rs", ".rb",
    ".php", ".cs", ".c", ".cc", ".cpp", ".h", ".hpp", ".sql", ".sh",
})
LANGUAGE_BY_SUFFIX = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".c": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".h": "C/C++ Header",
    ".hpp": "C++ Header",
    ".sql": "SQL",
    ".sh": "Shell",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".json": "JSON",
    ".toml": "TOML",
}
AUTH_TOKENS = ("auth", "permission", "rbac", "acl", "jwt", "session", "login", "oauth")
DATABASE_TOKENS = ("database", "db/", "models/", "schema", "repository", "repositories")
MIGRATION_TOKENS = ("migration", "migrations/", "alembic/versions/")
API_TOKENS = ("api/", "routes/", "router", "controller", "endpoint", "graphql")
INFRA_TOKENS = (
    ".github/workflows/", "dockerfile", "docker-compose", "terraform", "infra/",
    "deploy/", "deployment", "k8s/", "kubernetes/", "helm/",
)
SECRET_TOKENS = ("secret", "credential", "password", "token", ".env", "private_key")
PERF_TOKENS = ("performance", "benchmark", "latency", "profil", "loadtest", "load_test")


def _run_git(repo_path: Path, *args: str, text: bool = False) -> subprocess.CompletedProcess:
    command = ["git", *args]
    try:
        return subprocess.run(
            command,
            cwd=repo_path,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=text,
            timeout=60,
        )
    except FileNotFoundError as exc:
        raise MergeGateError("GIT_NOT_AVAILABLE") from exc
    except subprocess.TimeoutExpired as exc:
        raise MergeGateError(f"GIT_TIMEOUT: {' '.join(command)}") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr if isinstance(exc.stderr, str) else exc.stderr.decode("utf-8", "replace")
        raise MergeGateError(
            f"GIT_COMMAND_FAILED: {' '.join(command)}: {stderr.strip()}"
        ) from exc


def resolve_commit(repo_path: Path, ref: str) -> str:
    if not isinstance(ref, str) or not ref or "\x00" in ref:
        raise MergeGateError("GIT_REF_INVALID")
    result = _run_git(
        repo_path,
        "rev-parse",
        "--verify",
        "--end-of-options",
        f"{ref}^{{commit}}",
        text=True,
    )
    sha = result.stdout.strip()
    if len(sha) != 40 or any(ch not in "0123456789abcdef" for ch in sha):
        raise MergeGateError(f"GIT_COMMIT_NOT_SHA1: {ref!r}")
    return sha


def merge_base(repo_path: Path, base_sha: str, candidate_sha: str) -> str:
    result = _run_git(repo_path, "merge-base", base_sha, candidate_sha, text=True)
    sha = result.stdout.strip()
    if len(sha) != 40 or any(ch not in "0123456789abcdef" for ch in sha):
        raise MergeGateError("GIT_MERGE_BASE_INVALID")
    return sha


def canonical_diff(repo_path: Path, merge_base_sha: str, candidate_sha: str) -> bytes:
    return _run_git(
        repo_path,
        "diff",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        "--no-renames",
        merge_base_sha,
        candidate_sha,
        "--",
    ).stdout


def candidate_tree_paths(repo_path: Path, candidate_sha: str) -> tuple[str, ...]:
    raw = _run_git(
        repo_path,
        "ls-tree",
        "-r",
        "--name-only",
        "-z",
        candidate_sha,
    ).stdout
    return tuple(
        item.decode("utf-8", "surrogateescape")
        for item in raw.split(b"\x00")
        if item
    )


@dataclass(frozen=True)
class ChangedFile:
    status: str
    path: str
    language: str | None
    classifications: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "path": self.path,
            "language": self.language,
            "classifications": list(self.classifications),
        }


def changed_files(repo_path: Path, merge_base_sha: str, candidate_sha: str) -> tuple[tuple[str, str], ...]:
    raw = _run_git(
        repo_path,
        "diff",
        "--name-status",
        "-z",
        "--no-renames",
        merge_base_sha,
        candidate_sha,
        "--",
    ).stdout
    parts = [item for item in raw.split(b"\x00") if item]
    if len(parts) % 2:
        raise MergeGateError("GIT_NAME_STATUS_MALFORMED")

    rows: list[tuple[str, str]] = []
    for index in range(0, len(parts), 2):
        status = parts[index].decode("ascii", "replace")
        path = parts[index + 1].decode("utf-8", "surrogateescape")
        rows.append((status, path))
    return tuple(rows)


def _lower(path: str) -> str:
    return path.replace("\\", "/").lower()


def _is_test_path(path: str) -> bool:
    p = PurePosixPath(path)
    lower = _lower(path)
    return (
        "tests" in p.parts
        or "test" in p.parts
        or p.name.startswith("test_")
        or p.name.endswith("_test.py")
        or ".test." in p.name
        or ".spec." in p.name
        or lower.startswith("tests/")
    )


def _classify_path(path: str) -> set[str]:
    lower = _lower(path)
    name = PurePosixPath(lower).name
    suffix = PurePosixPath(lower).suffix
    classes: set[str] = set()

    if any(token in lower for token in AUTH_TOKENS):
        classes.add("AUTH")
    if suffix == ".sql" or any(token in lower for token in DATABASE_TOKENS):
        classes.add("DATABASE")
    if any(token in lower for token in MIGRATION_TOKENS):
        classes.add("MIGRATION")
    if any(token in lower for token in API_TOKENS):
        classes.add("API")
    if name in DEPENDENCY_BASENAMES:
        classes.add("DEPENDENCY")
    if any(token in lower for token in INFRA_TOKENS) or suffix == ".tf":
        classes.add("INFRA")
    if any(token in lower for token in SECRET_TOKENS):
        classes.add("SECRETS")
    if any(token in lower for token in PERF_TOKENS):
        classes.add("PERFORMANCE")

    if (
        suffix in CODE_SUFFIXES
        and not _is_test_path(path)
        and "INFRA" not in classes
        and "MIGRATION" not in classes
    ):
        classes.add("BUSINESS_LOGIC")
    return classes


def _language(path: str) -> str | None:
    return LANGUAGE_BY_SUFFIX.get(PurePosixPath(path).suffix.lower())


def _show_text(repo_path: Path, candidate_sha: str, path: str) -> str | None:
    try:
        proc = _run_git(repo_path, "show", f"{candidate_sha}:{path}")
    except MergeGateError:
        return None
    try:
        return proc.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _discover_test_commands(
    repo_path: Path,
    candidate_sha: str,
    tree_paths: tuple[str, ...],
) -> tuple[str, ...]:
    path_set = set(tree_paths)
    commands: list[str] = []

    has_python = any(PurePosixPath(path).suffix == ".py" for path in tree_paths)
    has_tests = any(_is_test_path(path) for path in tree_paths)
    has_root_pytest_config = any(config in path_set for config in PYTEST_CONFIGS)
    if has_python and has_tests and has_root_pytest_config:
        commands.append("python -m pytest -q")

    package_paths = [path for path in tree_paths if PurePosixPath(path).name == "package.json"]
    for package_path in sorted(package_paths):
        text = _show_text(repo_path, candidate_sha, package_path)
        if text is None:
            continue
        try:
            package = json.loads(text)
        except json.JSONDecodeError:
            continue
        test_script = package.get("scripts", {}).get("test") if isinstance(package, dict) else None
        if isinstance(test_script, str) and test_script.strip():
            prefix = str(PurePosixPath(package_path).parent)
            if prefix == ".":
                commands.append("npm test")
            else:
                commands.append(f"npm --prefix {prefix} test")

    return tuple(dict.fromkeys(commands))


def _frameworks(
    repo_path: Path,
    candidate_sha: str,
    tree_paths: tuple[str, ...],
) -> tuple[str, ...]:
    found: set[str] = set()
    if "pyproject.toml" in tree_paths:
        text = _show_text(repo_path, candidate_sha, "pyproject.toml")
        if text:
            try:
                data = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                data = {}
            deps: list[str] = []
            project = data.get("project", {}) if isinstance(data, dict) else {}
            if isinstance(project, dict):
                raw_deps = project.get("dependencies", [])
                if isinstance(raw_deps, list):
                    deps.extend(str(item).lower() for item in raw_deps)
            blob = " ".join(deps)
            for needle, label in (
                ("fastapi", "FastAPI"),
                ("django", "Django"),
                ("flask", "Flask"),
                ("pytest", "pytest"),
                ("sqlalchemy", "SQLAlchemy"),
            ):
                if needle in blob:
                    found.add(label)

    if "package.json" in tree_paths:
        text = _show_text(repo_path, candidate_sha, "package.json")
        if text:
            try:
                package = json.loads(text)
            except json.JSONDecodeError:
                package = {}
            deps = {}
            if isinstance(package, dict):
                for key in ("dependencies", "devDependencies"):
                    value = package.get(key)
                    if isinstance(value, dict):
                        deps.update(value)
            for needle, label in (
                ("react", "React"),
                ("next", "Next.js"),
                ("express", "Express"),
                ("@nestjs/core", "NestJS"),
                ("vitest", "Vitest"),
                ("jest", "Jest"),
            ):
                if needle in deps:
                    found.add(label)
    return tuple(sorted(found))


@dataclass(frozen=True)
class GitIntake:
    schema_version: str
    audit_target: AuditTarget
    merge_base_sha: str
    changed_files: tuple[ChangedFile, ...]
    languages: tuple[tuple[str, int], ...]
    frameworks: tuple[str, ...]
    dependency_manifests: tuple[str, ...]
    migration_files: tuple[str, ...]
    infrastructure_files: tuple[str, ...]
    security_sensitive_files: tuple[str, ...]
    test_commands: tuple[str, ...]
    change_classifications: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "audit_target": self.audit_target.to_dict(),
            "merge_base_sha": self.merge_base_sha,
            "changed_files": [item.to_dict() for item in self.changed_files],
            "languages": {name: count for name, count in self.languages},
            "frameworks": list(self.frameworks),
            "dependency_manifests": list(self.dependency_manifests),
            "migration_files": list(self.migration_files),
            "infrastructure_files": list(self.infrastructure_files),
            "security_sensitive_files": list(self.security_sensitive_files),
            "test_commands": list(self.test_commands),
            "change_classifications": list(self.change_classifications),
        }

    @property
    def digest(self) -> str:
        return sha256_json(self.to_dict())

    def canonical_json(self) -> str:
        return canonical_json(self.to_dict())


def build_git_intake(
    *,
    repo_path: str | Path,
    repository: str,
    base_ref: str,
    candidate_ref: str,
) -> GitIntake:
    require_repository(repository)
    path = Path(repo_path).resolve()
    if not path.is_dir():
        raise MergeGateError(f"REPO_PATH_NOT_DIRECTORY: {path}")

    base_sha = resolve_commit(path, base_ref)
    candidate_sha = resolve_commit(path, candidate_ref)
    mb_sha = merge_base(path, base_sha, candidate_sha)
    diff = canonical_diff(path, mb_sha, candidate_sha)
    diff_sha256 = hashlib.sha256(diff).hexdigest()

    rows = changed_files(path, mb_sha, candidate_sha)
    tree_paths = candidate_tree_paths(path, candidate_sha)

    file_items: list[ChangedFile] = []
    language_counts: dict[str, int] = {}
    all_classes: set[str] = set()
    dependency = sorted(
        path for path in tree_paths if PurePosixPath(path).name in DEPENDENCY_BASENAMES
    )
    migrations: list[str] = []
    infrastructure: list[str] = []
    sensitive: list[str] = []

    for status, changed_path in rows:
        classes = _classify_path(changed_path)
        lang = _language(changed_path)
        if lang:
            language_counts[lang] = language_counts.get(lang, 0) + 1
        all_classes.update(classes)
        if "MIGRATION" in classes:
            migrations.append(changed_path)
        if "INFRA" in classes:
            infrastructure.append(changed_path)
        if classes.intersection({"AUTH", "SECRETS"}):
            sensitive.append(changed_path)
        file_items.append(
            ChangedFile(
                status=status,
                path=changed_path,
                language=lang,
                classifications=tuple(sorted(classes)),
            )
        )

    changed_paths = [item.path for item in file_items]
    if changed_paths and all(_is_test_path(path) for path in changed_paths):
        all_classes.add("TEST_ONLY")
    if changed_paths and all(PurePosixPath(path).suffix.lower() in DOC_SUFFIXES for path in changed_paths):
        all_classes.add("DOCS")

    return GitIntake(
        schema_version="git-intake-v1",
        audit_target=AuditTarget(repository, base_sha, candidate_sha, diff_sha256),
        merge_base_sha=mb_sha,
        changed_files=tuple(file_items),
        languages=tuple(sorted(language_counts.items())),
        frameworks=_frameworks(path, candidate_sha, tree_paths),
        dependency_manifests=tuple(sorted(dependency)),
        migration_files=tuple(sorted(migrations)),
        infrastructure_files=tuple(sorted(infrastructure)),
        security_sensitive_files=tuple(sorted(sensitive)),
        test_commands=_discover_test_commands(path, candidate_sha, tree_paths),
        change_classifications=tuple(sorted(all_classes)),
    )
