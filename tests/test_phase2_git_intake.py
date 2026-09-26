import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from agent_merge_gate import MergeGateError, build_git_intake


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@pytest.fixture
def real_repo(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "tests@example.com")
    git(repo, "config", "user.name", "Agent Merge Gate Tests")

    write(
        repo / "pyproject.toml",
        """[project]
name = "fixture"
version = "0.1.0"
dependencies = ["fastapi", "pytest"]
""",
    )
    write(repo / "tests" / "test_smoke.py", "def test_smoke():\n    assert True\n")
    write(repo / "app" / "core.py", "def value():\n    return 1\n")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "base")
    common = git(repo, "rev-parse", "HEAD")

    git(repo, "switch", "-c", "feature")
    write(
        repo / "app" / "auth.py",
        """def can_delete(user):
    return user.get("role") == "admin"
""",
    )
    git(repo, "add", ".")
    git(repo, "commit", "-m", "feature auth")
    candidate = git(repo, "rev-parse", "HEAD")

    git(repo, "switch", "main")
    write(repo / "docs" / "release.md", "# release\n")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "base advanced")
    base = git(repo, "rev-parse", "HEAD")

    return repo, common, base, candidate


def test_real_diverged_git_history_normalizes_deterministically(real_repo):
    repo, common, base, candidate = real_repo

    first = build_git_intake(
        repo_path=repo,
        repository="owner/repo",
        base_ref=base,
        candidate_ref=candidate,
    )
    second = build_git_intake(
        repo_path=repo,
        repository="owner/repo",
        base_ref="main",
        candidate_ref="feature",
    )

    assert first.to_dict() == second.to_dict()
    assert first.digest == second.digest
    assert first.merge_base_sha == common
    assert first.audit_target.base_sha == base
    assert first.audit_target.candidate_sha == candidate

    assert [item.path for item in first.changed_files] == ["app/auth.py"]
    assert first.changed_files[0].status == "A"
    assert set(first.changed_files[0].classifications) == {"AUTH", "BUSINESS_LOGIC"}
    assert first.change_classifications == ("AUTH", "BUSINESS_LOGIC")
    assert first.languages == (("Python", 1),)
    assert first.dependency_manifests == ("pyproject.toml",)
    assert first.frameworks == ("FastAPI", "pytest")
    assert first.test_commands == ("python -m pytest -q",)

    expected_diff = subprocess.run(
        [
            "git",
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-renames",
            common,
            candidate,
            "--",
        ],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    assert first.audit_target.diff_sha256 == hashlib.sha256(expected_diff).hexdigest()


def test_candidate_inventory_classifies_real_changed_files(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "tests@example.com")
    git(repo, "config", "user.name", "Agent Merge Gate Tests")

    write(repo / "app.py", "print('ok')\n")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")

    write(repo / "requirements.txt", "fastapi==0.1\n")
    write(repo / "migrations" / "001_create.sql", "create table x(id int);\n")
    write(repo / ".github" / "workflows" / "deploy.yml", "name: deploy\n")
    write(repo / "config" / "secrets.py", "TOKEN_NAME = 'service-token'\n")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "candidate")
    candidate = git(repo, "rev-parse", "HEAD")

    intake = build_git_intake(
        repo_path=repo,
        repository="owner/repo",
        base_ref=base,
        candidate_ref=candidate,
    )

    assert "DEPENDENCY" in intake.change_classifications
    assert "MIGRATION" in intake.change_classifications
    assert "DATABASE" in intake.change_classifications
    assert "INFRA" in intake.change_classifications
    assert "SECRETS" in intake.change_classifications
    assert intake.dependency_manifests == ("requirements.txt",)
    assert intake.migration_files == ("migrations/001_create.sql",)
    assert intake.infrastructure_files == (".github/workflows/deploy.yml",)
    assert intake.security_sensitive_files == ("config/secrets.py",)


def test_cli_writes_canonical_json(real_repo, tmp_path: Path):
    repo, _, base, candidate = real_repo
    output = tmp_path / "intake.json"

    subprocess.run(
        [
            "python",
            "-m",
            "agent_merge_gate.intake_cli",
            "--repo-path",
            str(repo),
            "--repository",
            "owner/repo",
            "--base",
            base,
            "--candidate",
            candidate,
            "--output",
            str(output),
        ],
        check=True,
    )

    payload = output.read_text(encoding="utf-8")
    parsed = json.loads(payload)
    assert parsed["audit_target"]["base_sha"] == base
    assert parsed["audit_target"]["candidate_sha"] == candidate
    assert payload == json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"


def test_non_repository_path_fails_closed(tmp_path: Path):
    with pytest.raises(MergeGateError):
        build_git_intake(
            repo_path=tmp_path,
            repository="owner/repo",
            base_ref="main",
            candidate_ref="feature",
        )
