#!/usr/bin/env python3
"""Post-apply full-file delta scan for externally generated patches.

The custom checks in this file are advisory heuristics. Established scanners
should be run separately for blocking security policy.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ast_security import run_custom_heuristic_checks
from tg_swebench_cli import normalize_patch_text

ACTIVE_RULES = ["SQLI", "SECRETS", "MISSING_AUTH", "NO_TRANSACTION", "XSS", "WEAK_RNG"]


def _run(cmd: List[str], cwd: Optional[Path] = None, input_text: Optional[str] = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, input=input_text, text=True, capture_output=True, check=False)


def _load_dataset_index(dataset_name: str, split: str) -> Dict[str, Dict[str, Any]]:
    from datasets import load_dataset
    ds = load_dataset(dataset_name, split=split)
    return {
        str(row["instance_id"]): {"repo": row.get("repo"), "base_commit": row.get("base_commit")}
        for row in ds if row.get("instance_id")
    }


def _ensure_repo(repo_cache: Path, repo: str) -> Path:
    repo_dir = repo_cache / repo.replace("/", "__")
    if repo_dir.exists(): return repo_dir
    repo_dir.parent.mkdir(parents=True, exist_ok=True)
    proc = _run(["git", "clone", f"https://github.com/{repo}.git", str(repo_dir)])
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())
    return repo_dir


def _prepare_worktree(repo_dir: Path, worktree_dir: Path, base_commit: str) -> None:
    shutil.rmtree(worktree_dir, ignore_errors=True)
    _run(["git", "worktree", "prune"], cwd=repo_dir)
    proc = _run(["git", "worktree", "add", "--detach", str(worktree_dir), base_commit], cwd=repo_dir)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())


def _scan(code: str) -> List[str]:
    return run_custom_heuristic_checks(code, ACTIVE_RULES)


def _scan_file(worktree: Path, rel: str) -> Tuple[List[str], List[str], List[str]]:
    before_proc = _run(["git", "show", f"HEAD:{rel}"], cwd=worktree)
    before = before_proc.stdout if before_proc.returncode == 0 else ""
    after_path = worktree / rel
    after = after_path.read_text(encoding="utf-8") if after_path.exists() else ""
    before_findings = _scan(before)
    after_findings = _scan(after)
    new_findings = sorted(set(after_findings) - set(before_findings))
    return before_findings, after_findings, new_findings


def _load_predictions(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list): return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        out = []
        for key, value in data.items():
            row = dict(value) if isinstance(value, dict) else {"model_patch": value}
            row.setdefault("instance_id", key); out.append(row)
        return out
    raise ValueError("unsupported predictions shape")


def scan_instance(rec: Dict[str, Any], meta: Dict[str, Any], repo_cache: Path, worktree_root: Path) -> Dict[str, Any]:
    instance_id = str(rec.get("instance_id"))
    patch = normalize_patch_text(str(rec.get("model_patch", "")))
    report: Dict[str, Any] = {
        "schema_version": "2.0",
        "instance_id": instance_id,
        "repo": meta.get("repo"),
        "base_commit": meta.get("base_commit"),
        "scan_scope": "postapply_fullfile_delta_custom_heuristics_v2",
        "scan_failed": False,
        "scan_error": None,
        "changed_files": [],
        "files": [],
        "findings": [],
        "advisory_only": True,
    }
    if not patch.strip():
        report["scan_failed"] = True; report["scan_error"] = "empty patch"; return report
    if not meta.get("repo") or not meta.get("base_commit"):
        report["scan_failed"] = True; report["scan_error"] = "missing repository metadata"; return report

    worktree = worktree_root / instance_id.replace("/", "__")
    try:
        repo_dir = _ensure_repo(repo_cache, str(meta["repo"]))
        _prepare_worktree(repo_dir, worktree, str(meta["base_commit"]))
        check = _run(["git", "apply", "--check", "-"], cwd=worktree, input_text=patch)
        if check.returncode != 0:
            raise RuntimeError("patch validation failed: " + (check.stderr.strip() or check.stdout.strip()))
        apply = _run(["git", "apply", "--whitespace=nowarn", "-"], cwd=worktree, input_text=patch)
        if apply.returncode != 0:
            raise RuntimeError(apply.stderr.strip() or apply.stdout.strip())
        diff = _run(["git", "diff", "--name-only"], cwd=worktree)
        if diff.returncode != 0: raise RuntimeError(diff.stderr.strip() or diff.stdout.strip())
        changed = [x.strip() for x in diff.stdout.splitlines() if x.strip()]
        report["changed_files"] = changed
        all_new: List[str] = []
        for rel in changed:
            if not rel.endswith(".py"): continue
            before, after, new = _scan_file(worktree, rel)
            report["files"].append({"path": rel, "before_findings": before, "after_findings": after, "new_findings": new})
            all_new.extend(new)
        report["findings"] = sorted(set(all_new))
    except Exception as exc:
        report["scan_failed"] = True; report["scan_error"] = str(exc)
    finally:
        shutil.rmtree(worktree, ignore_errors=True)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run advisory custom heuristic scans on externally generated patches.")
    parser.add_argument("--preds", required=True)
    parser.add_argument("--dataset", default="princeton-nlp/SWE-bench_Lite")
    parser.add_argument("--split", default="test")
    parser.add_argument("--outdir", required=True)
    parser.add_argument("--repo-cache-dir", default=".guardian_repo_cache")
    args = parser.parse_args()

    predictions = _load_predictions(Path(args.preds))
    index = _load_dataset_index(args.dataset, args.split)
    outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)
    cache = Path(args.repo_cache_dir); worktrees = cache / "worktrees"; worktrees.mkdir(parents=True, exist_ok=True)
    for rec in predictions:
        instance_id = str(rec.get("instance_id"))
        report = scan_instance(rec, index.get(instance_id, {}), cache, worktrees)
        (outdir / f"{instance_id}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"{instance_id}: completed={not report['scan_failed']} findings={len(report['findings'])}")


if __name__ == "__main__": main()
