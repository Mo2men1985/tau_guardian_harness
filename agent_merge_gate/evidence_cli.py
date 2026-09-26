"""CLI for Phase 3 deterministic evidence collection."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .container_runner import DEFAULT_IMAGE
from .deterministic_evidence import collect_deterministic_evidence, verdict_exit_code


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run deterministic evidence collection for one exact Git candidate."
    )
    parser.add_argument("--repo-path", default=".")
    parser.add_argument("--repository", required=True, help="owner/name")
    parser.add_argument("--base", required=True, help="base ref or exact SHA")
    parser.add_argument("--candidate", required=True, help="candidate ref or exact SHA")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--runner-image", default=DEFAULT_IMAGE)
    args = parser.parse_args()

    intake, bundle, execution = collect_deterministic_evidence(
        repo_path=args.repo_path,
        repository=args.repository,
        base_ref=args.base,
        candidate_ref=args.candidate,
        output_dir=args.output_dir,
        image=args.runner_image,
    )

    summary = {
        "candidate_sha": intake.audit_target.candidate_sha,
        "diff_sha256": intake.audit_target.diff_sha256,
        "decision": bundle.decision.decision,
        "reason_codes": list(bundle.decision.reason_codes),
        "bundle_sha256": bundle.bundle_sha256,
        "semantic_fingerprint_sha256": execution["semantic_fingerprint_sha256"],
        "runner_image_id": execution["runner_image_id"],
    }
    print(json.dumps(summary, sort_keys=True))
    return verdict_exit_code(bundle.decision.decision)


if __name__ == "__main__":
    raise SystemExit(main())
