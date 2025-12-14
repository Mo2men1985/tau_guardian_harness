"""Run multiple mini-SWE-agent candidates with optional roulette selection."""

from __future__ import annotations

import argparse
import json
import random
import shlex
import subprocess
from pathlib import Path
from typing import List, Sequence

from tg_output_stamp import make_timestamped_dirname


def _build_command(base_cmd: Sequence[str], msa_dir: Path, models: List[str]) -> List[str]:
    cmd = list(base_cmd)
    cmd += ["--msa-dir", str(msa_dir)]
    if models:
        cmd += ["--models", ",".join(models)]
    return cmd


def _run(cmd: List[str]) -> None:
    print(f"[CMD] {' '.join(shlex.quote(part) for part in cmd)}")
    subprocess.run(cmd, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run K mini-SWE-agent candidates")
    parser.add_argument("--instances", default=None, help="Comma-separated instance IDs")
    parser.add_argument("--limit", type=int, default=None, help="Limit instances")
    parser.add_argument("--filter", dest="instance_filter", default=None, help="Instance filter")
    parser.add_argument("--outbase", required=True, help="Base output directory name (msa_runXX)")
    parser.add_argument("--k", type=int, default=3, help="Number of candidates to run")
    parser.add_argument("--models", default=None, help="Comma-separated models for baseline candidate")
    parser.add_argument("--roulette-models", dest="roulette_models", default=None, help="Models for roulette candidate")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for roulette mode")
    parser.add_argument(
        "--base-cmd",
        default="python tg_swebench_cli.py",
        help="Command prefix used to invoke a single mini-SWE run",
    )
    parser.add_argument(
        "--stamp-outdir",
        action="store_true",
        help="Append timestamp to outbase to avoid collisions",
    )

    args = parser.parse_args()

    base_cmd = shlex.split(args.base_cmd)
    outbase = args.outbase
    if args.stamp_outdir:
        outbase = make_timestamped_dirname(outbase)

    models = [m.strip() for m in (args.models or "").split(",") if m.strip()]
    roulette_models = [m.strip() for m in (args.roulette_models or "").split(",") if m.strip()]

    manifest = {
        "outbase": outbase,
        "k": args.k,
        "instances": args.instances,
        "limit": args.limit,
        "filter": args.instance_filter,
        "models": models,
        "roulette_models": roulette_models,
        "seed": args.seed,
        "base_cmd": base_cmd,
        "commands": [],
    }

    for idx in range(1, args.k + 1):
        msa_dir = Path(f"{outbase}_cand{idx}")
        msa_dir.mkdir(parents=True, exist_ok=True)

        cmd = _build_command(base_cmd, msa_dir, models if idx != 2 else roulette_models or models)

        if args.instances:
            cmd += ["--instances", args.instances]
        if args.limit is not None:
            cmd += ["--limit", str(args.limit)]
        if args.instance_filter:
            cmd += ["--filter", args.instance_filter]
        if idx == 2 and roulette_models:
            cmd += ["--roulette", "true", "--seed", str(args.seed)]
            random.seed(args.seed)

        manifest["commands"].append({"candidate": idx, "cmd": cmd, "msa_dir": str(msa_dir)})

        # Execute sequentially to keep logs simple
        _run(cmd)

    manifest_path = Path(f"{outbase}_manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[INFO] Wrote manifest to {manifest_path}")


if __name__ == "__main__":
    main()
