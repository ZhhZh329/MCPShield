"""Run MCPShield v2 experiments."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run_exp_file(exp_path: Path) -> None:
    import run_exp

    out_dir = run_exp.run_exp(exp_path)
    print(f"[main] output_dir: {out_dir}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="MCPShield v2 runner")
    parser.add_argument("--exp", type=Path, help="Run a single exp file")
    args = parser.parse_args(argv[1:])

    default_exp = ROOT / "experiments" / "test" / "exp_attack.yaml"
    exp_path = args.exp or default_exp
    if not exp_path.exists():
        print(f"Missing exp file: {exp_path}")
        return 1

    run_exp_file(exp_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
