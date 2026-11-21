#!/usr/bin/env python3
"""List new lockfile crate names and check their allowlist entries."""

import argparse
from pathlib import Path
import tomllib


def crate_names(path):
    with path.open("rb") as lockfile:
        lock = tomllib.load(lockfile)
    return {package["name"] for package in lock.get("package", [])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-lock", type=Path, required=True)
    parser.add_argument("--head-lock", type=Path, required=True)
    parser.add_argument("--allowlist", type=Path, required=True)
    args = parser.parse_args()

    try:
        new_names = crate_names(args.head_lock) - crate_names(args.base_lock)
        allowed = {
            line.strip()
            for line in args.allowlist.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(f"Cannot read crate inputs: {error}")

    if not new_names:
        print("No new crate names.")
        return 0

    print("New crate names:")
    for name in sorted(new_names):
        status = "allowlisted" if name in allowed else "not allowlisted"
        print(f"- {name} ({status})")
    return 1 if new_names - allowed else 0


if __name__ == "__main__":
    raise SystemExit(main())
