#!/usr/bin/env python3
"""Fail once a waived advisory passes its deadline, for each scanner config.

cargo-audit and cargo-deny have no expiry for an ignore, so a waiver there would
stay silent forever. .cargo/waiver-deadlines.toml holds the dates. This check:

  - needs a deadline for every ignore in .cargo/audit.toml, deny.toml and
    osv-scanner.toml, and rejects a deadline nothing uses
  - needs each OSV `ignoreUntil` to equal its deadline
  - fails on and after the deadline day (UTC), the same day osv-scanner stops
    honouring `ignoreUntil` on a UTC runner
  - warns during the WARN_DAYS before a deadline, because this check gates releases

Exit 0 prints "WAIVER-DEADLINES: OK". Any problem prints a "WAIVER-DEADLINES:
EXPIRED" or "WAIVER-DEADLINES: ERROR" line and exits 1. Problems never pass silently:
a missing file or a config it cannot read is an error.

Usage: scripts/check-waiver-deadlines.py [--root DIR] [--tool NAME] [--today YYYY-MM-DD]
--root and --today exist for tests. CI passes neither.
"""

import argparse
import datetime as dt
import os
import sys
import tomllib
from pathlib import Path

WARN_DAYS = 30
DEADLINES = ".cargo/waiver-deadlines.toml"
TOOLS = {
    "cargo-audit": ".cargo/audit.toml",
    "cargo-deny": "deny.toml",
    "osv-scanner": "osv-scanner.toml",
}


def load(root, relative):
    with open(root / relative, "rb") as file:
        return tomllib.load(file)


def ignored_ids(tool, config):
    """Return the waived ids for one scanner config."""
    if tool == "osv-scanner":
        return [entry["id"] for entry in config.get("IgnoredVulns", [])]
    entries = config.get("advisories", {}).get("ignore", [])
    return [entry if isinstance(entry, str) else entry["id"] for entry in entries]


def load_deadlines(root, errors):
    """Return {advisory id: deadline} from the one source of dates."""
    deadlines = {}
    for waiver in load(root, DEADLINES).get("waiver", []):
        deadline = waiver["deadline"]
        if type(deadline) is not dt.date:
            errors.append(f"{DEADLINES}: {waiver['ids']} needs a plain date deadline")
            continue
        for advisory in waiver["ids"]:
            if advisory in deadlines:
                errors.append(f"{DEADLINES}: {advisory} is listed twice")
            deadlines[advisory] = deadline
    return deadlines


def check(root, selected, today):
    errors, expired, warnings = [], [], []
    deadlines = load_deadlines(root, errors)
    configs = {tool: load(root, path) for tool, path in TOOLS.items()}
    ids_by_tool = {tool: ignored_ids(tool, config) for tool, config in configs.items()}

    used = {advisory for ids in ids_by_tool.values() for advisory in ids}
    for advisory in sorted(set(deadlines) - used):
        errors.append(f"{DEADLINES}: {advisory} is not waived anywhere; remove it")

    for tool in selected:
        for advisory in ids_by_tool[tool]:
            deadline = deadlines.get(advisory)
            if deadline is None:
                errors.append(f"{tool}: {advisory} has no deadline in {DEADLINES}")
            elif today >= deadline:
                expired.append(f"{tool}: {advisory} deadline {deadline} (today {today})")
            elif (deadline - today).days <= WARN_DAYS:
                warnings.append(f"{tool}: {advisory} expires on {deadline}")

    if "osv-scanner" in selected:
        for entry in configs["osv-scanner"].get("IgnoredVulns", []):
            advisory, until = entry["id"], entry.get("ignoreUntil")
            if advisory in deadlines and until != deadlines[advisory]:
                errors.append(
                    f"osv-scanner: {advisory} ignoreUntil is {until}, "
                    f"expected {deadlines[advisory]}"
                )
    return errors, expired, warnings


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--tool", choices=sorted(TOOLS), action="append")
    parser.add_argument("--today", type=dt.date.fromisoformat)
    args = parser.parse_args()

    today = args.today or dt.datetime.now(dt.timezone.utc).date()
    selected = args.tool or sorted(TOOLS)
    try:
        errors, expired, warnings = check(args.root, selected, today)
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as error:
        print(f"WAIVER-DEADLINES: ERROR cannot read waivers: {error!r}")
        return 1

    prefix = "::warning::" if os.environ.get("GITHUB_ACTIONS") else ""
    for line in warnings:
        print(f"{prefix}WAIVER-DEADLINES: WARNING {line}")
    for line in errors:
        print(f"WAIVER-DEADLINES: ERROR {line}")
    for line in expired:
        print(f"WAIVER-DEADLINES: EXPIRED {line}")
    if errors or expired:
        if expired:
            print(f"Recheck each advisory, then remove the waiver or change {DEADLINES}.")
        return 1
    print(f"WAIVER-DEADLINES: OK {', '.join(selected)} on {today}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
