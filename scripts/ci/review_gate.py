#!/usr/bin/env python3
"""Compute the review-gate commit status using only GitHub API metadata."""

import json
import os
from pathlib import Path
import re
import subprocess


FAMILIES = {
    "CLAUDE": "CLAUDE", "FABLE": "CLAUDE", "OPUS": "CLAUDE",
    "CODEX": "CODEX",
    "GROK": "CURSOR", "COMPOSER": "CURSOR", "CURSOR": "CURSOR",
}
VERDICT = re.compile(
    r"(CLAUDE|FABLE|OPUS|CODEX|GROK|COMPOSER|CURSOR)-VERDICT (PASS|FAIL) ([0-9a-fA-F]{40})"
)
MONEY_DIRS = ("crates/konsensus-lightning/", "crates/konsensus-crypto/")
MONEY_TERMS = ("spend_budget", "pairing", "invoice", "session")


def evaluate(head_sha, branch, labels, files, comments, authors=""):
    """Return (state, description); never execute or inspect file contents."""
    labels = {label.lower() for label in labels}
    builders = {family for family in set(FAMILIES.values())
                if f"builder:{family.lower()}" in labels}
    if len(builders) == 1:
        builder = next(iter(builders))
    elif builders:
        builder = None  # Conflicting labels must not silently pick a builder.
    else:
        builder = ("CURSOR" if branch.startswith("cursor/") else
                   "CLAUDE" if branch.startswith("cloud/") else None)
    short_sha = head_sha[:7]
    if builder is None:
        return "pending", f"builder unknown on {short_sha}; set builder:claude|codex|cursor"

    # This is an honest-system gate until per-vendor GitHub Apps exist:
    # an allowed author can claim any vendor; the tag does not prove provenance.
    allowed = ({author.strip().casefold() for author in authors.split(",")
                if author.strip()} if authors.strip() else None)
    latest = {}
    for comment in comments:
        if allowed is not None and comment["user"]["login"].casefold() not in allowed:
            continue
        lines = (comment.get("body") or "").splitlines()
        match = VERDICT.fullmatch(lines[0]) if lines else None
        if not match or match[3].lower() != head_sha.lower():
            continue
        family = FAMILIES[match[1]]
        # Edits count as new verdicts; IDs break ties within the same second.
        order = (comment.get("updated_at") or comment["created_at"], comment["id"])
        if family not in latest or order > latest[family][0]:
            latest[family] = (order, match[2])

    failures = sorted(family for family, (_, outcome) in latest.items()
                      if family != builder and outcome == "FAIL")
    if failures:
        return "failure", f"{', '.join(failures)} FAIL on {short_sha}"
    passes = {family for family, (_, outcome) in latest.items()
              if family != builder and outcome == "PASS"}
    others = set(FAMILIES.values()) - {builder}

    # Follow the rule's docs-only exception before money/security classification.
    docs_only = bool(files) and all(path.endswith(".md") or path.startswith("docs/")
                                    for path in files)
    if docs_only:
        if passes:
            return "success", f"docs-only: non-builder PASS on {short_sha}"
        return "pending", f"needs 1 non-builder PASS ({' or '.join(sorted(others))}) on {short_sha}"

    sensitive = bool(labels & {"money", "security"}) or any(
        path.startswith(MONEY_DIRS) or any(term in path for term in MONEY_TERMS)
        for path in files
    )
    required = "CLAUDE" if builder == "CODEX" else "CODEX"
    if sensitive and required not in passes:
        return "pending", f"needs {required} PASS on {short_sha} (2 non-builder families required)"
    if len(passes) < 2:
        missing = " and ".join(sorted(others - passes))
        return "pending", f"needs {missing} PASS on {short_sha}"
    return "success", f"2 non-builder families PASS on {short_sha}"


def github_api(endpoint, *, method="GET", payload=None, paginate=False):
    """Use the runner's gh authentication; slurp every page before evaluating."""
    command = ["gh", "api", "--method", method, endpoint]
    if paginate:
        command += ["--paginate", "--slurp"]
    if payload is not None:
        command += ["--input", "-"]
    result = subprocess.run(command, input=json.dumps(payload) if payload is not None else None,
                            text=True, capture_output=True, check=True)
    data = json.loads(result.stdout)
    return [item for page in data for item in page] if paginate else data


def run_gate(event_name, event, repository, authors="", *, api=github_api):
    """Read a fresh PR snapshot and publish a status on its actual head SHA."""
    root = f"repos/{repository}"

    def post(sha, state, description):
        api(f"{root}/statuses/{sha}", method="POST", payload={
            "context": "review-gate", "state": state, "description": description,
        })
        print(f"review-gate {sha[:7]}: {state}: {description}")

    if event_name == "merge_group":
        post(event["merge_group"]["head_sha"], "success",
             "PR review gate enforced before enqueue")
        return
    if event_name == "issue_comment":
        if "pull_request" not in event["issue"]:
            return
        number = event["issue"]["number"]
    elif event_name == "pull_request":
        number = event["number"]
    else:
        raise ValueError(f"Unsupported event: {event_name}")

    endpoint = f"{root}/pulls/{number}"
    pr = api(endpoint)
    sha = pr["head"]["sha"]
    # Clear any previous success before API reads; errors leave this pending.
    post(sha, "pending", f"computing review gate on {sha[:7]}")
    files = api(f"{endpoint}/files?per_page=100", paginate=True)
    comments = api(f"{root}/issues/{number}/comments?per_page=100", paginate=True)
    current = api(endpoint)
    if (current["head"]["sha"] != sha or current["head"]["ref"] != pr["head"]["ref"]
            or {label["name"] for label in current["labels"]}
            != {label["name"] for label in pr["labels"]}
            or current["changed_files"] != pr["changed_files"]):
        post(current["head"]["sha"], "pending", "PR changed; waiting for a fresh review-gate run")
        return
    # GitHub caps this endpoint at 3,000 files. Never classify a partial list.
    if len(files) != pr["changed_files"]:
        post(sha, "pending", f"file list incomplete on {sha[:7]}; cannot evaluate reviews")
        return
    paths = [file[key] for file in files for key in ("filename", "previous_filename")
             if key in file]
    state, description = evaluate(sha, pr["head"]["ref"],
                                  [label["name"] for label in pr["labels"]],
                                  paths, comments, authors)
    post(sha, state, description)


if __name__ == "__main__":
    run_gate(os.environ["GITHUB_EVENT_NAME"],
             json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text()),
             os.environ["GITHUB_REPOSITORY"], os.environ.get("REVIEW_GATE_AUTHORS", ""))
