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
TRUSTED_ASSOCIATIONS = ("OWNER", "MEMBER", "COLLABORATOR")
FENCE = re.compile(r" {0,3}(`{3,}|~{3,})")
# Executable or configuration files under docs/ and the files that define the
# review rules themselves are never "docs-only", whatever their extension.
NOT_DOCS_SUFFIXES = (".sh", ".yml", ".yaml", ".toml")
NOT_DOCS_NAMES = ("contributing.md", "codeowners")


def parse_allowlist(authors):
    """Return the casefolded login allowlist, or None when it has no entries.

    An allowlist made only of blanks or commas (for example ",") is treated
    exactly like an unset variable.
    """
    allowed = {author.strip().casefold() for author in (authors or "").split(",")}
    allowed.discard("")
    return allowed or None


def is_trusted_author(comment, allowed):
    """Allowlisted logins count whatever their association (cursor[bot] is NONE);
    without an allowlist only OWNER/MEMBER/COLLABORATOR count."""
    user = comment.get("user")
    login = user.get("login") if isinstance(user, dict) else None
    if not isinstance(login, str) or not login:
        return False
    if allowed is not None:
        return login.casefold() in allowed
    return comment.get("author_association") in TRUSTED_ASSOCIATIONS


def verdict_lines(body):
    """Yield verdict matches from lines outside fenced or indented code.

    Each line must be exactly the verdict after stripping surrounding spaces,
    tabs and CR; quotes, bold and any other decoration do not match.
    """
    fence = None
    # Split on "\n" only: GitHub does not break lines at U+2028, U+0085, etc.
    for line in (body or "").split("\n"):
        opener = FENCE.match(line)
        if fence is None:
            if opener:
                fence = opener[1]
                continue
        else:
            # A fence closes only with the same character, at least as long.
            closer = line.strip(" \t\r")
            if (opener and closer == opener[1] and closer[0] == fence[0]
                    and len(closer) >= len(fence)):
                fence = None
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        if "\t" in line[:indent] or indent >= 4:
            continue  # Indented code block.
        match = VERDICT.fullmatch(line.strip(" \t\r"))
        if match:
            yield match


def is_docs_path(path):
    """Inclusion stays case-sensitive; exclusions match in any case."""
    lowered = path.casefold()
    if (lowered.startswith(".github/") or lowered.endswith(NOT_DOCS_SUFFIXES)
            or lowered.rsplit("/", 1)[-1] in NOT_DOCS_NAMES):
        return False
    return path.endswith(".md") or path.startswith("docs/")


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
    allowed = parse_allowlist(authors)
    latest = {}
    for comment in comments:
        if not is_trusted_author(comment, allowed):
            continue
        outcomes = {}
        for match in verdict_lines(comment.get("body")):
            if match[3].lower() != head_sha.lower():
                continue
            family = FAMILIES[match[1]]
            # Conflicting verdicts for one family in one comment fail closed.
            if outcomes.get(family) != "FAIL":
                outcomes[family] = match[2]
        # Order by posting time, never by edit time: editing an old verdict
        # must not revive it over a newer one. IDs break same-second ties.
        order = (comment["created_at"], comment["id"])
        for family, outcome in outcomes.items():
            if family not in latest or order > latest[family][0]:
                latest[family] = (order, outcome)

    failures = sorted(family for family, (_, outcome) in latest.items()
                      if family != builder and outcome == "FAIL")
    if failures:
        return "failure", f"{', '.join(failures)} FAIL on {short_sha}"
    passes = {family for family, (_, outcome) in latest.items()
              if family != builder and outcome == "PASS"}
    others = set(FAMILIES.values()) - {builder}

    # Follow the rule's docs-only exception before money/security classification.
    docs_only = bool(files) and all(is_docs_path(path) for path in files)
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
    # Keep full comment objects, including GitHub's author_association.
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
