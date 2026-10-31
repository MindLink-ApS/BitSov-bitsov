#!/usr/bin/env python3
"""PR flow gates computed from GitHub API metadata only.

Two commit statuses keep review capacity, not build capacity, setting the pace:

* ``wip-cap``: only the first WIP_CAP open, non-draft PRs (ranked by priority
  label, then age) get ``success``. Every other open, non-draft PR is
  ``pending`` with its place in the queue. Drafts get a neutral ``success``
  ("draft: not in the queue") so a status left from before conversion never
  sticks.
* ``pr-size``: a PR whose counted diff exceeds PR_SIZE_LIMIT lines fails
  unless it has the ``large-ok`` label and a ``## Design note`` section with
  text. Lockfiles, vendored code, tests, fixtures and test evidence are not
  counted, so adding tests never pushes a PR over the limit.

One trusted run recomputes every open PR. It runs from the default branch
(schedule, manual dispatch, or after the read-only trigger workflow), so a
fork's read-only pull_request token never has to publish anything and no PR
data is executed or trusted. Statuses are posted only when they change.
"""

import fnmatch
import json
import os
import re
import subprocess

DEFAULT_WIP_CAP = 4
DEFAULT_SIZE_LIMIT = 500
# Lower rank is served first; a PR takes the best rank of its labels.
PRIORITY = {"m6": 0, "deadline": 0, "security": 1, "money": 1, "merge-ready": 2}
UNRANKED = 3
LARGE_OK = "large-ok"
UNCOUNTED = (
    "Cargo.lock", "*.lock", "vendor/*", "*/vendor/*",
    "tests/*", "*/tests/*", "*_tests.rs", "*/tests.rs", "test_*.py", "*/test_*.py",
    "fixtures/*", "*/fixtures/*", "docs/testing/*", "*.snap", "CHANGELOG.md",
)
DESIGN_NOTE = re.compile(r"^#{2,3}[ \t]+design note[ \t]*$", re.IGNORECASE | re.MULTILINE)
# When several open PRs share one head SHA, the commit carries one status per
# context. wip-cap keeps the best (a shared commit is in review if any of its
# PRs holds a slot); pr-size keeps the worst (any PR it fails for fails it).
WIP_ORDER = {"success": 0, "pending": 1}
SIZE_ORDER = {"failure": 0, "pending": 1, "success": 2}


def positive_int(value, default):
    """Parse a repository variable; blank or invalid values use the default."""
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


def rank(pr):
    """Sort key: best priority label, then oldest first, then lowest number."""
    labels = {label["name"].casefold() for label in pr.get("labels", [])}
    best = min((PRIORITY[name] for name in labels if name in PRIORITY), default=UNRANKED)
    return (best, pr["created_at"], pr["number"])


def wip_statuses(prs, cap):
    """Return {head_sha: (state, description)} for every open PR."""
    open_prs = [pr for pr in prs if pr["state"] == "open"]
    active = sorted((pr for pr in open_prs if not pr["draft"]), key=rank)
    per_pr = []
    for position, pr in enumerate(active, start=1):
        if position <= cap:
            per_pr.append((pr["head"]["sha"], "success", f"in WIP slot {position} of {cap}"))
        else:
            per_pr.append((pr["head"]["sha"], "pending",
                           f"queued: {position - cap} beyond WIP cap {cap}; "
                           "wait, or convert a lower-priority PR to draft"))
    for pr in open_prs:
        if pr["draft"]:
            per_pr.append((pr["head"]["sha"], "success", "draft: not in the WIP queue"))
    statuses = {}
    for sha, state, description in per_pr:
        held = statuses.get(sha)
        if held is None or WIP_ORDER[state] < WIP_ORDER[held[0]]:
            statuses[sha] = (state, description)
    return statuses


def is_counted(path):
    return not any(fnmatch.fnmatchcase(path, pattern) for pattern in UNCOUNTED)


def file_is_counted(change):
    """A rename counts if either side is counted: moving code into tests/ is
    still a change to code."""
    paths = [change["filename"]] + ([change["previous_filename"]]
                                    if change.get("previous_filename") else [])
    return any(is_counted(path) for path in paths)


def has_design_note(body):
    """True when a '## Design note' heading is followed by at least one text line."""
    text = (body or "").replace("\r\n", "\n").replace("\r", "\n")
    match = DESIGN_NOTE.search(text)
    if not match:
        return False
    for line in text[match.end():].split("\n"):
        stripped = line.strip()
        if stripped.startswith("#"):
            return False
        if stripped:
            return True
    return False


def size_status(files, labels, body, limit):
    """Return (state, description) for the pr-size status."""
    counted = sum(f.get("additions", 0) + f.get("deletions", 0)
                  for f in files if file_is_counted(f))
    if counted <= limit:
        return "success", f"{counted} counted lines (limit {limit})"
    if LARGE_OK in {label.casefold() for label in labels} and has_design_note(body):
        return "success", f"{counted} counted lines; large-ok with a design note"
    return "failure", (f"{counted} counted lines > {limit}: split it, or add label "
                       f"{LARGE_OK} and a '## Design note' section")


def merge_worst(statuses, sha, state, description):
    held = statuses.get(sha)
    if held is None or SIZE_ORDER[state] < SIZE_ORDER[held[0]]:
        statuses[sha] = (state, description)


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


def publish(api, root, sha, context, state, description):
    """Post a status only when the latest one for this context differs."""
    description = description[:140]
    combined = api(f"{root}/commits/{sha}/status")
    for status in combined.get("statuses", []):
        if status.get("context") == context:
            if status.get("state") == state and status.get("description") == description:
                return False
            break
    api(f"{root}/statuses/{sha}", method="POST", payload={
        "context": context, "state": state, "description": description,
    })
    print(f"{context} {sha[:7]}: {state}: {description}")
    return True


def run_all(repository, cap, limit, *, api=github_api):
    """Recompute both gates for every open PR and publish what changed."""
    root = f"repos/{repository}"
    prs = api(f"{root}/pulls?state=open&per_page=100", paginate=True)
    wip = wip_statuses(prs, cap)
    size = {}
    for pr in prs:
        if pr["state"] != "open":
            continue
        sha = pr["head"]["sha"]
        endpoint = f"{root}/pulls/{pr['number']}"
        detail = api(endpoint)
        if detail["head"]["sha"] != sha:
            continue  # Pushed during this run; the next run sizes the new head.
        files = api(f"{endpoint}/files?per_page=100", paginate=True)
        # GitHub caps this endpoint at 3,000 files. Never size a partial list.
        if len(files) != detail["changed_files"]:
            merge_worst(size, sha, "pending", "file list incomplete; cannot size this PR")
            continue
        merge_worst(size, sha, *size_status(files, [label["name"] for label in detail["labels"]],
                                            detail.get("body") or "", limit))
    for sha, (state, description) in wip.items():
        publish(api, root, sha, "wip-cap", state, description)
    for sha, (state, description) in size.items():
        publish(api, root, sha, "pr-size", state, description)


if __name__ == "__main__":
    run_all(os.environ["GITHUB_REPOSITORY"],
            positive_int(os.environ.get("WIP_CAP"), DEFAULT_WIP_CAP),
            positive_int(os.environ.get("PR_SIZE_LIMIT"), DEFAULT_SIZE_LIMIT))
