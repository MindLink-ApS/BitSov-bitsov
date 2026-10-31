#!/usr/bin/env python3
"""PR flow gates computed from GitHub API metadata only.

Two commit statuses keep review capacity, not build capacity, setting the pace:

* ``wip-cap``: only the first WIP_CAP open, non-draft PRs (ranked by priority
  label, then age) get ``success``. Every other open, non-draft PR is
  ``pending`` with its place in the queue. Drafts carry no status.
* ``pr-size``: a PR whose counted diff exceeds PR_SIZE_LIMIT lines fails
  unless it has the ``large-ok`` label and a ``## Design note`` section with
  text. Lockfiles, vendored code, tests, fixtures and test evidence are not
  counted, so adding tests never pushes a PR over the limit.
"""

import fnmatch
import json
import os
from pathlib import Path
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
    "*/fixtures/*", "docs/testing/*", "*.snap", "CHANGELOG.md",
)
DESIGN_NOTE = re.compile(r"^#{2,3}[ \t]+design note[ \t]*$", re.IGNORECASE | re.MULTILINE)


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
    """Return {head_sha: (state, description)} for every open, non-draft PR."""
    active = sorted((pr for pr in prs if pr["state"] == "open" and not pr["draft"]), key=rank)
    statuses = {}
    for position, pr in enumerate(active, start=1):
        sha = pr["head"]["sha"]
        if position <= cap:
            statuses[sha] = ("success", f"in WIP slot {position} of {cap}")
        else:
            statuses[sha] = ("pending", f"queued: {position - cap} beyond WIP cap {cap}; "
                                        "wait, or convert a lower-priority PR to draft")
    return statuses


def is_counted(path):
    return not any(fnmatch.fnmatchcase(path, pattern) for pattern in UNCOUNTED)


def has_design_note(body):
    """True when a '## Design note' heading is followed by at least one text line."""
    match = DESIGN_NOTE.search(body or "")
    if not match:
        return False
    for line in (body or "")[match.end():].split("\n"):
        stripped = line.strip()
        if stripped.startswith("#"):
            return False
        if stripped:
            return True
    return False


def size_status(files, labels, body, limit):
    """Return (state, description) for the pr-size status."""
    counted = sum(f.get("additions", 0) + f.get("deletions", 0)
                  for f in files if is_counted(f["filename"]))
    if counted <= limit:
        return "success", f"{counted} counted lines (limit {limit})"
    if LARGE_OK in {label.casefold() for label in labels} and has_design_note(body):
        return "success", f"{counted} counted lines; large-ok with a design note"
    return "failure", (f"{counted} counted lines > {limit}: split it, or add label "
                       f"{LARGE_OK} and a '## Design note' section")


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


def post(api, root, sha, context, state, description):
    api(f"{root}/statuses/{sha}", method="POST", payload={
        "context": context, "state": state, "description": description[:140],
    })
    print(f"{context} {sha[:7]}: {state}: {description}")


def run_wip_cap(repository, cap, *, api=github_api):
    """Recompute the queue for every open PR; one run settles all of them."""
    root = f"repos/{repository}"
    prs = api(f"{root}/pulls?state=open&per_page=100", paginate=True)
    for sha, (state, description) in wip_statuses(prs, cap).items():
        post(api, root, sha, "wip-cap", state, description)


def run_pr_size(repository, number, limit, *, api=github_api):
    root = f"repos/{repository}"
    endpoint = f"{root}/pulls/{number}"
    pr = api(endpoint)
    sha = pr["head"]["sha"]
    files = api(f"{endpoint}/files?per_page=100", paginate=True)
    # GitHub caps this endpoint at 3,000 files. Never size a partial list.
    if len(files) != pr["changed_files"]:
        post(api, root, sha, "pr-size", "pending", "file list incomplete; cannot size this PR")
        return
    state, description = size_status(files, [label["name"] for label in pr["labels"]],
                                      pr.get("body") or "", limit)
    post(api, root, sha, "pr-size", state, description)


if __name__ == "__main__":
    repo = os.environ["GITHUB_REPOSITORY"]
    gate = os.environ["PR_FLOW_GATE"]
    if gate == "wip-cap":
        run_wip_cap(repo, positive_int(os.environ.get("WIP_CAP"), DEFAULT_WIP_CAP))
    elif gate == "pr-size":
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        run_pr_size(repo, event["pull_request"]["number"],
                    positive_int(os.environ.get("PR_SIZE_LIMIT"), DEFAULT_SIZE_LIMIT))
    else:
        raise SystemExit(f"unknown PR_FLOW_GATE {gate!r}")
