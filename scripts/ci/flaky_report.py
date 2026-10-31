#!/usr/bin/env python3
"""Nightly flaky-test report from GitHub Actions metadata.

A run is a flaky signal when its first attempt failed and a later attempt on
the same commit succeeded. The tests that failed in the first attempt are read
from that attempt's failed job logs, and each one gets a single open issue
titled ``flaky: <test>`` with the ``flaky`` label, updated with a comment per
new occurrence.

This only reports. It never skips, retries or marks a test as passed, so a
flaky test can never count as green on money or security paths.
"""

import datetime
import json
import os
import re
import subprocess

LABEL = "flaky"
FAILED_TEST = re.compile(r"^test (\S+) \.\.\. FAILED\b", re.MULTILINE)
PANIC_HEADER = re.compile(r"^---- (\S+) stdout ----$", re.MULTILINE)
# GitHub prefixes each log line with an ISO timestamp; strip it before matching.
TIMESTAMP = re.compile(r"^\S*\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z ", re.MULTILINE)
MAX_TESTS_PER_RUN = 20


def failed_tests(log):
    """Return the sorted, de-duplicated test names that failed in a job log."""
    text = TIMESTAMP.sub("", log or "")
    names = set(FAILED_TEST.findall(text)) | set(PANIC_HEADER.findall(text))
    return sorted(names)[:MAX_TESTS_PER_RUN]


def is_flaky_signal(first_attempt, latest):
    """First attempt failed and a later attempt on the same commit passed."""
    return (latest.get("run_attempt", 1) > 1
            and latest.get("conclusion") == "success"
            and first_attempt.get("conclusion") == "failure"
            and first_attempt.get("head_sha") == latest.get("head_sha"))


def issue_title(test):
    return f"flaky: {test}"


def occurrence_line(run, test):
    return (f"- {run['created_at'][:10]} `{test}` failed in attempt 1 and passed in "
            f"attempt {run['run_attempt']} of [{run['name']}]({run['html_url']}) "
            f"on `{run['head_sha'][:7]}` ({run.get('head_branch') or 'detached'})")


def github_api(endpoint, *, method="GET", payload=None, paginate=False, raw=False, key=None):
    """Use the runner's gh authentication. With `key`, pages are objects whose
    `key` array is flattened (the Actions runs endpoint)."""
    command = ["gh", "api", "--method", method, endpoint]
    if paginate:
        command += ["--paginate", "--slurp"]
    if payload is not None:
        command += ["--input", "-"]
    result = subprocess.run(command, input=json.dumps(payload) if payload is not None else None,
                            text=True, capture_output=True, check=True)
    if raw:
        return result.stdout
    data = json.loads(result.stdout)
    return [item for page in data for item in (page[key] if key else page)] if paginate else data


def collect(repository, since, *, api=github_api):
    """Return {test: [occurrence lines]} for flaky signals created since `since`."""
    root = f"repos/{repository}"
    runs = api(f"{root}/actions/runs?status=completed&created=>={since}&per_page=100",
               paginate=True, key="workflow_runs")
    found = {}
    for run in runs:
        if run.get("run_attempt", 1) <= 1 or run.get("conclusion") != "success":
            continue
        first = api(f"{root}/actions/runs/{run['id']}/attempts/1")
        if not is_flaky_signal(first, run):
            continue
        jobs = api(f"{root}/actions/runs/{run['id']}/attempts/1/jobs?per_page=100")
        for job in jobs.get("jobs", []):
            if job.get("conclusion") != "failure":
                continue
            log = api(f"{root}/actions/jobs/{job['id']}/logs", raw=True)
            for test in failed_tests(log):
                found.setdefault(test, []).append(occurrence_line(run, test))
    return found


def report(repository, found, *, api=github_api):
    """Open one issue per flaky test, or comment new occurrences on the open one."""
    root = f"repos/{repository}"
    issues = api(f"{root}/issues?state=open&labels={LABEL}&per_page=100", paginate=True)
    by_title = {issue["title"]: issue for issue in issues if "pull_request" not in issue}
    for test, lines in sorted(found.items()):
        body = "\n".join(sorted(set(lines)))
        issue = by_title.get(issue_title(test))
        if issue is None:
            api(f"{root}/issues", method="POST", payload={
                "title": issue_title(test), "labels": [LABEL],
                "body": ("Nightly flaky-test report: this test failed and then passed on a "
                         "re-run of the same commit. It is not skipped or quarantined from "
                         "CI; fix the cause, then close this issue.\n\n" + body),
            })
            print(f"opened: {issue_title(test)}")
        else:
            api(f"{root}/issues/{issue['number']}/comments", method="POST",
                payload={"body": "New occurrences:\n\n" + body})
            print(f"updated: #{issue['number']} {issue_title(test)}")


if __name__ == "__main__":
    hours = int(os.environ.get("FLAKY_LOOKBACK_HOURS", "24"))
    since = (datetime.datetime.now(datetime.timezone.utc)
             - datetime.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    repo = os.environ["GITHUB_REPOSITORY"]
    report(repo, collect(repo, since))
