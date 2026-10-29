#!/usr/bin/env python3
"""Public GitHub factory dashboard. Runtime dependencies: gh and Python stdlib.

Verdicts follow the review gate (scripts/ci/review_gate.py): a line that is
exactly `<VENDOR>-VERDICT PASS|FAIL <40-hex sha>` (surrounding spaces/tabs
allowed) anywhere outside quotes and fenced or indented code, from a login in
REVIEW_GATE_AUTHORS when it has any entries (whatever its author_association),
else from an OWNER/MEMBER/COLLABORATOR. Only known vendors count:
CLAUDE/FABLE/OPUS/SONNET/ANTHROPIC are Anthropic; CODEX/OPENAI are OpenAI;
GEMINI/GOOGLE are Google; GROK/COMPOSER/CURSOR are the gate's Cursor family;
XAI is xAI.

First-verdict rate: one earliest verdict per PR (any vendor/head), whose posting
falls in the rolling seven-day window, including open, merged and closed PRs.
The body as originally posted is not available, so comments that were edited
(updated_at differs from created_at) are ignored for this metric only; the
earliest unedited verdict counts instead. Review bodies carry no edit time and
always count. Current-head verdicts use posting time, not edit time.
CI aggregates latest head checks/statuses, excluding review-gate and review/*.
Titles are cut to 120 characters; if the body would still exceed 65,000
characters, the oldest open-PR rows are dropped and counted in a "more" line.
The E2E result is the newest completed main run, even while another is running.
No local factory files, model calls, PR checkout, or comment writes are used.
"""
import argparse
from datetime import datetime, timedelta, timezone
import html
import json
import os
import re
import statistics
import subprocess
import sys
from urllib.parse import urlencode


LABEL = "harness-state"
TITLE = "Factory state (auto)"
E2E_WORKFLOW = "three-node-paid-e2e.yml"
FAMILIES = {
    "CODEX": "openai", "OPENAI": "openai",
    "CLAUDE": "anthropic", "FABLE": "anthropic", "ANTHROPIC": "anthropic",
    "OPUS": "anthropic", "SONNET": "anthropic",
    "GEMINI": "google", "GOOGLE": "google",
    # The review gate treats GROK/COMPOSER/CURSOR as one CURSOR family.
    "GROK": "cursor", "COMPOSER": "cursor", "CURSOR": "cursor", "XAI": "xai",
}
VERDICT = re.compile(
    "(" + "|".join(sorted(FAMILIES)) + r")-VERDICT (PASS|FAIL) ([0-9a-fA-F]{40})"
)
TRUSTED_ASSOCIATIONS = ("OWNER", "MEMBER", "COLLABORATOR")
TITLE_LIMIT = 120
BODY_LIMIT = 65000
# Bidirectional embedding/override/isolate controls and directional marks.
BIDI = re.compile("[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def parse_allowlist(authors):
    """Casefolded logins, or None when the list has no non-blank entries."""
    allowed = {author.strip().casefold() for author in (authors or "").split(",")}
    allowed.discard("")
    return allowed or None


def is_trusted_author(entry, allowed):
    """Same rule as the review gate; entries without a user never count."""
    user = entry.get("user")
    login = user.get("login") if isinstance(user, dict) else None
    if not isinstance(login, str) or not login:
        return False
    if allowed is not None:
        return login.casefold() in allowed
    return entry.get("author_association") in TRUSTED_ASSOCIATIONS


def prose_lines(body):
    """Ignore fenced examples; anchored parsers also reject block quotes."""
    fence = None
    # GitHub breaks lines only at "\n"; never split at U+2028 or U+0085.
    for line in (body or "").replace("\r\n", "\n").split("\n"):
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if marker:
            token = marker[1]
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            continue
        if fence is None:
            yield line


def verdicts(pr, allowed=None):
    found = []
    for entry in pr.get("comments", []) + pr.get("reviews", []):
        posted = entry.get("submitted_at") or entry.get("created_at")
        if not posted or not is_trusted_author(entry, allowed):
            continue  # Pending review drafts are not published verdicts.
        edited = entry.get("updated_at") not in (None, entry.get("created_at"))
        for line in prose_lines(entry.get("body")):
            indent = len(line) - len(line.lstrip(" \t"))
            if "\t" in line[:indent] or indent >= 4:
                continue  # Indented code block.
            match = VERDICT.fullmatch(line.strip(" \t\r"))
            if match:
                vendor, result, sha = match.groups()
                found.append({"vendor": vendor, "result": result, "sha": sha.lower(),
                              "created_at": posted, "id": entry.get("id", 0),
                              "edited": edited})
    return sorted(found, key=lambda v: (timestamp(v["created_at"]), v["id"]))


def rollup(states):
    states = list(states)
    if not states:
        return "missing"
    if any(s in {"failure", "error", "cancelled", "timed_out", "action_required",
                 "startup_failure", "stale"} for s in states):
        return "failure"
    if any(s in {"pending", "queued", "in_progress", "waiting", "requested"} for s in states):
        return "pending"
    if all(s in {"success", "neutral", "skipped"} for s in states):
        return "success"
    return "unknown"


def head_status(pr):
    latest = {}
    for status in pr.get("statuses", []):
        key = ("status", status["context"])
        if key not in latest or status["id"] > latest[key]["id"]:
            latest[key] = status
    for check in pr.get("check_runs", []):
        key = ("check", check["name"], (check.get("app") or {}).get("id"))
        if key not in latest or check["id"] > latest[key]["id"]:
            latest[key] = check
    gate, ci = [], []
    for key, item in latest.items():
        name = key[1].lower()
        state = (item.get("conclusion") if item.get("status") == "completed"
                 else item.get("status")) if key[0] == "check" else item["state"]
        if name == "review-gate":
            gate.append(state)
        elif not name.startswith("review/"):
            ci.append(state)
    return rollup(gate), rollup(ci)


def short_title(title):
    title = str(title)
    return title if len(title) <= TITLE_LIMIT else title[:TITLE_LIMIT - 1] + "\u2026"


def compute_state(data, now, authors=""):
    cutoff = now - timedelta(days=7)
    allowed = parse_allowlist(authors)
    open_prs, first = [], []
    merges = {"last_24h": 0, "last_7d": 0}
    for pr in data["pulls"]:
        recorded = [v for v in verdicts(pr, allowed) if timestamp(v["created_at"]) <= now]
        unedited = [v for v in recorded if not v["edited"]]
        if unedited and timestamp(unedited[0]["created_at"]) >= cutoff:
            first.append(unedited[0]["result"])
        merged = pr.get("merged_at")
        if merged:
            age = now - timestamp(merged)
            merges["last_24h"] += int(timedelta(0) <= age <= timedelta(hours=24))
            merges["last_7d"] += int(timedelta(0) <= age <= timedelta(days=7))
        if pr["state"] != "open":
            continue
        sha = pr["head"]["sha"].lower()
        current = {}
        for verdict in recorded:
            if verdict["sha"] == sha:
                family = FAMILIES[verdict["vendor"]]
                current[family] = {k: v for k, v in verdict.items()
                                   if k not in ("id", "edited")}
        labels = sorted(label["name"] for label in pr["labels"])
        builder = next((label for label in labels if re.match(r"^builder[:/-]", label, re.I)), None)
        merge_state = (pr.get("mergeable_state") or "unknown").upper()
        known = merge_state != "UNKNOWN"
        gate, ci = head_status(pr)
        open_prs.append({
            "number": pr["number"], "title": short_title(pr["title"]), "head_sha": sha,
            "age_hours": round(max(0, (now - timestamp(pr["created_at"])).total_seconds() / 3600), 2),
            "draft": pr["draft"], "labels": labels, "builder_label": builder,
            "verdicts": dict(sorted(current.items())), "review_gate": gate, "ci": ci,
            "mergeable_state": merge_state,
            "behind": merge_state == "BEHIND" if known else None,
            "dirty": merge_state == "DIRTY" if known else None,
        })
    completed = [r for r in data["e2e_runs"]
                 if r["head_branch"] == "main" and r["status"] == "completed"]
    last = max(completed, key=lambda r: (r["created_at"], r["id"]), default=None)
    tasks = [match[1].lower() == "x" for line in prose_lines(data["checklist_body"])
             if (match := re.match(r"^\s*(?:[-*+]|\d+[.)])\s+\[([ xX])\](?:\s|$)", line))]
    return {
        "repository": data["repository"],
        "generated_at": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "open_prs": sorted(open_prs, key=lambda pr: pr["number"]), "merges": merges,
        "median_open_pr_age_hours": statistics.median([pr["age_hours"] for pr in open_prs]) if open_prs else None,
        "first_verdict_7d": {"passed": first.count("PASS"), "total": len(first),
                             "pass_rate": round(first.count("PASS") / len(first), 4) if first else None},
        "three_node_paid_e2e": ({k: last.get(k) for k in
                                ("id", "head_sha", "status", "conclusion", "created_at", "updated_at", "html_url")}
                               if last else None),
        "checklist_428": {"checked": sum(tasks), "total": len(tasks)},
    }


def neutralize(text):
    """Drop bidi controls and break issue references and autolinks."""
    text = BIDI.sub("", str(text))
    # "#1", "owner/repo#5" and "GH-7" would add timeline cross-references.
    text = re.sub(r"#(?=\d)", "#\u200b", text)
    text = re.sub(r"(?i)\b(gh)-(?=\d)", "\\1-\u200b", text)
    text = re.sub(r"(?i)(?<=[a-z])://", ":\u200b//", text)
    return re.sub(r"(?i)\bwww\.", "www\u200b.", text)


def cell(value):
    # GitHub decodes entities before its mention filter. Break the username
    # with a zero-width space as well, so an issue edit cannot ping people.
    text = html.escape(neutralize(value), quote=False).replace("@", "&#64;\u200b")
    text = re.sub(r"([\\`*_\[\]|()])", r"\\\1", text)
    return " ".join(text.split())


def render_markdown(state):
    rate = state["first_verdict_7d"]
    percent = f'{rate["pass_rate"] * 100:.1f}%' if rate["pass_rate"] is not None else "n/a"
    median = state["median_open_pr_age_hours"]
    median = f"{median:.1f} h" if median is not None else "n/a"
    e2e = state["three_node_paid_e2e"]
    checklist = state["checklist_428"]
    # Titles are already cut in compute_state; repeat it for any other caller.
    state = dict(state, open_prs=[dict(pr, title=short_title(pr["title"]))
                                  for pr in state["open_prs"]])
    header = [
        f'**Open: {len(state["open_prs"])} · Median age: {median} · '
        f'Merged 24h/7d: {state["merges"]["last_24h"]}/{state["merges"]["last_7d"]} · '
        f'First-verdict PASS 7d: {percent} ({rate["passed"]}/{rate["total"]}) · '
        f'E2E main: {cell(e2e["conclusion"]) if e2e else "n/a"} · '
        f'#428: {checklist["checked"]}/{checklist["total"]}**', "",
        "| PR | Title | Age (h) | Draft | Labels | Builder | Head verdicts | review-gate | CI | Merge state |",
        "| --- | --- | ---: | --- | --- | --- | --- | --- | --- | --- |",
    ]
    rows = []
    for pr in state["open_prs"]:
        votes = "; ".join(f'{family}: {v["result"]} {v["sha"][:12]}' for family, v in pr["verdicts"].items())
        values = [pr["title"], f'{pr["age_hours"]:.2f}',
                  "yes" if pr["draft"] else "no", ", ".join(pr["labels"]) or "—",
                  pr["builder_label"] or "—", votes or "missing", pr["review_gate"], pr["ci"], pr["mergeable_state"]]
        rows.append(f'| #{int(pr["number"])} | ' + " | ".join(cell(v) for v in values) + " |")
    footer = ["", f'Updated {state["generated_at"]}. First verdict = earliest unedited verdict per PR, '
              "any vendor/head; window is its posting time. CI excludes review contexts; "
              "E2E = latest completed main run.", ""]

    def build(omitted):
        # Rows are sorted by PR number, so the oldest PRs are dropped first.
        shown = dict(state, open_prs=state["open_prs"][omitted:])
        more = []
        if omitted:
            shown["open_prs_omitted"] = omitted
            more = ["", f"\u2026 {omitted} more open PRs (oldest) not shown to fit "
                    "GitHub's issue body limit."]
        # Escape HTML/mentions/backticks even in JSON; json.loads still recovers
        # the exact same data. Repo-controlled text never becomes executable Markdown.
        encoded = json.dumps(shown, ensure_ascii=True, separators=(",", ":"))
        for char in "<>&@`":
            encoded = encoded.replace(char, f"\\u{ord(char):04x}")
        return "\n".join(header + rows[omitted:] + more + footer
                         + ["```json", encoded, "```", ""])

    body = build(0)
    if len(body) > BODY_LIMIT:
        # The size shrinks as rows are dropped: binary-search the fewest drops.
        low, high = 1, len(rows)
        while low < high:
            middle = (low + high) // 2
            if len(build(middle)) <= BODY_LIMIT:
                high = middle
            else:
                low = middle + 1
        body = build(low)
    if len(body) > BODY_LIMIT:
        raise ValueError("report exceeds the GitHub issue body limit even without PR rows")
    return body


class GitHub:
    """Small repository-scoped gh transport; JSON bodies go through stdin."""
    def __init__(self, repo):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise ValueError("repository must be OWNER/REPO")
        self.repo = repo

    def request(self, path, method="GET", payload=None, query=None):
        endpoint = "graphql" if path == "graphql" else f"repos/{self.repo}" + (f"/{path}" if path else "")
        if query:
            endpoint += "?" + urlencode(query)
        command = ["gh", "api", endpoint, "--hostname", "github.com", "--method", method,
                   "-H", "Accept: application/vnd.github+json",
                   "-H", "X-GitHub-Api-Version: 2022-11-28"]
        if payload is not None:
            command += ["--input", "-"]
        result = subprocess.run(command, input=json.dumps(payload) if payload is not None else None,
                                capture_output=True, text=True, timeout=60, check=True)
        response = json.loads(result.stdout)
        if path == "graphql" and (response.get("errors") or not response.get("data")):
            raise RuntimeError("GitHub GraphQL request failed: " + str(response.get("errors")))
        return response

    def pages(self, path, key=None, **query):
        page = 1
        while True:
            response = self.request(path, query={**query, "per_page": 100, "page": page})
            items = response[key] if key else response
            yield items
            if len(items) < 100:
                break
            page += 1

    def list_all(self, path, key=None, **query):
        return [item for page in self.pages(path, key, **query) for item in page]

    def graphql(self, query, **variables):
        return self.request("graphql", "POST", {"query": query, "variables": variables})["data"]


def collect(api, now):
    metadata = api.request("")
    if metadata["visibility"] != "public":
        raise ValueError("harness state only supports public repositories")
    pulls = {}
    for pr in api.list_all("pulls", state="open"):
        detail = api.request(f'pulls/{pr["number"]}')
        pulls[pr["number"]] = detail
    cutoff = now - timedelta(days=7)
    for page in api.pages("pulls", state="closed", sort="updated", direction="desc"):
        for pr in page:
            if timestamp(pr["updated_at"]) < cutoff:
                break
            pulls.setdefault(pr["number"], pr)
        else:
            continue
        break
    for pr in pulls.values():
        number = pr["number"]
        pr["comments"] = api.list_all(f"issues/{number}/comments")
        pr["reviews"] = api.list_all(f"pulls/{number}/reviews")
        if pr["state"] == "open":
            sha = pr["head"]["sha"]
            pr["statuses"] = api.list_all(f"commits/{sha}/statuses")
            pr["check_runs"] = api.list_all(f"commits/{sha}/check-runs", key="check_runs")
    runs = api.request(f"actions/workflows/{E2E_WORKFLOW}/runs", query={
        "branch": "main", "status": "completed", "per_page": 1,
    })["workflow_runs"]
    return {"repository": api.repo, "pulls": list(pulls.values()), "e2e_runs": runs,
            "checklist_body": api.request("issues/428")["body"] or ""}


def publish(api, body):
    issues = [issue for issue in api.list_all("issues", state="open", labels=LABEL)
              if "pull_request" not in issue]
    if len(issues) > 1:
        raise ValueError("multiple open harness-state issues; refusing to choose a dashboard")
    owner, name = api.repo.split("/")
    pinned = api.graphql("""
        query($owner: String!, $name: String!) {
          repository(owner: $owner, name: $name) {
            pinnedIssues(first: 100) { nodes { issue { number } } }
          }
        }
    """, owner=owner, name=name)["repository"]["pinnedIssues"]["nodes"]
    if issues:
        issue = issues[0]
        if issue.get("body") != body:
            api.request(f'issues/{issue["number"]}', "PATCH", {"body": body})
    else:
        if not any(label["name"] == LABEL for label in api.list_all("labels")):
            api.request("labels", "POST", {"name": LABEL, "color": "1d76db",
                                          "description": "Automatically maintained factory state"})
        issue = api.request("issues", "POST", {"title": TITLE, "labels": [LABEL], "body": body})
    if not any(pin["issue"]["number"] == issue["number"] for pin in pinned):
        result = api.graphql("""
            mutation($issueId: ID!) {
              pinIssue(input: {issueId: $issueId}) { issue { number } }
            }
        """, issueId=issue["node_id"])
        if result["pinIssue"]["issue"]["number"] != issue["number"]:
            raise RuntimeError("GitHub did not pin the dashboard issue")
    return issue["number"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"), help="public OWNER/REPO")
    parser.add_argument("--dry-run", action="store_true", help="collect and render without any GitHub writes")
    args = parser.parse_args()
    if not args.repo:
        parser.error("--repo or GITHUB_REPOSITORY is required")
    api = GitHub(args.repo)
    now = datetime.now(timezone.utc)
    authors = os.environ.get("REVIEW_GATE_AUTHORS", "")
    body = render_markdown(compute_state(collect(api, now), now, authors))
    if args.dry_run:
        print(body, end="")
    else:
        number = publish(api, body)
        print(f"Updated factory state: https://github.com/{api.repo}/issues/{number}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as error:
        print(f"harness-state: {error}", file=sys.stderr)
        sys.exit(1)
