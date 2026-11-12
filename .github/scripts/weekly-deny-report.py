#!/usr/bin/env python3
"""Open, replace, or close one scheduled check issue.

The default check is weekly cargo deny. Another workflow can set
CHECK_SIGNATURE and the title lines. A green deny run closes only deny
issues, including older issues that have no signature yet.
"""

import json
import os
import re
import subprocess
import sys
from datetime import date, datetime, timezone

LABEL = "nightly-failure"
SIGNATURE = "cargo deny check"
TITLE_PREFIX = "Weekly deny red"
FAILURE_LEAD = "Weekly `cargo deny check` failed."
GREEN_LEAD = "Weekly deny is green"
SUPERSEDE_LEAD = "Superseded by a new weekly deny failure"
STATE_RE = re.compile(r"<!-- nightly-failure-state: (\{.*?\}) -->")


def load_config():
    global SIGNATURE, TITLE_PREFIX, FAILURE_LEAD, GREEN_LEAD, SUPERSEDE_LEAD
    SIGNATURE = os.environ.get("CHECK_SIGNATURE", SIGNATURE)
    TITLE_PREFIX = os.environ.get("CHECK_TITLE", TITLE_PREFIX)
    FAILURE_LEAD = os.environ.get("CHECK_LEAD", FAILURE_LEAD)
    GREEN_LEAD = os.environ.get("CHECK_GREEN", GREEN_LEAD)
    SUPERSEDE_LEAD = os.environ.get("CHECK_SUPERSEDE", SUPERSEDE_LEAD)


def is_this_check(issue):
    found = state_of(issue.get("body")).get("signature")
    if found == SIGNATURE:
        return True
    return not found and SIGNATURE == "cargo deny check"


def gh(args, check=True, input_text=None):
    result = subprocess.run(
        ["gh", *args],
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit(result.returncode)
    return result


def state_of(body):
    match = STATE_RE.search(body or "")
    if not match:
        return {}
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return {}


def open_issues(repo):
    result = gh(
        [
            "issue",
            "list",
            "--repo",
            repo,
            "--label",
            LABEL,
            "--state",
            "open",
            "--limit",
            "20",
            "--json",
            "number,body",
        ]
    )
    issues = json.loads(result.stdout or "[]")
    return sorted(issues, key=lambda item: item["number"])


def ensure_labels(repo):
    listed = json.loads(
        gh(
            [
                "label",
                "list",
                "--repo",
                repo,
                "--limit",
                "100",
                "--json",
                "name",
            ]
        ).stdout
        or "[]"
    )
    present = {item["name"] for item in listed}
    for name, color in ((LABEL, "B60205"), ("ready", "0E8A16")):
        if name in present:
            continue
        gh(
            [
                "label",
                "create",
                name,
                "--repo",
                repo,
                "--color",
                color,
            ]
        )


def close_issue(repo, number, comment):
    gh(
        [
            "issue",
            "close",
            str(number),
            "--repo",
            repo,
            "--reason",
            "completed",
            "--comment",
            comment,
        ]
    )


def body_for(run_url, first_failed_on, day):
    started = date.fromisoformat(first_failed_on)
    current = date.fromisoformat(day)
    days = (current - started).days + 1
    state = {
        "first_failed_on": first_failed_on,
        "day": day,
        "signature": SIGNATURE,
    }
    title_days = f" ({days} consecutive days)" if days > 1 else ""
    body = (
        f"{FAILURE_LEAD}\n\n"
        f"Run: {run_url}\n\n"
        f"<!-- nightly-failure-state: {json.dumps(state, separators=(',', ':'))} -->\n"
    )
    return f"{TITLE_PREFIX}{title_days}", body


def create_issue(repo, assignee, title, body):
    args = [
        "issue",
        "create",
        "--repo",
        repo,
        "--title",
        title,
        "--label",
        f"{LABEL},ready",
        "--body",
        body,
    ]
    if assignee:
        args.extend(["--assignee", assignee])
    result = gh(args, check=False)
    if result.returncode != 0 and assignee:
        sys.stderr.write(result.stderr)
        args = [arg for arg in args if arg != "--assignee" and arg != assignee]
        gh(args)
        return
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit(result.returncode)
    print(result.stdout.strip())


def main():
    load_config()
    result = os.environ.get("CHECK_RESULT", os.environ.get("DENY_RESULT", ""))
    if not result:
        raise SystemExit("CHECK_RESULT is unset")
    repo = os.environ["REPO"]
    run_url = os.environ["RUN_URL"]
    assignee = os.environ.get("ASSIGNEE", "")
    day = datetime.now(timezone.utc).date().isoformat()
    print(f"PLAN: {SIGNATURE} result {result} on {day}")
    if result == "cancelled":
        print("OK: cancelled")
        return
    ensure_labels(repo)
    issues = [issue for issue in open_issues(repo) if is_this_check(issue)]
    if result == "success":
        print(f"DO: close {len(issues)} open issues for {SIGNATURE}")
        for issue in issues:
            close_issue(repo, issue["number"], f"{GREEN_LEAD}: {run_url}")
        print("OK: green")
        return
    if result != "failure":
        print(f"OK: ignored result {result}")
        return
    today = [
        issue
        for issue in issues
        if state_of(issue.get("body")).get("day") == day
        and state_of(issue.get("body")).get("signature") == SIGNATURE
    ]
    if today:
        current = today[-1]
        print(f"DO: update #{current['number']}")
        prior = state_of(current.get("body"))
        title, body = body_for(run_url, prior.get("first_failed_on", day), day)
        gh(
            [
                "issue",
                "edit",
                str(current["number"]),
                "--repo",
                repo,
                "--title",
                title,
                "--body",
                body,
            ]
        )
        print("OK: updated")
        return
    first = day
    if issues:
        prior = state_of(issues[-1].get("body"))
        first = prior.get("first_failed_on", day)
        for issue in issues:
            print(f"DO: supersede #{issue['number']}")
            gh(
                [
                    "issue",
                    "close",
                    str(issue["number"]),
                    "--repo",
                    repo,
                    "--reason",
                    "not planned",
                    "--comment",
                    f"{SUPERSEDE_LEAD}: {run_url}",
                ]
            )
    title, body = body_for(run_url, first, day)
    print(f"DO: create {SIGNATURE} issue")
    create_issue(repo, assignee, title, body)
    print("OK: filed")


if __name__ == "__main__":
    main()
