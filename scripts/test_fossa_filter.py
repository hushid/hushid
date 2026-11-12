#!/usr/bin/env python3
"""Tests for scripts/fossa-filter.py."""

import json
import os
import subprocess
import sys
import tempfile

FILTER = os.path.join(os.path.dirname(__file__), "fossa-filter.py")


def run_filter(issues, stderr=""):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as handle:
        json.dump(issues, handle)
        handle.flush()
        json_path = handle.name
    stderr_path = ""
    if stderr:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as handle:
            handle.write(stderr)
            handle.flush()
            stderr_path = handle.name
    command = [sys.executable, FILTER, json_path]
    if stderr_path:
        command.append(stderr_path)
    result = subprocess.run(command, capture_output=True, text=True)
    os.unlink(json_path)
    if stderr_path:
        os.unlink(stderr_path)
    return result.returncode, result.stdout


def test_empty_issues():
    rc, out = run_filter([])
    assert rc == 0, out
    assert "0 issue(s)" in out


def test_empty_issues_with_stderr_fail():
    rc, out = run_filter([], stderr="license problem\n")
    assert rc == 1, out
    assert "listed no issue" in out
    assert "license problem" in out


def test_llvm_exception_filtered():
    issues = [
        {"revisionId": "cargo+cc$1.0.106", "license": "apache-2.0 WITH llvm-exception", "type": "policy_conflict"},
        {"revisionId": "cargo+compiler_builtins$0.1.139", "license": "Apache-2.0 WITH LLVM-exception", "type": "policy_conflict"},
    ]
    rc, out = run_filter(issues)
    assert rc == 0, out
    assert "2 issue(s)" in out


def test_r_efi_filtered():
    issues = [
        {"revisionId": "cargo+r-efi$5.3.0", "license": "LGPL-2.1-or-later", "type": "policy_flag"},
    ]
    rc, out = run_filter(issues)
    assert rc == 0, out


def test_ring_and_aws_lc_filtered():
    issues = [
        {"revisionId": "cargo+ring$0.17.8", "license": "openssl-ssleay", "type": "policy_flag"},
        {"revisionId": "cargo+aws-lc-sys$0.22.0", "license": "GPL-1.0-only", "type": "policy_conflict"},
    ]
    rc, out = run_filter(issues)
    assert rc == 0, out


def test_unknown_crate_not_filtered():
    issues = [
        {"revisionId": "cargo+mystery-crate$0.1.0", "license": "apache-2.0 WITH llvm-exception", "type": "policy_conflict"},
    ]
    rc, out = run_filter(issues)
    assert rc == 1, out
    assert "mystery-crate" in out


def test_genuine_issue_not_filtered():
    issues = [
        {"revisionId": "cargo+shady-crate$0.1.0", "license": "GPL-3.0", "type": "policy_conflict"},
    ]
    rc, out = run_filter(issues)
    assert rc == 1, out
    assert "1 genuine" in out


def test_mixed_issues():
    issues = [
        {"revisionId": "cargo+r-efi$5.3.0", "license": "LGPL-2.1-or-later", "type": "policy_flag"},
        {"revisionId": "cargo+bad-crate$1.0.0", "license": "AGPL-3.0", "type": "policy_conflict"},
    ]
    rc, out = run_filter(issues)
    assert rc == 1, out
    assert "bad-crate" in out
    assert "1 genuine" in out


def test_object_wrapper():
    rc, out = run_filter({"issues": [
        {"revisionId": "cargo+cc$1.0.106", "license": "apache-2.0 WITH llvm-exception", "type": "policy_conflict"},
    ]})
    assert rc == 0, out


def test_invalid_json():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as handle:
        handle.write("not-json")
        handle.flush()
        path = handle.name
    result = subprocess.run([sys.executable, FILTER, path], capture_output=True, text=True)
    os.unlink(path)
    assert result.returncode == 1, result.stdout
    assert "not JSON" in result.stdout


if __name__ == "__main__":
    tests = [name for name in globals() if name.startswith("test_")]
    failed = 0
    for name in sorted(tests):
        try:
            globals()[name]()
        except AssertionError as exc:
            print(f"FAIL {name}: {exc}")
            failed += 1
        else:
            print(f"PASS {name}")
    print(f"{len(tests) - failed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
