#!/usr/bin/env python3
"""Drop documented FOSSA license false positives.

Exit 0 when every listed issue is one of these crates. Exit 1 when a
real issue remains, or when a failed scan passed a stderr file and
listed nothing to filter.

The allowlist is the set FOSSA misreads: the LLVM exception on
compiler crates and on dual-licensed crates that also offer plain
Apache-2.0 or MIT, LGPL on r-efi type definitions, the historical
SSLeay marker in ring, GPL test vectors in aws-lc-sys, and the Apple
header marker in security-framework. That crate declares MIT or
Apache-2.0.
"""

import json
import sys

LLVM_EXCEPTION_CRATES = {
    "cc",
    "compiler_builtins",
    "wasi",
    "wasip2",
    "wit-bindgen-core",
    "wit-bindgen-rust",
    "wit-bindgen-rust-macro",
    # Also Apache-2.0 OR MIT. FOSSA reports only the exception form.
    "linux-raw-sys",
    "rustix",
}

LLVM_EXCEPTION_LICENSES = {
    "apache-2.0 WITH llvm-exception",
    "Apache-2.0 WITH LLVM-exception",
}


def license_id(issue):
    value = issue.get("license") or issue.get("licenseId") or ""
    if isinstance(value, dict):
        value = value.get("id") or value.get("name") or ""
    return str(value)


def is_false_positive(pkg, lic):
    if pkg in LLVM_EXCEPTION_CRATES and lic in LLVM_EXCEPTION_LICENSES:
        return True
    if pkg == "r-efi" and lic in ("LGPL-2.1-or-later", "LGPL-2.1+"):
        return True
    if pkg == "ring" and "ssleay" in lic.lower():
        return True
    if pkg == "aws-lc-sys" and lic.startswith("GPL-"):
        return True
    if pkg == "security-framework" and lic == "APSL-2.0":
        return True
    return False


def extract_package(issue):
    rev = issue.get("revisionId", "")
    if rev:
        if "+" in rev:
            rev = rev.split("+", 1)[1]
        if "$" in rev:
            rev = rev.rsplit("$", 1)[0]
        return rev
    return issue.get("package", "") or issue.get("name", "") or ""


def load_issues(path):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        issues = data.get("issues", data.get("issue", []))
        if isinstance(issues, list):
            return issues
    return []


def main():
    if len(sys.argv) < 2:
        print("Usage: fossa-filter.py <fossa-results.json> [stderr]", file=sys.stderr)
        return 2
    try:
        issues = load_issues(sys.argv[1])
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL: FOSSA output was not JSON ({exc})")
        return 1

    stderr_path = sys.argv[2] if len(sys.argv) > 2 else ""
    if stderr_path and not issues:
        print("FAIL: FOSSA test failed and listed no issue.")
        try:
            with open(stderr_path, encoding="utf-8", errors="replace") as handle:
                text = handle.read(2000)
        except OSError as exc:
            print(exc)
            return 1
        if text.strip():
            print(text)
        return 1

    real = []
    filtered = 0
    for issue in issues:
        pkg = extract_package(issue)
        lic = license_id(issue)
        if is_false_positive(pkg, lic):
            filtered += 1
            continue
        real.append((pkg, lic, issue.get("type", "") or issue.get("issueType", "")))

    if real:
        print(f"FAIL: {len(real)} genuine issue(s) after filtering {filtered} known false positives:")
        for pkg, lic, kind in real:
            print(f"  - {pkg}  {lic}  ({kind})")
        return 1

    print(f"OK: All {filtered} issue(s) are documented false positives.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
