#!/usr/bin/env python

# Run me after the backport branch release to cleanup CHANGES records
# that was backported and published.

import re
import subprocess
from pathlib import Path

ALLOWED_SUFFIXES = (
    "bugfix",
    "feature",
    "deprecation",
    "breaking",
    "doc",
    "packaging",
    "contrib",
    "misc",
)
PATTERN = re.compile(
    r"(\d+|[0-9a-f]{8}|[0-9a-f]{7}|[0-9a-f]{40})\.("
    + "|".join(ALLOWED_SUFFIXES)
    + r")(\.\d+)?(\.rst)?",
)


def main():
    root = Path(__file__).parent.parent
    delete = []
    changes = (root / "CHANGES.rst").read_text()
    for fname in (root / "CHANGES").iterdir():
        match = PATTERN.match(fname.name)
        if match is not None:
            commit_issue_or_pr = match.group(1)
            tst_issue_or_pr = f":issue:`{commit_issue_or_pr}`"
            tst_commit = f":commit:`{commit_issue_or_pr}`"
            if tst_issue_or_pr in changes or tst_commit in changes:
                subprocess.run(["git", "rm", fname])
                delete.append(fname.name)
    print("Deleted CHANGES records:", " ".join(delete))
    print("Please verify and commit")


if __name__ == "__main__":
    main()
