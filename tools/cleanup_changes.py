#!/usr/bin/env python

# Run me after the backport branch release to cleanup CHANGES records
# that was backported and published.

import re
import subprocess
from pathlib import Path

ALLOWED_SUFFIXES = ["feature", "bugfix", "doc", "removal", "misc"]
PATTERN = re.compile(r"(\d+)\.(" + "|".join(ALLOWED_SUFFIXES) + r")(\.\d+)?(\.rst)?")


def main():
    root = Path(__file__).parent.parent
    delete = []
    changes = (root / "CHANGES.rst").read_text()
    for fname in (root / "CHANGES").iterdir():
        match = PATTERN.match(fname.name)
        if match is not None:
            num = match.group(1)
            tst = f"`#{num} <https://github.com/aio-libs/aiohttp/issues/{num}>`_"
            if tst in changes:
                subprocess.run(["git", "rm", fname])
                delete.append(fname.name)
    print("Deleted CHANGES records:", " ".join(delete))
    print("Please verify and commit")


if __name__ == "__main__":
    main()
