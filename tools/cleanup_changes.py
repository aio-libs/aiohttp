#!/usr/bin/env python

# Run me after the backport branch release to cleanup CHANGES records
# that was backported and publiched.

import subprocess
from pathlib import Path


def main():
    root = Path(__file__).parent.parent
    delete = []
    changes = (root / "CHANGES.rst").read_text()
    for fname in (root / "CHANGES").iterdir():
        if fname.name.startswith("."):
            continue
        if fname.stem in changes:
            subprocess.run(["git", "rm", fname])
            delete.append(fname.name)
    print("Deleted CHANGES records:", " ".join(delete))
    print("Please verify and commit")


if __name__ == "__main__":
    main()
