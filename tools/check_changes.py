#!/usr/bin/env python3

import re
import sys
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


def get_root(script_path):
    folder = script_path.resolve().parent
    while not (folder / ".git").exists():
        folder = folder.parent
        if folder == folder.anchor:
            raise RuntimeError("git repo not found")
    return folder


def main(argv):
    print('Check "CHANGES" folder... ', end="", flush=True)
    here = Path(argv[0])
    root = get_root(here)
    changes = root / "CHANGES"
    failed = False
    for fname in changes.iterdir():
        if fname.name in (".gitignore", ".TEMPLATE.rst", "README.rst"):
            continue
        if not PATTERN.match(fname.name):
            if not failed:
                print("")
            print("Illegal CHANGES record", fname, file=sys.stderr)
            failed = True

    if failed:
        print("", file=sys.stderr)
        print("See ./CHANGES/README.rst for the naming instructions", file=sys.stderr)
        print("", file=sys.stderr)
    else:
        print("OK")

    return int(failed)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
