#!/usr/bin/env python3

import sys
from pathlib import Path

ALLOWED_SUFFIXES = [".feature", ".bugfix", ".doc", ".removal", ".misc"]


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
        if fname.name in (".gitignore", ".TEMPLATE.rst"):
            continue
        if fname.suffix not in ALLOWED_SUFFIXES:
            if not failed:
                print("")
            print(fname, "has illegal suffix", file=sys.stderr)
            failed = True

    if failed:
        print("", file=sys.stderr)
        print("Allowed suffixes are:", ALLOWED_SUFFIXES, file=sys.stderr)
        print("", file=sys.stderr)
    else:
        print("OK")

    return int(failed)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
