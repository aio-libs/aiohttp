#!/usr/bin/env python

import argparse
import hashlib
import pathlib
import sys

PARSER = argparse.ArgumentParser(
    description="Helper for check file hashes in Makefile instead of bare timestamps"
)
PARSER.add_argument("dst", metavar="DST", type=pathlib.Path)
PARSER.add_argument("-d", "--debug", action="store_true", default=False)


def main(argv):
    args = PARSER.parse_args(argv)
    dst = args.dst
    assert dst.suffix == ".hash"
    dirname = dst.parent
    if dirname.name != ".hash":
        if args.debug:
            print(f"Invalid name {dst} -> dirname {dirname}", file=sys.stderr)
        return 0
    dirname.mkdir(exist_ok=True)
    src_dir = dirname.parent
    src_name = dst.stem  # drop .hash
    full_src = src_dir / src_name
    hasher = hashlib.sha256()
    try:
        hasher.update(full_src.read_bytes())
    except OSError:
        if args.debug:
            print(f"Cannot open {full_src}", file=sys.stderr)
        return 0
    src_hash = hasher.hexdigest()
    if dst.exists():
        dst_hash = dst.read_text()
    else:
        dst_hash = ""
    if src_hash != dst_hash:
        dst.write_text(src_hash)
        print(f"re-hash {src_hash}")
    else:
        if args.debug:
            print(f"Skip {src_hash} checksum, up-to-date")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
