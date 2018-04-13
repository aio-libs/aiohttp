#!/usr/bin/env python3

import argparse
import re
import sys
from pathlib import Path


PATTERN = re.compile("\(#(\d+)\)")


def get_root(script_path):
    folder = script_path.absolute().parent
    while not (folder / '.git').exists():
        folder = folder.parent
        if folder == folder.anchor:
            raise RuntimeError("git repo not found")
    return folder


def main(argv):
    parser = argparse.ArgumentParser(description='Expand github links.')
    parser.add_argument('filename', default='CHANGES.rst', nargs='?',
                        help="filename to proess")
    args = parser.parse_args()
    here = Path(argv[0])
    root = get_root(here)
    fname = root / args.filename

    content = fname.read_text()
    new = PATTERN.sub(
        r'(`#\1 <https://github.com/aio-libs/aiohttp/pull/\1>`_)',
        content)

    fname.write_text(new)
    print(f"Fixed links in {fname}")
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
