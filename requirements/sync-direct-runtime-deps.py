#!/usr/bin/env python
"""Sync direct runtime dependencies from setup.cfg to runtime-deps.in."""

from configparser import ConfigParser
from pathlib import Path

cfg = ConfigParser()
cfg.read(Path("setup.cfg"))
reqs = cfg["options"]["install_requires"] + cfg.items("options.extras_require")[0][1]
reqs = sorted(reqs.split("\n"), key=str.casefold)
reqs.remove("")

with open(Path("requirements", "runtime-deps.in"), "w") as outfile:
    header = "# Extracted from `setup.cfg` via `make sync-direct-runtime-deps`\n\n"
    outfile.write(header)
    outfile.write("\n".join(reqs) + "\n")
