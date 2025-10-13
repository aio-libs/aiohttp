#!/usr/bin/env python
"""Sync direct runtime dependencies from pyproject.toml to runtime-deps.in."""

import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

data = tomllib.loads(Path("pyproject.toml").read_text())
reqs = (
    data["project"]["dependencies"]
    + data["project"]["optional-dependencies"]["speedups"]
)
reqs = sorted(reqs, key=str.casefold)

with open(Path("requirements", "runtime-deps.in"), "w") as outfile:
    header = "# Extracted from `pyproject.toml` via `make sync-direct-runtime-deps`\n\n"
    outfile.write(header)
    outfile.write("\n".join(reqs) + "\n")
