"""Tests for circular imports in all local packages and modules.

This ensures all internal packages can be imported right away without
any need to import some other module before doing so.

This module is based on an idea that pytest uses for self-testing:
* https://github.com/sanitizers/octomachinery/blob/be18b54/tests/circular_imports_test.py
* https://github.com/pytest-dev/pytest/blob/d18c75b/testing/test_meta.py
* https://twitter.com/codewithanthony/status/1229445110510735361
"""  # noqa: E501
import os
import pkgutil
import subprocess
import sys
from itertools import chain
from pathlib import Path
from types import ModuleType
from typing import Generator, List

import pytest

import aiohttp


def _find_all_importables(pkg: ModuleType) -> List[str]:
    """Find all importables in the project.

    Return them in order.
    """
    return sorted(
        set(
            chain.from_iterable(
                _discover_path_importables(Path(p), pkg.__name__) for p in pkg.__path__
            ),
        ),
    )


def _discover_path_importables(
    pkg_pth: Path,
    pkg_name: str,
) -> Generator[str, None, None]:
    """Yield all importables under a given path and package."""
    for dir_path, _d, file_names in os.walk(pkg_pth):
        pkg_dir_path = Path(dir_path)

        if pkg_dir_path.parts[-1] == "__pycache__":
            continue

        if all(Path(_).suffix != ".py" for _ in file_names):
            continue

        rel_pt = pkg_dir_path.relative_to(pkg_pth)
        pkg_pref = ".".join((pkg_name,) + rel_pt.parts)
        yield from (
            pkg_path
            for _, pkg_path, _ in pkgutil.walk_packages(
                (str(pkg_dir_path),),
                prefix=f"{pkg_pref}.",
            )
        )


@pytest.mark.parametrize(
    "import_path",
    _find_all_importables(aiohttp),
)
def test_no_warnings(import_path: str) -> None:
    """Verify that exploding importables doesn't explode.

    This is seeking for any import errors including ones caused
    by circular imports.
    """
    imp_cmd = sys.executable, "-W", "error", "-c", f"import {import_path!s}"

    subprocess.check_call(imp_cmd)
