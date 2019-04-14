"""PEP 517 build backend pre-installing extra build deps if possible."""
import functools
import os
import pathlib

from setuptools.build_meta import (
    build_sdist,
    build_wheel,
    get_requires_for_build_sdist,
    get_requires_for_build_wheel,
    prepare_metadata_for_build_wheel,
)
import toml

from . import maybe_install_pkgs


def get_optional_build_deps():
    """Grab optional build dependencies from pyproject.toml config.

    This basically reads entries from:

        [tool.fortunate-pkg.build-system]
        optionally-requires = ["optional-dist"]
    """
    cwd_path = os.path.realpath(os.getcwd())
    with open(os.path.join(cwd_path, 'pyproject.toml')) as config_file:
        pyproject_config = toml.load(config_file)
    return (
        pyproject_config['tool']['fortunate-pkg']['build-system'].
        get('optionally-requires', [])
    )


def get_build_env_location():
    """Identify the current virtualenv path.

    Based on the current file path, find out where it's installed. This
    method seems to be more reliable than others.

    Other ways to do this include:
    1) Using ``__file__`` from ``pip`` and ``setuptools``
    2) Grabbing the value of the ``PYTHONPATH`` environment variable
    """
    overlay_venv_path = (
        pathlib.Path(__file__) / '..' / '..' / '..' / '..' / '..'
    ).resolve()
    return overlay_venv_path


def try_having_optional_build_deps(f):
    """Try installing optional build deps ignoring the outcome.

    The list is sourced from:

        [tool.fortunate-pkg.build-system]
        optionally-requires = ["optional-dist"]
    """
    @functools.wraps(f)
    def w(*args, **kwargs):
        optional_build_deps = get_optional_build_deps()
        build_env_location = get_build_env_location()
        maybe_install_pkgs(*optional_build_deps, where=build_env_location)
        return f(*args, **kwargs)
    return w


build_sdist = try_having_optional_build_deps(build_sdist)
build_wheel = try_having_optional_build_deps(build_wheel)
