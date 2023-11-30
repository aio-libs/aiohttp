"""An early plugin enabling pytest-xdist in supported envs."""

from contextlib import suppress
from sys import platform
from typing import TYPE_CHECKING, List

try:
    from asyncio import ThreadedChildWatcher
except ImportError:
    SUPPORTS_XDIST = platform == "win32"
else:
    SUPPORTS_XDIST = True
    del ThreadedChildWatcher


if TYPE_CHECKING:
    from _pytest.config import Config
    from _pytest.config.argparsing import Parser


import pytest


@pytest.hookimpl(tryfirst=True)  # type: ignore[misc]
def pytest_load_initial_conftests(
    early_config: "Config",
    parser: "Parser",
    args: List[str],
) -> None:
    """Auto-enable pytest-xdist when supported and not disabled."""
    if not SUPPORTS_XDIST:
        return

    with suppress(ValueError):
        p_pos = args.index("no:xdist") - 1
        if p_pos >= 0:
            # NOTE: allow disabling xdist with `-p no:xdist`
            return

    xdist_args = "-n", "auto"
    args[:0] = xdist_args  # Prepend to allow user-supplied overrides

    # NOTE: Unregistering pytest-cov is necessary to avoid it being
    # NOTE: initialized with parallelism disabled because it gets
    # NOTE: initialized first.
    early_config.pluginmanager.unregister(
        early_config.pluginmanager.get_plugin("_cov"),
        "_cov",
    )
    early_config.pluginmanager.unregister(
        early_config.pluginmanager.get_plugin("_cov_contexts"),
        "_cov_contexts",
    )

    # NOTE: Updating the args in parser will help pytest-cov
    # NOTE: detect pytest-xdist.
    parser.parse_known_and_unknown_args(
        args,
        early_config.known_args_namespace,
    )
    with suppress(ImportError):
        import pytest_cov.plugin  # type: ignore[import]

        pytest_cov.plugin.pytest_load_initial_conftests(
            early_config,
            parser,
            args,
        )
