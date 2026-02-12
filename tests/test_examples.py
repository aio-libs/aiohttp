#!/usr/bin/env python3
"""Tests for examples folder.

All examples are self-contained and run as subprocesses to verify they
complete without errors or warnings.

All tests are marked with @pytest.mark.example. Run them with:

    pytest -m example
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

import pytest

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
PYTHON = sys.executable


class ExampleConfig(NamedTuple):
    name: str
    timeout: int = 30

    def __str__(self) -> str:
        return self.name


SELF_CONTAINED_EXAMPLES = [
    ExampleConfig("rate_limit_middleware", timeout=60),
    ExampleConfig("logging_middleware", timeout=30),
    ExampleConfig("retry_middleware", timeout=60),
    ExampleConfig("basic_auth_middleware", timeout=30),
    ExampleConfig("digest_auth_qop_auth", timeout=30),
    ExampleConfig("combined_middleware", timeout=60),
    ExampleConfig("token_refresh_middleware", timeout=60),
    ExampleConfig("fake_server", timeout=30),
    ExampleConfig("web_srv", timeout=30),
    ExampleConfig("server_simple", timeout=30),
    ExampleConfig("web_srv_route_deco", timeout=30),
    ExampleConfig("web_srv_route_table", timeout=30),
    ExampleConfig("web_cookies", timeout=30),
    ExampleConfig("web_classview", timeout=30),
    ExampleConfig("web_rewrite_headers_middleware", timeout=30),
    ExampleConfig("static_files", timeout=30),
    ExampleConfig("cli_app", timeout=30),
    ExampleConfig("lowlevel_srv", timeout=30),
    ExampleConfig("background_tasks", timeout=30),
    ExampleConfig("web_ws", timeout=30),
    ExampleConfig("client_json", timeout=30),
    ExampleConfig("client_auth", timeout=30),
    ExampleConfig("curl", timeout=30),
    ExampleConfig("client_ws", timeout=30),
]


def _build_subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(EXAMPLES_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _run_example(module_name: str, timeout: int) -> None:
    subprocess.check_output(
        [
            PYTHON,
            "-Werror",
            "-Wignore::DeprecationWarning:audioop",
            "-m",
            module_name,
        ],
        stderr=subprocess.STDOUT,
        timeout=timeout,
        env=_build_subprocess_env(),
    )


@pytest.mark.example
@pytest.mark.parametrize("config", SELF_CONTAINED_EXAMPLES, ids=str)
def test_example_runs_successfully(config: ExampleConfig) -> None:
    """Verify self-contained example completes without errors or warnings."""
    _run_example(config.name, config.timeout)
