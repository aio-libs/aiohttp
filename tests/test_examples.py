#!/usr/bin/env python3
"""Smoke tests for examples folder.

These tests run examples as subprocess invocations to verify they complete
without errors or warnings. They are excluded from the main test suite and
can be run separately with:

    pytest -m example --numprocesses=0

Note: --numprocesses=0 is required because examples use hardcoded ports.
"""

from __future__ import annotations

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


SELF_CONTAINED_EXAMPLES = [
    ExampleConfig("rate_limit_middleware.py", timeout=60),
    ExampleConfig("logging_middleware.py", timeout=30),
    ExampleConfig("retry_middleware.py", timeout=60),
    ExampleConfig("basic_auth_middleware.py", timeout=30),
    ExampleConfig("digest_auth_qop_auth.py", timeout=30),
    ExampleConfig("combined_middleware.py", timeout=60),
    ExampleConfig("token_refresh_middleware.py", timeout=60),
]


def _run_example(example_path: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON, str(example_path)],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(example_path.parent),
    )


@pytest.mark.example
@pytest.mark.parametrize(
    "config",
    SELF_CONTAINED_EXAMPLES,
    ids=[e.name for e in SELF_CONTAINED_EXAMPLES],
)
def test_example_runs_successfully(config: ExampleConfig) -> None:
    """Verify example completes without errors."""
    example_path = EXAMPLES_DIR / config.name
    assert example_path.exists(), f"Example not found: {example_path}"

    result = _run_example(example_path, config.timeout)

    assert result.returncode == 0, (
        f"Example {config.name} failed with exit code {result.returncode}\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
