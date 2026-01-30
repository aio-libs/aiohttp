#!/usr/bin/env python3
"""Tests for examples folder.

This module contains two types of tests:
1. Smoke tests: Run self-contained examples as subprocesses to verify they
   complete without errors or warnings.
2. Functional tests: Import and test server examples using aiohttp_client.

All tests are marked with @pytest.mark.example and excluded from the main
test suite. Run them separately with:

    pytest -m example --numprocesses=0

Note: --numprocesses=0 is required because examples may use hardcoded ports.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

import pytest

if TYPE_CHECKING:
    from aiohttp.test_utils import TestClient

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
PYTHON = sys.executable

KNOWN_ACCEPTABLE_WARNINGS = [
    "deprecationwarning: 'audioop' is deprecated",
]


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
        [PYTHON, "-W", "error", str(example_path)],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(example_path.parent),
    )


WARNING_PATTERNS = [
    "deprecationwarning",
    "pendingdeprecationwarning",
    "runtimewarning",
    "resourcewarning",
    "syntaxwarning",
    "userwarning",
    "futurewarning",
]


def _has_unexpected_warnings(stderr: str) -> bool:
    stderr_lower = stderr.lower()
    for acceptable in KNOWN_ACCEPTABLE_WARNINGS:
        stderr_lower = stderr_lower.replace(acceptable, "")
    return any(pattern in stderr_lower for pattern in WARNING_PATTERNS)


@pytest.mark.example
@pytest.mark.parametrize(
    "config",
    SELF_CONTAINED_EXAMPLES,
    ids=[e.name for e in SELF_CONTAINED_EXAMPLES],
)
def test_example_runs_successfully(config: ExampleConfig) -> None:
    """Verify self-contained example completes without errors or warnings."""
    example_path = EXAMPLES_DIR / config.name
    assert example_path.exists(), f"Example not found: {example_path}"

    result = _run_example(example_path, config.timeout)

    assert result.returncode == 0, (
        f"Example {config.name} failed with exit code {result.returncode}\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
    assert not _has_unexpected_warnings(
        result.stderr
    ), f"Warnings in {config.name}:\n{result.stderr}"


@pytest.mark.example
async def test_server_simple_routes(aiohttp_client: Any) -> None:
    """Functional test for server_simple.py routes."""
    from examples import server_simple

    app = server_simple.init()
    client: TestClient[Any, Any] = await aiohttp_client(app)

    async with client.get("/") as resp:
        assert resp.status == 200
        text = await resp.text()
        assert text == "Hello, Anonymous"

    async with client.get("/John") as resp:
        assert resp.status == 200
        text = await resp.text()
        assert text == "Hello, John"

    async with client.ws_connect("/echo") as ws:
        await ws.send_str("Hello")
        msg = await ws.receive_str()
        assert msg == "Hello, Hello"


@pytest.mark.example
async def test_web_ws_broadcast(aiohttp_client: Any) -> None:
    """Functional test for web_ws.py broadcasting behavior."""
    from examples import web_ws

    app = web_ws.init()
    client: TestClient[Any, Any] = await aiohttp_client(app)

    async with client.ws_connect("/") as ws1:
        msg = await ws1.receive_str()
        assert msg == "Welcome!!!"

        async with client.ws_connect("/") as ws2:
            msg = await ws2.receive_str()
            assert msg == "Welcome!!!"

            msg = await ws1.receive_str()
            assert msg == "Someone joined"

            await ws1.send_str("Hello")

            msg = await ws2.receive_str()
            assert msg == "Hello"
