#!/usr/bin/env python3
"""Tests for examples folder.

This module contains two types of tests:
1. Smoke tests: Run self-contained examples as subprocesses to verify they
   complete without errors or warnings.
2. Functional tests: Import and test server examples using aiohttp_client.

All tests are marked with @pytest.mark.example. Run them with:

    pytest -m example
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
sys.path.insert(0, str(EXAMPLES_DIR.parent))
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
    ExampleConfig("fake_server.py", timeout=30),
    ExampleConfig("web_srv.py", timeout=30),
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
async def test_client_json(aiohttp_client: Any) -> None:  # type: ignore[misc]
    """Functional test for client_json.py using a mock server."""
    from aiohttp import web
    from examples import client_json  # noqa: I900

    async def json_handler(request: web.Request) -> web.Response:
        return web.json_response({"url": str(request.url), "method": request.method})

    app = web.Application()
    app.router.add_get("/get", json_handler)
    client: TestClient[Any, Any] = await aiohttp_client(app)

    result = await client_json.go(f"{client.make_url('/get')}")
    assert result["method"] == "GET"


@pytest.mark.example
async def test_client_auth(aiohttp_client: Any) -> None:  # type: ignore[misc]
    """Functional test for client_auth.py using a mock server."""
    from aiohttp import BasicAuth, hdrs, web
    from examples import client_auth  # noqa: I900

    async def auth_handler(request: web.Request) -> web.Response:
        auth_header = request.headers.get(hdrs.AUTHORIZATION, "")
        if auth_header:
            auth = BasicAuth.decode(auth_header)
            if auth.login == "andrew" and auth.password == "password":
                return web.Response(text="Authenticated")
        return web.Response(status=401, text="Unauthorized")

    app = web.Application()
    app.router.add_get("/auth", auth_handler)
    client: TestClient[Any, Any] = await aiohttp_client(app)

    result = await client_auth.go(f"{client.make_url('/auth')}")
    assert result == "Authenticated"


@pytest.mark.example
async def test_curl(aiohttp_client: Any) -> None:  # type: ignore[misc]
    """Functional test for curl.py using a mock server."""
    from aiohttp import web
    from examples import curl  # noqa: I900

    async def simple_handler(request: web.Request) -> web.Response:
        return web.Response(text="Hello from curl test")

    app = web.Application()
    app.router.add_get("/", simple_handler)
    client: TestClient[Any, Any] = await aiohttp_client(app)

    await curl.curl(str(client.make_url("/")))


@pytest.mark.example
async def test_background_tasks(aiohttp_client: Any) -> None:  # type: ignore[misc]
    """Functional test for background_tasks.py with valkey disabled."""
    from examples import background_tasks  # noqa: I900

    app = background_tasks.init(skip_valkey=True)
    client: TestClient[Any, Any] = await aiohttp_client(app)

    async with client.ws_connect("/news") as ws:
        await ws.send_str("test message")
        await ws.close()


@pytest.mark.example
async def test_client_ws(aiohttp_client: Any) -> None:  # type: ignore[misc]
    """Functional test for client_ws.py using a mock server."""
    from aiohttp import web
    from examples import client_ws  # noqa: I900

    received_messages: list[str] = []

    async def ws_handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                received_messages.append(msg.data)
                await ws.send_str(f"Echo: {msg.data}")
        return ws

    app = web.Application()
    app.router.add_get("/", ws_handler)
    client: TestClient[Any, Any] = await aiohttp_client(app)

    messages = iter(["Hello\n", "World\n", ""])

    await client_ws.start_client(
        str(client.make_url("/")),
        name="TestUser",
        input_func=lambda: next(messages),
    )

    assert len(received_messages) == 2
    assert "TestUser: Hello\n" in received_messages[0]


@pytest.mark.example
async def test_server_simple_routes(aiohttp_client: Any) -> None:  # type: ignore[misc]
    """Functional test for server_simple.py routes."""
    from examples import server_simple  # noqa: I900

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
async def test_web_ws_broadcast(aiohttp_client: Any) -> None:  # type: ignore[misc]
    """Functional test for web_ws.py broadcasting behavior."""
    from examples import web_ws  # noqa: I900

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


# @pytest.mark.example
# async def test_web_srv_routes(aiohttp_client: Any) -> None:  # type: ignore[misc]
#     """Functional test for web_srv.py routes."""
#     from examples import web_srv

#     app = web_srv.init()
#     client: TestClient[Any, Any] = await aiohttp_client(app)

#     async with client.get("/simple") as resp:
#         assert resp.status == 200
#         text = await resp.text()
#         assert text == "Simple answer"

#     async with client.get("/change_body") as resp:
#         assert resp.status == 200
#         body = await resp.read()
#         assert body == b"Body changed"

#     async with client.get("/hello/World") as resp:
#         assert resp.status == 200
#         text = await resp.text()
#         assert text == "Hello, World"


@pytest.mark.example
async def test_web_srv_route_deco(aiohttp_client: Any) -> None:  # type: ignore[misc]
    """Functional test for web_srv_route_deco.py routes."""
    from examples import web_srv_route_deco  # noqa: I900

    app = web_srv_route_deco.init()
    client: TestClient[Any, Any] = await aiohttp_client(app)

    async with client.get("/simple") as resp:
        assert resp.status == 200
        text = await resp.text()
        assert text == "Simple answer"


@pytest.mark.example
async def test_web_srv_route_table(aiohttp_client: Any) -> None:  # type: ignore[misc]
    """Functional test for web_srv_route_table.py routes."""
    from examples import web_srv_route_table  # noqa: I900

    app = web_srv_route_table.init()
    client: TestClient[Any, Any] = await aiohttp_client(app)

    async with client.get("/simple") as resp:
        assert resp.status == 200
        text = await resp.text()
        assert text == "Simple answer"

    async with client.get("/hello/Test") as resp:
        assert resp.status == 200
        text = await resp.text()
        assert text == "Hello, Test"


@pytest.mark.example
async def test_web_cookies(aiohttp_client: Any) -> None:  # type: ignore[misc]
    """Functional test for web_cookies.py cookie handling."""
    from examples import web_cookies  # noqa: I900

    app = web_cookies.init()
    client: TestClient[Any, Any] = await aiohttp_client(app)

    async with client.get("/") as resp:
        assert resp.status == 200
        assert "text/html" in resp.content_type

    async with client.get("/login", allow_redirects=False) as resp:
        assert resp.status == 302
        assert "AUTH" in resp.cookies


@pytest.mark.example
async def test_web_classview(aiohttp_client: Any) -> None:  # type: ignore[misc]
    """Functional test for web_classview.py class-based views."""
    from examples import web_classview  # noqa: I900

    app = web_classview.init()
    client: TestClient[Any, Any] = await aiohttp_client(app)

    async with client.get("/") as resp:
        assert resp.status == 200
        assert "text/html" in resp.content_type

    async with client.get("/get") as resp:
        assert resp.status == 200
        data = await resp.json()
        assert data["method"] == "GET"

    async with client.post("/post", data={"key": "value"}) as resp:
        assert resp.status == 200
        data = await resp.json()
        assert data["method"] == "POST"


@pytest.mark.example
async def test_web_rewrite_headers_middleware(  # type: ignore[misc]
    aiohttp_client: Any,
) -> None:
    """Functional test for web_rewrite_headers_middleware.py."""
    from examples import web_rewrite_headers_middleware  # noqa: I900

    app = web_rewrite_headers_middleware.init()
    client: TestClient[Any, Any] = await aiohttp_client(app)

    async with client.get("/") as resp:
        assert resp.status == 200
        assert resp.headers.get("SERVER") == "Secured Server Software"
        text = await resp.text()
        assert text == "Everything is fine"


@pytest.mark.example
async def test_static_files(aiohttp_client: Any) -> None:  # type: ignore[misc]
    """Functional test for static_files.py static file serving."""
    from examples import static_files  # noqa: I900

    app = static_files.init()
    client: TestClient[Any, Any] = await aiohttp_client(app)

    async with client.get("/") as resp:
        assert resp.status == 200


@pytest.mark.example
async def test_cli_app(aiohttp_client: Any) -> None:  # type: ignore[misc]
    """Functional test for cli_app.py CLI application."""
    from examples import cli_app  # noqa: I900

    app = cli_app.init(["--repeat", "3", "Hello"])
    client: TestClient[Any, Any] = await aiohttp_client(app)

    async with client.get("/") as resp:
        assert resp.status == 200
        text = await resp.text()
        assert text == "Hello\nHello\nHello"


@pytest.mark.example
async def test_lowlevel_srv(aiohttp_client: Any) -> None:  # type: ignore[misc]
    """Functional test for lowlevel_srv.py low-level handler."""
    from aiohttp import web
    from examples import lowlevel_srv  # noqa: I900

    app = web.Application()
    app.router.add_get("/", lowlevel_srv.handler)
    client: TestClient[Any, Any] = await aiohttp_client(app)

    async with client.get("/") as resp:
        assert resp.status == 200
        text = await resp.text()
        assert text == "OK"
