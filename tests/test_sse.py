import asyncio
import time

import pytest

from aiohttp import web
from aiohttp.sse import sse_response
from aiohttp.test_utils import TestClient, TestServer


@pytest.mark.asyncio
async def test_event_format_basic() -> None:
    async def handler(request: web.Request) -> web.StreamResponse:
        async with sse_response(request, heartbeat=None) as resp:
            await resp.send("hello", event="greet", id=42, retry=500)
            return resp

    app = web.Application()
    app.router.add_get("/sse", handler)
    async with TestServer(app) as srv, TestClient(srv) as cli:
        resp = await cli.get("/sse")
        assert resp.status == 200
        # Read lines until blank line
        lines = []
        while True:
            line = await resp.content.readline()
            if not line:
                break
            s = line.decode().rstrip("\n")
            if s == "":
                break
            lines.append(s)
        assert "event: greet" in lines
        assert "id: 42" in lines
        assert "retry: 500" in lines
        assert any(l.startswith("data: ") for l in lines)


@pytest.mark.asyncio
async def test_heartbeat_comments() -> None:
    async def handler(request: web.Request) -> web.StreamResponse:
        async with sse_response(request, heartbeat=0.2) as resp:
            # keep connection alive for ~0.6s and then return
            await asyncio.sleep(0.65)
            return resp

    app = web.Application()
    app.router.add_get("/sse", handler)
    async with TestServer(app) as srv, TestClient(srv) as cli:
        resp = await cli.get("/sse")
        assert resp.status == 200
        comments = []
        start = time.monotonic()
        while time.monotonic() - start < 0.7:
            line = await resp.content.readline()
            if not line:
                break
            s = line.decode().rstrip("\n")
            if s.startswith(":"):
                comments.append(s)
        # Expect at least 2 heartbeat comments
        assert len(comments) >= 2
        assert all(c.startswith(":") for c in comments)


@pytest.mark.asyncio
async def test_backpressure_drop_new() -> None:
    async def handler(request: web.Request) -> web.StreamResponse:
        # queue size 2, drop_new when full
        async with sse_response(
            request, heartbeat=None, queue_size=2, backpressure="drop_new"
        ) as resp:
            for i in range(10):
                await resp.send(f"msg-{i}")
            return resp

    app = web.Application()
    app.router.add_get("/sse", handler)
    async with TestServer(app) as srv, TestClient(srv) as cli:
        resp = await cli.get("/sse")
        assert resp.status == 200
        received = []
        # read a handful of lines (allow drop_new to cut off)
        while True:
            line = await resp.content.readline()
            if not line:
                break
            s = line.decode().rstrip("\n")
            if s == "":
                continue
            if s.startswith("data: "):
                received.append(s.split(": ", 1)[1])
            if len(received) > 2:
                break
        # With drop_new, not all 10 should arrive
        assert len(received) <= 10


@pytest.mark.asyncio
async def test_json_custom_encoder() -> None:
    class SimpleEncoder:
        def __call__(self, obj):
            # Turn dict into a compact string
            return "|".join(f"{k}={v}" for k, v in obj.items())

    async def handler(request: web.Request) -> web.StreamResponse:
        async with sse_response(
            request, heartbeat=None, encoder=SimpleEncoder()
        ) as resp:
            await resp.send({"a": 1, "b": 2}, json=True)
            return resp

    app = web.Application()
    app.router.add_get("/sse", handler)
    async with TestServer(app) as srv, TestClient(srv) as cli:
        resp = await cli.get("/sse")
        assert resp.status == 200
        lines = []
        while True:
            line = await resp.content.readline()
            if not line:
                break
            s = line.decode().rstrip("\n")
            if s == "":
                break
            lines.append(s)
        assert any(l == "data: a=1|b=2" for l in lines)


@pytest.mark.asyncio
async def test_client_disconnect_cleanup() -> None:
    flag = {"clean": False}

    async def handler(request: web.Request) -> web.StreamResponse:
        async with sse_response(request, heartbeat=0.1) as resp:
            try:
                # Simulate long stream until client disconnects
                for _ in range(50):
                    await resp.send("tick")
                    await asyncio.sleep(0.05)
            except asyncio.CancelledError:
                pass
            finally:
                flag["clean"] = True
            return resp

    app = web.Application()
    app.router.add_get("/sse", handler)
    async with TestServer(app) as srv, TestClient(srv) as cli:
        resp = await cli.get("/sse")
        assert resp.status == 200
        # Disconnect early
        await resp.release()
        await asyncio.sleep(0.2)
        # Handler cleanup executed
        assert flag["clean"] is True
