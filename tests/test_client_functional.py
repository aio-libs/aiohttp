# HTTP client functional tests against aiohttp.web server

import asyncio
import datetime
import http.cookies
import io
import json
import logging
import pathlib
import socket
import ssl
import sys
import tarfile
import time
import zipfile
from contextlib import suppress
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    List,
    NoReturn,
    Optional,
    Type,
)
from unittest import mock

import pytest
from multidict import MultiDict
from pytest_mock import MockerFixture
from yarl import URL

import aiohttp
from aiohttp import Fingerprint, ServerFingerprintMismatch, hdrs, payload, web
from aiohttp.abc import AbstractResolver, ResolveResult
from aiohttp.client_exceptions import (
    ClientResponseError,
    InvalidURL,
    InvalidUrlClientError,
    InvalidUrlRedirectClientError,
    NonHttpUrlClientError,
    NonHttpUrlRedirectClientError,
    SocketTimeoutError,
    TooManyRedirects,
)
from aiohttp.client_reqrep import ClientRequest
from aiohttp.connector import Connection
from aiohttp.http_writer import StreamWriter
from aiohttp.payload import (
    AsyncIterablePayload,
    BufferedReaderPayload,
    BytesIOPayload,
    BytesPayload,
    StringIOPayload,
    StringPayload,
)
from aiohttp.pytest_plugin import AiohttpClient, AiohttpServer
from aiohttp.test_utils import TestClient, TestServer, unused_port
from aiohttp.typedefs import Handler


@pytest.fixture(autouse=True)
def cleanup(
    cleanup_payload_pending_file_closes: None,
) -> None:
    """Ensure all pending file close operations complete during test teardown."""


@pytest.fixture
def here():
    return pathlib.Path(__file__).parent


@pytest.fixture
def fname(here):
    return here / "conftest.py"


async def test_keepalive_two_requests_success(aiohttp_client) -> None:
    async def handler(request):
        body = await request.read()
        assert b"" == body
        return web.Response(body=b"OK")

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    connector = aiohttp.TCPConnector(limit=1)
    client = await aiohttp_client(app, connector=connector)

    resp1 = await client.get("/")
    await resp1.read()
    resp2 = await client.get("/")
    await resp2.read()

    assert 1 == len(client._session.connector._conns)


async def test_keepalive_after_head_requests_success(aiohttp_client) -> None:
    async def handler(request):
        body = await request.read()
        assert b"" == body
        return web.Response(body=b"OK")

    cnt_conn_reuse = 0

    async def on_reuseconn(session, ctx, params):
        nonlocal cnt_conn_reuse
        cnt_conn_reuse += 1

    trace_config = aiohttp.TraceConfig()
    trace_config._on_connection_reuseconn.append(on_reuseconn)

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    app.router.add_route("HEAD", "/", handler)

    connector = aiohttp.TCPConnector(limit=1)
    client = await aiohttp_client(
        app, connector=connector, trace_configs=[trace_config]
    )

    resp1 = await client.head("/")
    await resp1.read()
    resp2 = await client.get("/")
    await resp2.read()

    assert 1 == cnt_conn_reuse


@pytest.mark.parametrize("status", (101, 204, 304))
async def test_keepalive_after_empty_body_status(
    aiohttp_client: Any, status: int
) -> None:
    async def handler(request):
        body = await request.read()
        assert b"" == body
        return web.Response(status=status)

    cnt_conn_reuse = 0

    async def on_reuseconn(session, ctx, params):
        nonlocal cnt_conn_reuse
        cnt_conn_reuse += 1

    trace_config = aiohttp.TraceConfig()
    trace_config._on_connection_reuseconn.append(on_reuseconn)

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    connector = aiohttp.TCPConnector(limit=1)
    client = await aiohttp_client(
        app, connector=connector, trace_configs=[trace_config]
    )

    resp1 = await client.get("/")
    await resp1.read()
    resp2 = await client.get("/")
    await resp2.read()

    assert cnt_conn_reuse == 1


@pytest.mark.parametrize("status", (101, 204, 304))
async def test_keepalive_after_empty_body_status_stream_response(
    aiohttp_client: Any, status: int
) -> None:
    async def handler(request):
        stream_response = web.StreamResponse(status=status)
        await stream_response.prepare(request)
        return stream_response

    cnt_conn_reuse = 0

    async def on_reuseconn(session, ctx, params):
        nonlocal cnt_conn_reuse
        cnt_conn_reuse += 1

    trace_config = aiohttp.TraceConfig()
    trace_config._on_connection_reuseconn.append(on_reuseconn)

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    connector = aiohttp.TCPConnector(limit=1)
    client = await aiohttp_client(
        app, connector=connector, trace_configs=[trace_config]
    )

    resp1 = await client.get("/")
    await resp1.read()
    resp2 = await client.get("/")
    await resp2.read()

    assert cnt_conn_reuse == 1


async def test_keepalive_response_released(aiohttp_client: Any) -> None:
    async def handler(request):
        body = await request.read()
        assert b"" == body
        return web.Response(body=b"OK")

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    connector = aiohttp.TCPConnector(limit=1)
    client = await aiohttp_client(app, connector=connector)

    resp1 = await client.get("/")
    resp1.release()
    resp2 = await client.get("/")
    resp2.release()

    assert 1 == len(client._session.connector._conns)


async def test_upgrade_connection_not_released_after_read(aiohttp_client) -> None:
    async def handler(request: web.Request) -> web.Response:
        body = await request.read()
        assert b"" == body
        return web.Response(
            status=101, headers={"Connection": "Upgrade", "Upgrade": "tcp"}
        )

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    client = await aiohttp_client(app)

    resp = await client.get("/")
    await resp.read()
    assert resp.connection is not None
    assert not resp.closed


async def test_keepalive_server_force_close_connection(aiohttp_client) -> None:
    async def handler(request):
        body = await request.read()
        assert b"" == body
        response = web.Response(body=b"OK")
        response.force_close()
        return response

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    connector = aiohttp.TCPConnector(limit=1)
    client = await aiohttp_client(app, connector=connector)

    resp1 = await client.get("/")
    resp1.close()
    resp2 = await client.get("/")
    resp2.close()

    assert 0 == len(client._session.connector._conns)


async def test_keepalive_timeout_async_sleep(unused_port_socket: socket.socket) -> None:
    async def handler(request: web.Request) -> web.Response:
        body = await request.read()
        assert b"" == body
        return web.Response(body=b"OK")

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    runner = web.AppRunner(app, tcp_keepalive=True, keepalive_timeout=0.001)
    await runner.setup()

    site = web.SockSite(runner, unused_port_socket)
    await site.start()

    host, port = unused_port_socket.getsockname()[:2]

    try:
        async with aiohttp.ClientSession() as sess:
            resp1 = await sess.get(f"http://{host}:{port}/")
            await resp1.read()
            # wait for server keepalive_timeout
            await asyncio.sleep(0.01)
            resp2 = await sess.get(f"http://{host}:{port}/")
            await resp2.read()
    finally:
        await asyncio.gather(runner.shutdown(), site.stop())


@pytest.mark.skipif(
    sys.version_info[:2] == (3, 11),
    reason="https://github.com/pytest-dev/pytest/issues/10763",
)
async def test_keepalive_timeout_sync_sleep(unused_port_socket: socket.socket) -> None:
    async def handler(request: web.Request) -> web.Response:
        body = await request.read()
        assert b"" == body
        return web.Response(body=b"OK")

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    runner = web.AppRunner(app, tcp_keepalive=True, keepalive_timeout=0.001)
    await runner.setup()

    site = web.SockSite(runner, unused_port_socket)
    await site.start()

    host, port = unused_port_socket.getsockname()[:2]

    try:
        async with aiohttp.ClientSession() as sess:
            resp1 = await sess.get(f"http://{host}:{port}/")
            await resp1.read()
            # wait for server keepalive_timeout
            # time.sleep is a more challenging scenario than asyncio.sleep
            time.sleep(0.01)
            resp2 = await sess.get(f"http://{host}:{port}/")
            await resp2.read()
    finally:
        await asyncio.gather(runner.shutdown(), site.stop())


async def test_release_early(aiohttp_client) -> None:
    async def handler(request):
        await request.read()
        return web.Response(body=b"OK")

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    client = await aiohttp_client(app)
    resp = await client.get("/")
    assert resp.closed
    await resp.wait_for_close()
    assert 1 == len(client._session.connector._conns)


async def test_HTTP_304(aiohttp_client) -> None:
    async def handler(request):
        body = await request.read()
        assert b"" == body
        return web.Response(status=304)

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/")
    assert resp.status == 304
    content = await resp.read()
    assert content == b""


async def test_stream_request_on_server_eof(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(text="OK", status=200)

    app = web.Application()
    app.add_routes([web.get("/", handler)])
    app.add_routes([web.put("/", handler)])

    client = await aiohttp_client(app)

    async def data_gen():
        for _ in range(2):
            yield b"just data"
            await asyncio.sleep(0.1)

    async with client.put("/", data=data_gen()) as resp:
        assert 200 == resp.status
        assert len(client.session.connector._acquired) == 1
        conn = next(iter(client.session.connector._acquired))

    async with client.get("/") as resp:
        assert 200 == resp.status

    # First connection should have been closed, otherwise server won't know if it
    # received the full message.
    conns = next(iter(client.session.connector._conns.values()))
    assert len(conns) == 1
    assert conns[0][0] is not conn


async def test_stream_request_on_server_eof_nested(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(text="OK", status=200)

    app = web.Application()
    app.add_routes([web.get("/", handler)])
    app.add_routes([web.put("/", handler)])

    client = await aiohttp_client(app)

    async def data_gen():
        for _ in range(2):
            yield b"just data"
            await asyncio.sleep(0.1)

    assert client.session.connector is not None
    async with client.put("/", data=data_gen()) as resp:
        first_conn = next(iter(client.session.connector._acquired))
        assert 200 == resp.status

        async with client.get("/") as resp2:
            assert 200 == resp2.status

    # Should be 2 separate connections
    conns = next(iter(client.session.connector._conns.values()))
    assert len(conns) == 1

    assert first_conn is not None
    assert not first_conn.is_connected()
    assert first_conn is not conns[0][0]


async def test_HTTP_304_WITH_BODY(aiohttp_client) -> None:
    async def handler(request):
        body = await request.read()
        assert b"" == body
        return web.Response(body=b"test", status=304)

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/")
    assert resp.status == 304
    content = await resp.read()
    assert content == b""


async def test_auto_header_user_agent(aiohttp_client) -> None:
    async def handler(request):
        assert "aiohttp" in request.headers["user-agent"]
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    async with client.get("/") as resp:
        assert 200 == resp.status


async def test_skip_auto_headers_user_agent(aiohttp_client) -> None:
    async def handler(request):
        assert hdrs.USER_AGENT not in request.headers
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    async with client.get("/", skip_auto_headers=["user-agent"]) as resp:
        assert 200 == resp.status


async def test_skip_default_auto_headers_user_agent(aiohttp_client) -> None:
    async def handler(request):
        assert hdrs.USER_AGENT not in request.headers
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app, skip_auto_headers=["user-agent"])

    async with client.get("/") as resp:
        assert 200 == resp.status


async def test_skip_auto_headers_content_type(aiohttp_client) -> None:
    async def handler(request):
        assert hdrs.CONTENT_TYPE not in request.headers
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    async with client.get("/", skip_auto_headers=["content-type"]) as resp:
        assert 200 == resp.status


async def test_post_data_bytesio(aiohttp_client) -> None:
    data = b"some buffer"

    async def handler(request):
        assert len(data) == request.content_length
        val = await request.read()
        assert data == val
        return web.Response()

    app = web.Application()
    app.router.add_route("POST", "/", handler)
    client = await aiohttp_client(app)

    with io.BytesIO(data) as file_handle:
        async with client.post("/", data=file_handle) as resp:
            assert 200 == resp.status


async def test_post_data_with_bytesio_file(aiohttp_client) -> None:
    data = b"some buffer"

    async def handler(request):
        post_data = await request.post()
        assert ["file"] == list(post_data.keys())
        assert data == await asyncio.to_thread(post_data["file"].file.read)
        post_data["file"].file.close()  # aiohttp < 4 doesn't autoclose files
        return web.Response()

    app = web.Application()
    app.router.add_route("POST", "/", handler)
    client = await aiohttp_client(app)

    with io.BytesIO(data) as file_handle:
        async with client.post("/", data={"file": file_handle}) as resp:
            assert 200 == resp.status


async def test_post_data_stringio(aiohttp_client) -> None:
    data = "some buffer"

    async def handler(request):
        assert len(data) == request.content_length
        assert request.headers["CONTENT-TYPE"] == "text/plain; charset=utf-8"
        val = await request.text()
        assert data == val
        return web.Response()

    app = web.Application()
    app.router.add_route("POST", "/", handler)
    client = await aiohttp_client(app)

    async with client.post("/", data=io.StringIO(data)) as resp:
        assert 200 == resp.status


async def test_post_data_textio_encoding(aiohttp_client) -> None:
    data = "текст"

    async def handler(request):
        assert request.headers["CONTENT-TYPE"] == "text/plain; charset=koi8-r"
        val = await request.text()
        assert data == val
        return web.Response()

    app = web.Application()
    app.router.add_route("POST", "/", handler)
    client = await aiohttp_client(app)

    pl = aiohttp.TextIOPayload(io.StringIO(data), encoding="koi8-r")
    async with client.post("/", data=pl) as resp:
        assert 200 == resp.status


async def test_post_data_zipfile_filelike(aiohttp_client: AiohttpClient) -> None:
    data = b"This is a zip file payload text file."

    async def handler(request: web.Request) -> web.Response:
        val = await request.read()
        assert data == val, "Transmitted zipfile member failed to match original data."
        return web.Response()

    app = web.Application()
    app.router.add_route("POST", "/", handler)
    client = await aiohttp_client(app)

    buf = io.BytesIO()
    with zipfile.ZipFile(file=buf, mode="w") as zf:
        with zf.open("payload1.txt", mode="w") as zip_filelike_writing:
            zip_filelike_writing.write(data)

    buf.seek(0)
    zf = zipfile.ZipFile(file=buf, mode="r")
    resp = await client.post("/", data=zf.open("payload1.txt"))
    assert 200 == resp.status


async def test_post_data_tarfile_filelike(aiohttp_client: AiohttpClient) -> None:
    data = b"This is a tar file payload text file."

    async def handler(request: web.Request) -> web.Response:
        val = await request.read()
        assert data == val, "Transmitted tarfile member failed to match original data."
        return web.Response()

    app = web.Application()
    app.router.add_route("POST", "/", handler)
    client = await aiohttp_client(app)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo(name="payload1.txt")
        ti.size = len(data)
        tf.addfile(tarinfo=ti, fileobj=io.BytesIO(data))

    # Random-access tarfile.
    buf.seek(0)
    tf = tarfile.open(fileobj=buf, mode="r:")
    resp = await client.post("/", data=tf.extractfile("payload1.txt"))
    assert 200 == resp.status

    # Streaming tarfile.
    buf.seek(0)
    tf = tarfile.open(fileobj=buf, mode="r|")
    for entry in tf:
        resp = await client.post("/", data=tf.extractfile(entry))
        assert 200 == resp.status


async def test_post_bytes_data_content_length_from_body(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test that Content-Length is set from body payload size when sending bytes."""
    data = b"test payload data"

    async def handler(request: web.Request) -> web.Response:
        # Verify Content-Length header was set correctly
        assert request.content_length == len(data)
        assert request.headers.get("Content-Length") == str(len(data))

        # Verify we can read the data
        val = await request.read()
        assert data == val
        return web.Response()

    app = web.Application()
    app.router.add_route("POST", "/", handler)
    client = await aiohttp_client(app)

    # Send bytes data - this should trigger the code path where
    # Content-Length is set from body.size in update_transfer_encoding
    async with client.post("/", data=data) as resp:
        assert resp.status == 200


async def test_post_custom_payload_without_content_length(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test that Content-Length is set from payload.size when not explicitly provided."""
    data = b"custom payload data"

    async def handler(request: web.Request) -> web.Response:
        # Verify Content-Length header was set from payload size
        assert request.content_length == len(data)
        assert request.headers.get("Content-Length") == str(len(data))

        # Verify we can read the data
        val = await request.read()
        assert data == val
        return web.Response()

    app = web.Application()
    app.router.add_route("POST", "/", handler)
    client = await aiohttp_client(app)

    # Create a BytesPayload directly - this ensures we test the path
    # where update_transfer_encoding sets Content-Length from body.size
    bytes_payload = payload.BytesPayload(data)

    # Don't set Content-Length header explicitly
    async with client.post("/", data=bytes_payload) as resp:
        assert resp.status == 200


async def test_ssl_client(
    aiohttp_server,
    ssl_ctx,
    aiohttp_client,
    client_ssl_ctx,
) -> None:
    connector = aiohttp.TCPConnector(ssl=client_ssl_ctx)

    async def handler(request):
        return web.Response(text="Test message")

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    server = await aiohttp_server(app, ssl=ssl_ctx)
    client = await aiohttp_client(server, connector=connector)

    resp = await client.get("/")
    assert 200 == resp.status
    txt = await resp.text()
    assert txt == "Test message"


@pytest.mark.skipif(
    sys.version_info < (3, 11), reason="ssl_shutdown_timeout requires Python 3.11+"
)
async def test_ssl_client_shutdown_timeout(
    aiohttp_server: AiohttpServer,
    ssl_ctx: ssl.SSLContext,
    aiohttp_client: AiohttpClient,
    client_ssl_ctx: ssl.SSLContext,
) -> None:
    # Test that ssl_shutdown_timeout is properly used during connection closure

    connector = aiohttp.TCPConnector(ssl=client_ssl_ctx, ssl_shutdown_timeout=0.1)

    async def streaming_handler(request: web.Request) -> NoReturn:
        # Create a streaming response that continuously sends data
        response = web.StreamResponse()
        await response.prepare(request)

        # Keep sending data until connection is closed
        while True:
            await response.write(b"data chunk\n")
            await asyncio.sleep(0.01)  # Small delay between chunks

        assert False, "not reached"

    app = web.Application()
    app.router.add_route("GET", "/stream", streaming_handler)
    server = await aiohttp_server(app, ssl=ssl_ctx)
    client = await aiohttp_client(server, connector=connector)

    # Verify the connector has the correct timeout
    assert connector._ssl_shutdown_timeout == 0.1

    # Start a streaming request to establish SSL connection with active data transfer
    resp = await client.get("/stream")
    assert resp.status == 200

    # Create a background task that continuously reads data
    async def read_loop() -> None:
        while True:
            # Read "data chunk\n"
            await resp.content.read(11)

    read_task = asyncio.create_task(read_loop())
    await asyncio.sleep(0)  # Yield control to ensure read_task starts

    # Record the time before closing
    start_time = time.monotonic()

    # Now close the connector while the stream is still active
    # This will test the ssl_shutdown_timeout during an active connection
    await connector.close()

    # Verify the connection was closed within a reasonable time
    # Should be close to ssl_shutdown_timeout (0.1s) but allow some margin
    elapsed = time.monotonic() - start_time
    assert elapsed < 0.3, f"Connection closure took too long: {elapsed}s"

    read_task.cancel()
    with suppress(asyncio.CancelledError):
        await read_task
    assert read_task.done(), "Read task should be cancelled after connection closure"


async def test_ssl_client_alpn(
    aiohttp_server: AiohttpServer,
    aiohttp_client: AiohttpClient,
    ssl_ctx: ssl.SSLContext,
) -> None:

    async def handler(request: web.Request) -> web.Response:
        assert request.transport is not None
        sslobj = request.transport.get_extra_info("ssl_object")
        return web.Response(text=sslobj.selected_alpn_protocol())

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    ssl_ctx.set_alpn_protocols(("http/1.1",))
    server = await aiohttp_server(app, ssl=ssl_ctx)

    connector = aiohttp.TCPConnector(ssl=False)
    client = await aiohttp_client(server, connector=connector)
    resp = await client.get("/")
    assert resp.status == 200
    txt = await resp.text()
    assert txt == "http/1.1"


async def test_tcp_connector_fingerprint_ok(
    aiohttp_server,
    aiohttp_client,
    ssl_ctx,
    tls_certificate_fingerprint_sha256,
):
    tls_fingerprint = Fingerprint(tls_certificate_fingerprint_sha256)

    async def handler(request):
        return web.Response(text="Test message")

    connector = aiohttp.TCPConnector(ssl=tls_fingerprint)
    app = web.Application()
    app.router.add_route("GET", "/", handler)
    server = await aiohttp_server(app, ssl=ssl_ctx)
    client = await aiohttp_client(server, connector=connector)

    async with client.get("/") as resp:
        assert resp.status == 200


async def test_tcp_connector_fingerprint_fail(
    aiohttp_server,
    aiohttp_client,
    ssl_ctx,
    tls_certificate_fingerprint_sha256,
):
    async def handler(request):
        return web.Response(text="Test message")

    bad_fingerprint = b"\x00" * len(tls_certificate_fingerprint_sha256)

    connector = aiohttp.TCPConnector(ssl=Fingerprint(bad_fingerprint))

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    server = await aiohttp_server(app, ssl=ssl_ctx)
    client = await aiohttp_client(server, connector=connector)

    with pytest.raises(ServerFingerprintMismatch) as cm:
        await client.get("/")
    exc = cm.value
    assert exc.expected == bad_fingerprint
    assert exc.got == tls_certificate_fingerprint_sha256


async def test_format_task_get(aiohttp_server) -> None:
    async def handler(request):
        return web.Response(body=b"OK")

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    server = await aiohttp_server(app)
    client = aiohttp.ClientSession()
    task = asyncio.create_task(client.get(server.make_url("/")))
    assert f"{task}".startswith("<Task pending")
    resp = await task
    resp.close()
    await client.close()


async def test_str_params(aiohttp_client) -> None:
    async def handler(request):
        assert "q=t est" in request.rel_url.query_string
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    async with client.get("/", params="q=t+est") as resp:
        assert 200 == resp.status


async def test_params_and_query_string(aiohttp_client: AiohttpClient) -> None:
    """Test combining params with an existing query_string."""

    async def handler(request: web.Request) -> web.Response:
        assert request.rel_url.query_string == "q=abc&q=test&d=dog"
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    async with client.get("/?q=abc", params="q=test&d=dog") as resp:
        assert resp.status == 200


@pytest.mark.parametrize("params", [None, "", {}, MultiDict()])
async def test_empty_params_and_query_string(
    aiohttp_client: AiohttpClient, params: Any
) -> None:
    """Test combining empty params with an existing query_string."""

    async def handler(request: web.Request) -> web.Response:
        assert request.rel_url.query_string == "q=abc"
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    async with client.get("/?q=abc", params=params) as resp:
        assert resp.status == 200


async def test_drop_params_on_redirect(aiohttp_client: AiohttpClient) -> None:
    async def handler_redirect(request: web.Request) -> web.Response:
        return web.Response(status=301, headers={"Location": "/ok?a=redirect"})

    async def handler_ok(request):
        assert request.rel_url.query_string == "a=redirect"
        return web.Response(status=200)

    app = web.Application()
    app.router.add_route("GET", "/ok", handler_ok)
    app.router.add_route("GET", "/redirect", handler_redirect)
    client = await aiohttp_client(app)

    async with client.get("/redirect", params={"a": "initial"}) as resp:
        assert resp.status == 200


async def test_drop_fragment_on_redirect(aiohttp_client) -> None:
    async def handler_redirect(request):
        return web.Response(status=301, headers={"Location": "/ok#fragment"})

    async def handler_ok(request):
        return web.Response(status=200)

    app = web.Application()
    app.router.add_route("GET", "/ok", handler_ok)
    app.router.add_route("GET", "/redirect", handler_redirect)
    client = await aiohttp_client(app)

    async with client.get("/redirect") as resp:
        assert resp.status == 200
        assert resp.url.path == "/ok"


async def test_drop_fragment(aiohttp_client) -> None:
    async def handler_ok(request):
        return web.Response(status=200)

    app = web.Application()
    app.router.add_route("GET", "/ok", handler_ok)
    client = await aiohttp_client(app)

    async with client.get("/ok#fragment") as resp:
        assert resp.status == 200
        assert resp.url.path == "/ok"


async def test_history(aiohttp_client) -> None:
    async def handler_redirect(request):
        return web.Response(status=301, headers={"Location": "/ok"})

    async def handler_ok(request):
        return web.Response(status=200)

    app = web.Application()
    app.router.add_route("GET", "/ok", handler_ok)
    app.router.add_route("GET", "/redirect", handler_redirect)
    client = await aiohttp_client(app)

    async with client.get("/ok") as resp:
        assert len(resp.history) == 0
        assert resp.status == 200

    async with client.get("/redirect") as resp_redirect:
        assert len(resp_redirect.history) == 1
        assert resp_redirect.history[0].status == 301
        assert resp_redirect.status == 200


async def test_keepalive_closed_by_server(aiohttp_client) -> None:
    async def handler(request):
        body = await request.read()
        assert b"" == body
        resp = web.Response(body=b"OK")
        resp.force_close()
        return resp

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    connector = aiohttp.TCPConnector(limit=1)
    client = await aiohttp_client(app, connector=connector)

    resp1 = await client.get("/")
    val1 = await resp1.read()
    assert val1 == b"OK"
    resp2 = await client.get("/")
    val2 = await resp2.read()
    assert val2 == b"OK"

    assert 0 == len(client._session.connector._conns)


async def test_wait_for(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(body=b"OK")

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    resp = await asyncio.wait_for(client.get("/"), 10)
    assert resp.status == 200
    txt = await resp.text()
    assert txt == "OK"


async def test_raw_headers(aiohttp_client) -> None:
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    async with client.get("/") as resp:
        assert resp.status == 200

        raw_headers = tuple((bytes(h), bytes(v)) for h, v in resp.raw_headers)
        assert raw_headers == (
            (b"Content-Length", b"0"),
            (b"Date", mock.ANY),
            (b"Server", mock.ANY),
        )


async def test_host_header_first(aiohttp_client) -> None:
    async def handler(request):
        assert list(request.headers)[0] == hdrs.HOST
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    async with client.get("/") as resp:
        assert resp.status == 200


async def test_empty_header_values(aiohttp_client) -> None:
    async def handler(request):
        resp = web.Response()
        resp.headers["X-Empty"] = ""
        return resp

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    async with client.get("/") as resp:
        assert resp.status == 200
        raw_headers = tuple((bytes(h), bytes(v)) for h, v in resp.raw_headers)
        assert raw_headers == (
            (b"X-Empty", b""),
            (b"Content-Length", b"0"),
            (b"Date", mock.ANY),
            (b"Server", mock.ANY),
        )


async def test_204_with_gzipped_content_encoding(aiohttp_client) -> None:
    async def handler(request):
        resp = web.StreamResponse(status=204)
        resp.content_length = 0
        resp.content_type = "application/json"
        # resp.enable_compression(web.ContentCoding.gzip)
        resp.headers["Content-Encoding"] = "gzip"
        await resp.prepare(request)
        return resp

    app = web.Application()
    app.router.add_route("DELETE", "/", handler)
    client = await aiohttp_client(app)

    async with client.delete("/") as resp:
        assert resp.status == 204
        assert resp.closed


async def test_timeout_on_reading_headers(aiohttp_client, mocker) -> None:
    async def handler(request):
        resp = web.StreamResponse()
        await asyncio.sleep(0.1)
        await resp.prepare(request)
        return resp

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    with pytest.raises(asyncio.TimeoutError):
        await client.get("/", timeout=0.01)


async def test_timeout_on_conn_reading_headers(aiohttp_client, mocker) -> None:
    # tests case where user did not set a connection timeout

    async def handler(request):
        resp = web.StreamResponse()
        await asyncio.sleep(0.1)
        await resp.prepare(request)
        return resp

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    conn = aiohttp.TCPConnector()
    client = await aiohttp_client(app, connector=conn)

    with pytest.raises(asyncio.TimeoutError):
        await client.get("/", timeout=0.01)


async def test_timeout_on_session_read_timeout(aiohttp_client, mocker) -> None:
    async def handler(request):
        resp = web.StreamResponse()
        await asyncio.sleep(0.1)
        await resp.prepare(request)
        return resp

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    conn = aiohttp.TCPConnector()
    client = await aiohttp_client(
        app, connector=conn, timeout=aiohttp.ClientTimeout(sock_read=0.01)
    )

    with pytest.raises(asyncio.TimeoutError):
        await client.get("/")


async def test_read_timeout_between_chunks(aiohttp_client, mocker) -> None:
    async def handler(request):
        resp = aiohttp.web.StreamResponse()
        await resp.prepare(request)
        # write data 4 times, with pauses. Total time 2 seconds.
        for _ in range(4):
            await asyncio.sleep(0.5)
            await resp.write(b"data\n")
        return resp

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    # A timeout of 0.2 seconds should apply per read.
    timeout = aiohttp.ClientTimeout(sock_read=1)
    client = await aiohttp_client(app, timeout=timeout)

    res = b""
    async with await client.get("/") as resp:
        res += await resp.read()

    assert res == b"data\n" * 4


async def test_read_timeout_on_reading_chunks(aiohttp_client, mocker) -> None:
    async def handler(request):
        resp = aiohttp.web.StreamResponse()
        await resp.prepare(request)
        await resp.write(b"data\n")
        await asyncio.sleep(1)
        await resp.write(b"data\n")
        return resp

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    # A timeout of 0.2 seconds should apply per read.
    timeout = aiohttp.ClientTimeout(sock_read=0.2)
    client = await aiohttp_client(app, timeout=timeout)

    async with await client.get("/") as resp:
        assert (await resp.content.read(5)) == b"data\n"
        with pytest.raises(asyncio.TimeoutError):
            await resp.content.read()


async def test_read_timeout_on_write(aiohttp_client) -> None:
    async def gen_payload() -> AsyncIterator[str]:
        # Delay writing to ensure read timeout isn't triggered before writing completes.
        await asyncio.sleep(0.5)
        yield b"foo"

    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=await request.read())

    app = web.Application()
    app.router.add_put("/", handler)

    timeout = aiohttp.ClientTimeout(total=None, sock_read=0.1)
    client = await aiohttp_client(app)
    async with client.put("/", data=gen_payload(), timeout=timeout) as resp:
        result = await resp.read()  # Should not trigger a read timeout.
    assert result == b"foo"


async def test_timeout_on_reading_data(aiohttp_client, mocker) -> None:
    loop = asyncio.get_event_loop()

    fut = loop.create_future()

    async def handler(request):
        resp = web.StreamResponse(headers={"content-length": "100"})
        await resp.prepare(request)
        fut.set_result(None)
        await asyncio.sleep(0.2)
        return resp

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/", timeout=1)
    await fut

    with pytest.raises(asyncio.TimeoutError):
        await resp.read()


async def test_timeout_none(aiohttp_client, mocker) -> None:
    async def handler(request):
        resp = web.StreamResponse()
        await resp.prepare(request)
        return resp

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    async with client.get("/", timeout=None) as resp:
        assert resp.status == 200


async def test_connection_timeout_error(
    aiohttp_client: AiohttpClient, mocker: MockerFixture
) -> None:
    """Test that ConnectionTimeoutError is raised when connection times out."""

    async def handler(request: web.Request) -> NoReturn:
        assert False, "Handler should not be called"

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    # Mock the connector's connect method to raise asyncio.TimeoutError
    mock_connect = mocker.patch.object(
        client.session._connector, "connect", side_effect=asyncio.TimeoutError()
    )

    with pytest.raises(aiohttp.ConnectionTimeoutError) as exc_info:
        await client.get("/", timeout=aiohttp.ClientTimeout(connect=0.01))

    assert "Connection timeout to host" in str(exc_info.value)
    mock_connect.assert_called_once()


async def test_readline_error_on_conn_close(aiohttp_client: AiohttpClient) -> None:
    loop = asyncio.get_event_loop()

    async def handler(request):
        resp_ = web.StreamResponse()
        await resp_.prepare(request)

        # make sure connection is closed by client.
        with pytest.raises(aiohttp.ServerDisconnectedError):
            for _ in range(10):
                await resp_.write(b"data\n")
                await asyncio.sleep(0.5)
            return resp_

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    server = await aiohttp_client(app)

    session = aiohttp.ClientSession()
    try:
        timer_started = False
        url, headers = server.make_url("/"), {"Connection": "Keep-alive"}
        resp = await session.get(url, headers=headers)
        with pytest.raises(aiohttp.ClientConnectionError):
            while True:
                data = await resp.content.readline()
                data = data.strip()
                if not data:
                    break
                assert data == b"data"
                if not timer_started:

                    def do_release():
                        loop.create_task(resp.release())

                    loop.call_later(1.0, do_release)
                    timer_started = True
    finally:
        await session.close()


async def test_no_error_on_conn_close_if_eof(aiohttp_client) -> None:
    async def handler(request):
        resp_ = web.StreamResponse()
        await resp_.prepare(request)
        await resp_.write(b"data\n")
        await asyncio.sleep(0.5)
        return resp_

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    server = await aiohttp_client(app)

    session = aiohttp.ClientSession()
    try:
        url, headers = server.make_url("/"), {"Connection": "Keep-alive"}
        resp = await session.get(url, headers=headers)
        while True:
            data = await resp.content.readline()
            data = data.strip()
            if not data:
                break
            assert data == b"data"

        assert resp.content.exception() is None
    finally:
        await session.close()


async def test_error_not_overwrote_on_conn_close(aiohttp_client) -> None:
    async def handler(request):
        resp_ = web.StreamResponse()
        await resp_.prepare(request)
        return resp_

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    server = await aiohttp_client(app)

    session = aiohttp.ClientSession()
    try:
        url, headers = server.make_url("/"), {"Connection": "Keep-alive"}
        resp = await session.get(url, headers=headers)
        resp.content.set_exception(ValueError())
    finally:
        await session.close()

    assert isinstance(resp.content.exception(), ValueError)


async def test_HTTP_200_OK_METHOD(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(text=request.method)

    app = web.Application()
    for meth in ("get", "post", "put", "delete", "head", "patch", "options"):
        app.router.add_route(meth.upper(), "/", handler)

    client = await aiohttp_client(app)
    for meth in ("get", "post", "put", "delete", "head", "patch", "options"):
        resp = await client.request(meth, "/")
        assert resp.status == 200
        assert len(resp.history) == 0

        content1 = await resp.read()
        content2 = await resp.read()
        assert content1 == content2
        content = await resp.text()

        if meth == "head":
            assert b"" == content1
        else:
            assert meth.upper() == content


async def test_HTTP_200_OK_METHOD_connector(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(text=request.method)

    conn = aiohttp.TCPConnector()
    conn.clear_dns_cache()

    app = web.Application()
    for meth in ("get", "post", "put", "delete", "head"):
        app.router.add_route(meth.upper(), "/", handler)
    client = await aiohttp_client(app, connector=conn)

    for meth in ("get", "post", "put", "delete", "head"):
        resp = await client.request(meth, "/")

        content1 = await resp.read()
        content2 = await resp.read()
        assert content1 == content2
        content = await resp.text()

        assert resp.status == 200
        if meth == "head":
            assert b"" == content1
        else:
            assert meth.upper() == content


async def test_HTTP_302_REDIRECT_GET(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(text=request.method)

    async def redirect(request):
        raise web.HTTPFound(location="/")

    app = web.Application()
    app.router.add_get("/", handler)
    app.router.add_get("/redirect", redirect)
    client = await aiohttp_client(app)

    async with client.get("/redirect") as resp:
        assert 200 == resp.status
        assert 1 == len(resp.history)


async def test_HTTP_302_REDIRECT_HEAD(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(text=request.method)

    async def redirect(request):
        raise web.HTTPFound(location="/")

    app = web.Application()
    app.router.add_get("/", handler)
    app.router.add_get("/redirect", redirect)
    app.router.add_head("/", handler)
    app.router.add_head("/redirect", redirect)
    client = await aiohttp_client(app)

    async with client.request("head", "/redirect") as resp:
        assert 200 == resp.status
        assert 1 == len(resp.history)
        assert resp.method == "HEAD"


async def test_HTTP_302_REDIRECT_NON_HTTP(aiohttp_client) -> None:
    async def redirect(request):
        raise web.HTTPFound(location="ftp://127.0.0.1/test/")

    app = web.Application()
    app.router.add_get("/redirect", redirect)
    client = await aiohttp_client(app)

    with pytest.raises(NonHttpUrlRedirectClientError):
        await client.get("/redirect")


async def test_HTTP_302_REDIRECT_POST(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(text=request.method)

    async def redirect(request):
        raise web.HTTPFound(location="/")

    app = web.Application()
    app.router.add_get("/", handler)
    app.router.add_post("/redirect", redirect)
    client = await aiohttp_client(app)

    resp = await client.post("/redirect")
    assert 200 == resp.status
    assert 1 == len(resp.history)
    txt = await resp.text()
    assert txt == "GET"
    resp.close()


async def test_HTTP_302_REDIRECT_POST_with_content_length_hdr(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(text=request.method)

    async def redirect(request):
        await request.read()
        raise web.HTTPFound(location="/")

    data = json.dumps({"some": "data"})
    app = web.Application()
    app.router.add_get("/", handler)
    app.router.add_post("/redirect", redirect)
    client = await aiohttp_client(app)

    resp = await client.post(
        "/redirect", data=data, headers={"Content-Length": str(len(data))}
    )
    assert 200 == resp.status
    assert 1 == len(resp.history)
    txt = await resp.text()
    assert txt == "GET"
    resp.close()


async def test_HTTP_307_REDIRECT_POST(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(text=request.method)

    async def redirect(request):
        await request.read()
        raise web.HTTPTemporaryRedirect(location="/")

    app = web.Application()
    app.router.add_post("/", handler)
    app.router.add_post("/redirect", redirect)
    client = await aiohttp_client(app)

    resp = await client.post("/redirect", data={"some": "data"})
    assert 200 == resp.status
    assert 1 == len(resp.history)
    txt = await resp.text()
    assert txt == "POST"
    resp.close()


async def test_HTTP_308_PERMANENT_REDIRECT_POST(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(text=request.method)

    async def redirect(request):
        await request.read()
        raise web.HTTPPermanentRedirect(location="/")

    app = web.Application()
    app.router.add_post("/", handler)
    app.router.add_post("/redirect", redirect)
    client = await aiohttp_client(app)

    resp = await client.post("/redirect", data={"some": "data"})
    assert 200 == resp.status
    assert 1 == len(resp.history)
    txt = await resp.text()
    assert txt == "POST"
    resp.close()


async def test_HTTP_302_max_redirects(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(text=request.method)

    async def redirect(request):
        count = int(request.match_info["count"])
        if count:
            raise web.HTTPFound(location=f"/redirect/{count - 1}")
        else:
            raise web.HTTPFound(location="/")

    app = web.Application()
    app.router.add_get("/", handler)
    app.router.add_get(r"/redirect/{count:\d+}", redirect)
    client = await aiohttp_client(app)

    with pytest.raises(TooManyRedirects) as ctx:
        await client.get("/redirect/5", max_redirects=2)
    assert 2 == len(ctx.value.history)
    assert ctx.value.request_info.url.path == "/redirect/5"
    assert ctx.value.request_info.method == "GET"


async def test_HTTP_200_GET_WITH_PARAMS(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(
            text="&".join(k + "=" + v for k, v in request.query.items())
        )

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/", params={"q": "test"})
    assert 200 == resp.status
    txt = await resp.text()
    assert txt == "q=test"
    resp.close()


async def test_HTTP_200_GET_WITH_MultiDict_PARAMS(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(
            text="&".join(k + "=" + v for k, v in request.query.items())
        )

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/", params=MultiDict([("q", "test"), ("q", "test2")]))
    assert 200 == resp.status
    txt = await resp.text()
    assert txt == "q=test&q=test2"
    resp.close()


async def test_HTTP_200_GET_WITH_MIXED_PARAMS(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(
            text="&".join(k + "=" + v for k, v in request.query.items())
        )

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/?test=true", params={"q": "test"})
    assert 200 == resp.status
    txt = await resp.text()
    assert txt == "test=true&q=test"
    resp.close()


async def test_POST_DATA(aiohttp_client) -> None:
    async def handler(request):
        data = await request.post()
        return web.json_response(dict(data))

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    resp = await client.post("/", data={"some": "data"})
    assert 200 == resp.status
    content = await resp.json()
    assert content == {"some": "data"}
    resp.close()


async def test_POST_DATA_with_explicit_formdata(aiohttp_client) -> None:
    async def handler(request):
        data = await request.post()
        return web.json_response(dict(data))

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    form = aiohttp.FormData()
    form.add_field("name", "text")

    resp = await client.post("/", data=form)
    assert 200 == resp.status
    content = await resp.json()
    assert content == {"name": "text"}
    resp.close()


async def test_POST_DATA_with_charset(aiohttp_client) -> None:
    async def handler(request):
        mp = await request.multipart()
        part = await mp.next()
        text = await part.text()
        return web.Response(text=text)

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    form = aiohttp.FormData()
    form.add_field("name", "текст", content_type="text/plain; charset=koi8-r")

    resp = await client.post("/", data=form)
    assert 200 == resp.status
    content = await resp.text()
    assert content == "текст"
    resp.close()


async def test_POST_DATA_formdats_with_charset(aiohttp_client) -> None:
    async def handler(request):
        mp = await request.post()
        assert "name" in mp
        return web.Response(text=mp["name"])

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    form = aiohttp.FormData(charset="koi8-r")
    form.add_field("name", "текст")

    resp = await client.post("/", data=form)
    assert 200 == resp.status
    content = await resp.text()
    assert content == "текст"
    resp.close()


async def test_POST_DATA_with_charset_post(aiohttp_client) -> None:
    async def handler(request):
        data = await request.post()
        return web.Response(text=data["name"])

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    form = aiohttp.FormData()
    form.add_field("name", "текст", content_type="text/plain; charset=koi8-r")

    resp = await client.post("/", data=form)
    assert 200 == resp.status
    content = await resp.text()
    assert content == "текст"
    resp.close()


async def test_POST_MultiDict(aiohttp_client) -> None:
    async def handler(request):
        data = await request.post()
        assert data == MultiDict([("q", "test1"), ("q", "test2")])
        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    async with client.post(
        "/", data=MultiDict([("q", "test1"), ("q", "test2")])
    ) as resp:
        assert 200 == resp.status


async def test_GET_DEFLATE(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.json_response({"ok": True})

    write_mock = None
    writelines_mock = None
    original_write_bytes = ClientRequest.write_bytes

    async def write_bytes(
        self: ClientRequest,
        writer: StreamWriter,
        conn: Connection,
        content_length: Optional[int] = None,
    ) -> None:
        nonlocal write_mock, writelines_mock
        original_write = writer._write
        original_writelines = writer._writelines

        with (
            mock.patch.object(
                writer,
                "_write",
                autospec=True,
                spec_set=True,
                side_effect=original_write,
            ) as write_mock,
            mock.patch.object(
                writer,
                "_writelines",
                autospec=True,
                spec_set=True,
                side_effect=original_writelines,
            ) as writelines_mock,
        ):
            await original_write_bytes(self, writer, conn, content_length)

    with mock.patch.object(ClientRequest, "write_bytes", write_bytes):
        app = web.Application()
        app.router.add_get("/", handler)
        client = await aiohttp_client(app)

        async with client.get("/", data=b"", compress=True) as resp:
            assert resp.status == 200
            content = await resp.json()
            assert content == {"ok": True}

    # With packet coalescing, headers are buffered and may be written
    # during write_bytes if there's an empty body to process.
    # The test should verify no body chunks are written, but headers
    # may be written as part of the coalescing optimization.
    # If _write was called, it should only be for headers ending with \r\n\r\n
    # and not any body content
    for call in write_mock.call_args_list:  # type: ignore[union-attr]
        data = call[0][0]
        assert data.endswith(
            b"\r\n\r\n"
        ), "Only headers should be written, not body chunks"

    # No body data should be written via writelines either
    writelines_mock.assert_not_called()  # type: ignore[union-attr]


async def test_GET_DEFLATE_no_body(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.json_response({"ok": True})

    with mock.patch.object(ClientRequest, "write_bytes") as mock_write_bytes:
        app = web.Application()
        app.router.add_get("/", handler)
        client = await aiohttp_client(app)

        async with client.get("/", data=None, compress=True) as resp:
            assert resp.status == 200
            content = await resp.json()
            assert content == {"ok": True}

    # No chunks should have been sent for an empty body.
    mock_write_bytes.assert_not_called()


async def test_POST_DATA_DEFLATE(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        data = await request.post()
        return web.json_response(dict(data))

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    resp = await client.post("/", data={"some": "data"}, compress=True)
    assert 200 == resp.status
    content = await resp.json()
    assert content == {"some": "data"}
    resp.close()


async def test_POST_FILES(aiohttp_client, fname) -> None:
    content1 = fname.read_bytes()

    async def handler(request):
        data = await request.post()
        assert data["some"].filename == fname.name
        content2 = await asyncio.to_thread(data["some"].file.read)
        assert content2 == content1
        assert await asyncio.to_thread(data["test"].file.read) == b"data"
        data["some"].file.close()
        data["test"].file.close()
        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    with fname.open("rb") as f:
        async with client.post(
            "/", data={"some": f, "test": io.BytesIO(b"data")}, chunked=True
        ) as resp:
            assert 200 == resp.status


async def test_POST_FILES_DEFLATE(aiohttp_client, fname) -> None:
    content1 = fname.read_bytes()

    async def handler(request):
        data = await request.post()
        assert data["some"].filename == fname.name
        content2 = await asyncio.to_thread(data["some"].file.read)
        data["some"].file.close()
        assert content2 == content1
        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    with fname.open("rb") as f:
        async with client.post(
            "/", data={"some": f}, chunked=True, compress="deflate"
        ) as resp:
            assert 200 == resp.status


async def test_POST_bytes(aiohttp_client) -> None:
    body = b"0" * 12345

    async def handler(request):
        data = await request.read()
        assert body == data
        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    async with client.post("/", data=body) as resp:
        assert 200 == resp.status


async def test_POST_bytes_too_large(aiohttp_client) -> None:
    body = b"0" * (2**20 + 1)

    async def handler(request):
        data = await request.content.read()
        assert body == data
        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    with pytest.warns(ResourceWarning):
        resp = await client.post("/", data=body)

    assert 200 == resp.status
    resp.close()


async def test_POST_FILES_STR(aiohttp_client, fname) -> None:
    content1 = fname.read_bytes().decode()

    async def handler(request):
        data = await request.post()
        content2 = data["some"]
        assert content2 == content1
        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    with fname.open("rb") as f:
        async with client.post("/", data={"some": f.read().decode()}) as resp:
            assert 200 == resp.status


async def test_POST_FILES_STR_SIMPLE(aiohttp_client, fname) -> None:
    content = fname.read_bytes()

    async def handler(request):
        data = await request.read()
        assert data == content
        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    with fname.open("rb") as f:
        async with client.post("/", data=f.read()) as resp:
            assert 200 == resp.status


async def test_POST_FILES_LIST(aiohttp_client, fname) -> None:
    content = fname.read_bytes()

    async def handler(request):
        data = await request.post()
        assert fname.name == data["some"].filename
        assert await asyncio.to_thread(data["some"].file.read) == content
        data["some"].file.close()
        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    with fname.open("rb") as f:
        async with client.post("/", data=[("some", f)]) as resp:
            assert 200 == resp.status


async def test_POST_FILES_CT(aiohttp_client, fname) -> None:
    content = fname.read_bytes()

    async def handler(request):
        data = await request.post()
        assert fname.name == data["some"].filename
        assert "text/plain" == data["some"].content_type
        assert await asyncio.to_thread(data["some"].file.read) == content
        data["some"].file.close()
        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    with fname.open("rb") as f:
        form = aiohttp.FormData()
        form.add_field("some", f, content_type="text/plain")
        async with client.post("/", data=form) as resp:
            assert 200 == resp.status


async def test_POST_FILES_SINGLE(aiohttp_client, fname) -> None:
    content = fname.read_bytes().decode()

    async def handler(request):
        data = await request.text()
        assert data == content
        # if system cannot determine 'text/x-python' MIME type
        # then use 'application/octet-stream' default
        assert request.content_type in [
            "text/plain",
            "application/octet-stream",
            "text/x-python",
        ]
        assert "content-disposition" not in request.headers

        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    with fname.open("rb") as f:
        async with client.post("/", data=f) as resp:
            assert 200 == resp.status


async def test_POST_FILES_SINGLE_content_disposition(aiohttp_client, fname) -> None:
    content = fname.read_bytes().decode()

    async def handler(request):
        data = await request.text()
        assert data == content
        # if system cannot determine 'application/pgp-keys' MIME type
        # then use 'application/octet-stream' default
        assert request.content_type in [
            "text/plain",
            "application/octet-stream",
            "text/x-python",
        ]
        assert request.headers["content-disposition"] == (
            'inline; filename="conftest.py"'
        )

        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    with fname.open("rb") as f:
        async with client.post(
            "/", data=aiohttp.get_payload(f, disposition="inline")
        ) as resp:
            assert 200 == resp.status


async def test_POST_FILES_SINGLE_BINARY(aiohttp_client, fname) -> None:
    content = fname.read_bytes()

    async def handler(request):
        data = await request.read()
        assert data == content
        # if system cannot determine 'application/pgp-keys' MIME type
        # then use 'application/octet-stream' default
        assert request.content_type in [
            "application/pgp-keys",
            "text/plain",
            "text/x-python",
            "application/octet-stream",
        ]
        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    with fname.open("rb") as f:
        async with client.post("/", data=f) as resp:
            assert 200 == resp.status


async def test_POST_FILES_IO(aiohttp_client) -> None:
    async def handler(request):
        data = await request.post()
        assert b"data" == await asyncio.to_thread(data["unknown"].file.read)
        assert data["unknown"].content_type == "application/octet-stream"
        assert data["unknown"].filename == "unknown"
        data["unknown"].file.close()
        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    with io.BytesIO(b"data") as file_handle:
        async with client.post("/", data=[file_handle]) as resp:
            assert 200 == resp.status


async def test_POST_FILES_IO_WITH_PARAMS(aiohttp_client) -> None:
    async def handler(request):
        data = await request.post()
        assert data["test"] == "true"
        assert data["unknown"].content_type == "application/octet-stream"
        assert data["unknown"].filename == "unknown"
        assert await asyncio.to_thread(data["unknown"].file.read) == b"data"
        data["unknown"].file.close()
        assert data.getall("q") == ["t1", "t2"]

        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    with io.BytesIO(b"data") as file_handle:
        async with client.post(
            "/",
            data=(("test", "true"), MultiDict([("q", "t1"), ("q", "t2")]), file_handle),
        ) as resp:
            assert 200 == resp.status


async def test_POST_FILES_WITH_DATA(aiohttp_client, fname) -> None:
    content = fname.read_bytes()

    async def handler(request):
        data = await request.post()
        assert data["test"] == "true"
        assert data["some"].content_type in [
            "text/x-python",
            "text/plain",
            "application/octet-stream",
        ]
        assert data["some"].filename == fname.name
        assert await asyncio.to_thread(data["some"].file.read) == content
        data["some"].file.close()

        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    with fname.open("rb") as f:
        async with client.post("/", data={"test": "true", "some": f}) as resp:
            assert 200 == resp.status


async def test_POST_STREAM_DATA(aiohttp_client, fname) -> None:
    expected = fname.read_bytes()

    async def handler(request):
        assert request.content_type == "application/octet-stream"
        content = await request.read()
        assert request.content_length == len(expected)
        assert content == expected

        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    data_size = len(expected)

    with pytest.warns(DeprecationWarning):

        @aiohttp.streamer
        async def stream(writer, fname):
            with fname.open("rb") as f:
                data = await asyncio.to_thread(f.read, 100)
                while data:
                    await writer.write(data)
                    data = await asyncio.to_thread(f.read, 100)

    async with client.post(
        "/", data=stream(fname), headers={"Content-Length": str(data_size)}
    ) as resp:
        assert 200 == resp.status


async def test_POST_STREAM_DATA_no_params(aiohttp_client, fname) -> None:
    expected = fname.read_bytes()

    async def handler(request):
        assert request.content_type == "application/octet-stream"
        content = await request.read()
        assert request.content_length == len(expected)
        assert content == expected

        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    with fname.open("rb") as f:
        data_size = len(f.read())

    with pytest.warns(DeprecationWarning):

        @aiohttp.streamer
        async def stream(writer):
            with fname.open("rb") as f:
                data = await asyncio.to_thread(f.read, 100)
                while data:
                    await writer.write(data)
                    data = await asyncio.to_thread(f.read, 100)

    async with client.post(
        "/", data=stream, headers={"Content-Length": str(data_size)}
    ) as resp:
        assert 200 == resp.status


async def test_json(aiohttp_client) -> None:
    async def handler(request):
        assert request.content_type == "application/json"
        data = await request.json()
        return web.Response(body=aiohttp.JsonPayload(data))

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    resp = await client.post("/", json={"some": "data"})
    assert 200 == resp.status
    content = await resp.json()
    assert content == {"some": "data"}
    resp.close()

    with pytest.raises(ValueError):
        await client.post("/", data="some data", json={"some": "data"})


async def test_json_custom(aiohttp_client) -> None:
    async def handler(request):
        assert request.content_type == "application/json"
        data = await request.json()
        return web.Response(body=aiohttp.JsonPayload(data))

    used = False

    def dumps(obj):
        nonlocal used
        used = True
        return json.dumps(obj)

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app, json_serialize=dumps)

    resp = await client.post("/", json={"some": "data"})
    assert 200 == resp.status
    assert used
    content = await resp.json()
    assert content == {"some": "data"}
    resp.close()

    with pytest.raises(ValueError):
        await client.post("/", data="some data", json={"some": "data"})


async def test_expect_continue(aiohttp_client) -> None:
    expect_called = False

    async def handler(request):
        data = await request.post()
        assert data == {"some": "data"}
        return web.Response()

    async def expect_handler(request):
        nonlocal expect_called
        expect = request.headers.get(hdrs.EXPECT)
        if expect.lower() == "100-continue":
            request.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            expect_called = True

    app = web.Application()
    app.router.add_post("/", handler, expect_handler=expect_handler)
    client = await aiohttp_client(app)

    async with client.post("/", data={"some": "data"}, expect100=True) as resp:
        assert 200 == resp.status
    assert expect_called


async def test_expect100_with_no_body(aiohttp_client: AiohttpClient) -> None:
    """Test expect100 with GET request that has no body."""

    async def handler(request: web.Request) -> web.Response:
        return web.Response(text="OK")

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    # GET request with expect100=True but no body
    async with client.get("/", expect100=True) as resp:
        assert resp.status == 200
        assert await resp.text() == "OK"


async def test_expect100_continue_with_none_payload(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test expect100 continue handling when payload is None from the start."""
    expect_received = False

    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=b"OK")

    async def expect_handler(request: web.Request) -> None:
        nonlocal expect_received
        expect_received = True
        # Send 100 Continue
        assert request.transport is not None
        request.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")

    app = web.Application()
    app.router.add_post("/", handler, expect_handler=expect_handler)
    client = await aiohttp_client(app)

    # POST request with expect100=True but no body (data=None)
    async with client.post("/", expect100=True, data=None) as resp:
        assert resp.status == 200
        assert await resp.read() == b"OK"

    # Expect handler should still be called even with no body
    assert expect_received


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_encoding_deflate(aiohttp_client) -> None:
    async def handler(request):
        resp = web.Response(text="text")
        resp.enable_chunked_encoding()
        resp.enable_compression(web.ContentCoding.deflate)
        return resp

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/")
    assert 200 == resp.status
    txt = await resp.text()
    assert txt == "text"
    resp.close()


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_encoding_deflate_nochunk(aiohttp_client) -> None:
    async def handler(request):
        resp = web.Response(text="text")
        resp.enable_compression(web.ContentCoding.deflate)
        return resp

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/")
    assert 200 == resp.status
    txt = await resp.text()
    assert txt == "text"
    resp.close()


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_encoding_gzip(aiohttp_client) -> None:
    async def handler(request):
        resp = web.Response(text="text")
        resp.enable_chunked_encoding()
        resp.enable_compression(web.ContentCoding.gzip)
        return resp

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/")
    assert 200 == resp.status
    txt = await resp.text()
    assert txt == "text"
    resp.close()


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_encoding_gzip_write_by_chunks(aiohttp_client) -> None:
    async def handler(request):
        resp = web.StreamResponse()
        resp.enable_compression(web.ContentCoding.gzip)
        await resp.prepare(request)
        await resp.write(b"0")
        await resp.write(b"0")
        return resp

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/")
    assert 200 == resp.status
    txt = await resp.text()
    assert txt == "00"
    resp.close()


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_encoding_gzip_nochunk(aiohttp_client) -> None:
    async def handler(request):
        resp = web.Response(text="text")
        resp.enable_compression(web.ContentCoding.gzip)
        return resp

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/")
    assert 200 == resp.status
    txt = await resp.text()
    assert txt == "text"
    resp.close()


async def test_bad_payload_compression(aiohttp_client) -> None:
    async def handler(request):
        resp = web.Response(text="text")
        resp.headers["Content-Encoding"] = "gzip"
        return resp

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/")
    assert 200 == resp.status

    with pytest.raises(aiohttp.ClientPayloadError):
        await resp.read()

    resp.close()


async def test_bad_payload_chunked_encoding(aiohttp_client) -> None:
    async def handler(request):
        resp = web.StreamResponse()
        resp.force_close()
        resp._length_check = False
        resp.headers["Transfer-Encoding"] = "chunked"
        writer = await resp.prepare(request)
        await writer.write(b"9\r\n\r\n")
        await writer.write_eof()
        return resp

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/")
    assert 200 == resp.status

    with pytest.raises(aiohttp.ClientPayloadError):
        await resp.read()

    resp.close()


async def test_no_payload_304_with_chunked_encoding(aiohttp_client: Any) -> None:
    """Test a 304 response with no payload with chunked set should have it removed."""

    async def handler(request):
        resp = web.StreamResponse(status=304)
        resp.enable_chunked_encoding()
        resp._length_check = False
        resp.headers["Transfer-Encoding"] = "chunked"
        writer = await resp.prepare(request)
        await writer.write_eof()
        return resp

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/")
    assert resp.status == 304
    assert hdrs.CONTENT_LENGTH not in resp.headers
    assert hdrs.TRANSFER_ENCODING not in resp.headers
    await resp.read()

    resp.close()


async def test_head_request_with_chunked_encoding(aiohttp_client: Any) -> None:
    """Test a head response with chunked set should have it removed."""

    async def handler(request):
        resp = web.StreamResponse(status=200)
        resp.enable_chunked_encoding()
        resp._length_check = False
        resp.headers["Transfer-Encoding"] = "chunked"
        writer = await resp.prepare(request)
        await writer.write_eof()
        return resp

    app = web.Application()
    app.router.add_head("/", handler)
    client = await aiohttp_client(app)

    resp = await client.head("/")
    assert resp.status == 200
    assert hdrs.CONTENT_LENGTH not in resp.headers
    assert hdrs.TRANSFER_ENCODING not in resp.headers
    await resp.read()

    resp.close()


async def test_no_payload_200_with_chunked_encoding(aiohttp_client: Any) -> None:
    """Test chunked is preserved on a 200 response with no payload."""

    async def handler(request):
        resp = web.StreamResponse(status=200)
        resp.enable_chunked_encoding()
        resp._length_check = False
        resp.headers["Transfer-Encoding"] = "chunked"
        writer = await resp.prepare(request)
        await writer.write_eof()
        return resp

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/")
    assert resp.status == 200
    assert hdrs.CONTENT_LENGTH not in resp.headers
    assert hdrs.TRANSFER_ENCODING in resp.headers
    await resp.read()

    resp.close()


async def test_bad_payload_content_length(aiohttp_client: Any) -> None:
    async def handler(request):
        resp = web.Response(text="text")
        resp.headers["Content-Length"] = "10000"
        resp.force_close()
        return resp

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/")
    assert 200 == resp.status

    with pytest.raises(aiohttp.ClientPayloadError):
        await resp.read()

    resp.close()


async def test_payload_content_length_by_chunks(aiohttp_client) -> None:
    async def handler(request):
        resp = web.StreamResponse(headers={"content-length": "2"})
        await resp.prepare(request)
        await resp.write(b"answer")
        await resp.write(b"two")
        request.transport.close()
        return resp

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/")
    data = await resp.read()
    assert data == b"an"
    resp.close()


async def test_chunked(aiohttp_client) -> None:
    async def handler(request):
        resp = web.Response(text="text")
        resp.enable_chunked_encoding()
        return resp

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/")
    assert 200 == resp.status
    assert resp.headers["Transfer-Encoding"] == "chunked"
    txt = await resp.text()
    assert txt == "text"
    resp.close()


async def test_shortcuts(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(text=request.method)

    app = web.Application()
    for meth in ("get", "post", "put", "delete", "head", "patch", "options"):
        app.router.add_route(meth.upper(), "/", handler)
    client = await aiohttp_client(app)

    for meth in ("get", "post", "put", "delete", "head", "patch", "options"):
        coro = getattr(client.session, meth)
        resp = await coro(client.make_url("/"))

        assert resp.status == 200
        assert len(resp.history) == 0

        content1 = await resp.read()
        content2 = await resp.read()
        assert content1 == content2
        content = await resp.text()

        if meth == "head":
            assert b"" == content1
        else:
            assert meth.upper() == content


async def test_cookies(aiohttp_client) -> None:
    async def handler(request):
        assert request.cookies.keys() == {"test1", "test3"}
        assert request.cookies["test1"] == "123"
        assert request.cookies["test3"] == "456"
        return web.Response()

    c = http.cookies.Morsel()
    c.set("test3", "456", "456")

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app, cookies={"test1": "123", "test2": c})

    async with client.get("/") as resp:
        assert 200 == resp.status


async def test_cookies_per_request(aiohttp_client) -> None:
    async def handler(request):
        assert request.cookies.keys() == {"test1", "test3", "test4", "test6"}
        assert request.cookies["test1"] == "123"
        assert request.cookies["test3"] == "456"
        assert request.cookies["test4"] == "789"
        assert request.cookies["test6"] == "abc"
        return web.Response()

    c = http.cookies.Morsel()
    c.set("test3", "456", "456")

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app, cookies={"test1": "123", "test2": c})

    rc = http.cookies.Morsel()
    rc.set("test6", "abc", "abc")

    async with client.get("/", cookies={"test4": "789", "test5": rc}) as resp:
        assert 200 == resp.status


async def test_cookies_redirect(aiohttp_client) -> None:
    async def redirect1(request):
        ret = web.Response(status=301, headers={"Location": "/redirect2"})
        ret.set_cookie("c", "1")
        return ret

    async def redirect2(request):
        ret = web.Response(status=301, headers={"Location": "/"})
        ret.set_cookie("c", "2")
        return ret

    async def handler(request):
        assert request.cookies.keys() == {"c"}
        assert request.cookies["c"] == "2"
        return web.Response()

    app = web.Application()
    app.router.add_get("/redirect1", redirect1)
    app.router.add_get("/redirect2", redirect2)
    app.router.add_get("/", handler)

    client = await aiohttp_client(app)
    async with client.get("/redirect1") as resp:
        assert 200 == resp.status


async def test_cookies_on_empty_session_jar(aiohttp_client) -> None:
    async def handler(request):
        assert "custom-cookie" in request.cookies
        assert request.cookies["custom-cookie"] == "abc"
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app, cookies=None)

    async with client.get("/", cookies={"custom-cookie": "abc"}) as resp:
        assert 200 == resp.status


async def test_morsel_with_attributes(aiohttp_client) -> None:
    # A comment from original test:
    #
    # No cookie attribute should pass here
    # they are only used as filters
    # whether to send particular cookie or not.
    # E.g. if cookie expires it just becomes thrown away.
    # Server who sent the cookie with some attributes
    # already knows them, no need to send this back again and again

    async def handler(request):
        assert request.cookies.keys() == {"test3"}
        assert request.cookies["test3"] == "456"
        return web.Response()

    c = http.cookies.Morsel()
    c.set("test3", "456", "456")
    c["httponly"] = True
    c["secure"] = True
    c["max-age"] = 1000

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app, cookies={"test2": c})

    async with client.get("/") as resp:
        assert 200 == resp.status


async def test_set_cookies(
    aiohttp_client: AiohttpClient, caplog: pytest.LogCaptureFixture
) -> None:
    async def handler(request: web.Request) -> web.Response:
        ret = web.Response()
        ret.set_cookie("c1", "cookie1")
        ret.set_cookie("c2", "cookie2")
        ret.headers.add(
            "Set-Cookie",
            "invalid,cookie=value; "  # Comma character is not allowed
            "HttpOnly; Path=/",
        )
        return ret

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    with caplog.at_level(logging.WARNING):
        async with client.get("/") as resp:
            assert 200 == resp.status
            cookie_names = {c.key for c in client.session.cookie_jar}
            _ = resp.cookies
        assert cookie_names == {"c1", "c2"}

    assert "Can not load cookies: Illegal cookie name 'invalid,cookie'" in caplog.text


async def test_set_cookies_with_curly_braces(aiohttp_client: AiohttpClient) -> None:
    """Test that cookies with curly braces in names are now accepted (#2683)."""

    async def handler(request: web.Request) -> web.Response:
        ret = web.Response()
        ret.set_cookie("c1", "cookie1")
        ret.headers.add(
            "Set-Cookie",
            "ISAWPLB{A7F52349-3531-4DA9-8776-F74BC6F4F1BB}="
            "{925EC0B8-CB17-4BEB-8A35-1033813B0523}; "
            "HttpOnly; Path=/",
        )
        return ret

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    async with client.get("/") as resp:
        assert 200 == resp.status
        cookie_names = {c.key for c in client.session.cookie_jar}
        assert cookie_names == {"c1", "ISAWPLB{A7F52349-3531-4DA9-8776-F74BC6F4F1BB}"}


async def test_set_cookies_expired(aiohttp_client) -> None:
    async def handler(request):
        ret = web.Response()
        ret.set_cookie("c1", "cookie1")
        ret.set_cookie("c2", "cookie2")
        ret.headers.add(
            "Set-Cookie",
            "c3=cookie3; HttpOnly; Path=/ Expires=Tue, 1 Jan 1980 12:00:00 GMT; ",
        )
        return ret

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    async with client.get("/") as resp:
        assert 200 == resp.status
        cookie_names = {c.key for c in client.session.cookie_jar}
    assert cookie_names == {"c1", "c2"}


async def test_set_cookies_max_age(aiohttp_client) -> None:
    async def handler(request):
        ret = web.Response()
        ret.set_cookie("c1", "cookie1")
        ret.set_cookie("c2", "cookie2")
        ret.headers.add("Set-Cookie", "c3=cookie3; HttpOnly; Path=/ Max-Age=1; ")
        return ret

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    async with client.get("/") as resp:
        assert 200 == resp.status
        cookie_names = {c.key for c in client.session.cookie_jar}
        assert cookie_names == {"c1", "c2", "c3"}
        await asyncio.sleep(2)
        cookie_names = {c.key for c in client.session.cookie_jar}
        assert cookie_names == {"c1", "c2"}


async def test_set_cookies_max_age_overflow(aiohttp_client) -> None:
    async def handler(request):
        ret = web.Response()
        ret.headers.add(
            "Set-Cookie",
            "overflow=overflow; HttpOnly; Path=/ Max-Age=" + str(overflow) + "; ",
        )
        return ret

    overflow = int(
        datetime.datetime.max.replace(tzinfo=datetime.timezone.utc).timestamp()
    )
    empty = None
    try:
        empty = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            seconds=overflow
        )
    except OverflowError as ex:
        assert isinstance(ex, OverflowError)
    assert not isinstance(empty, datetime.datetime)
    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    async with client.get("/") as resp:
        assert 200 == resp.status
        for cookie in client.session.cookie_jar:
            if cookie.key == "overflow":
                assert int(cookie["max-age"]) == int(overflow)


async def test_request_conn_error() -> None:
    client = aiohttp.ClientSession()
    with pytest.raises(aiohttp.ClientConnectionError):
        await client.get("http://0.0.0.0:1")
    await client.close()


@pytest.mark.xfail
async def test_broken_connection(aiohttp_client) -> None:
    async def handler(request):
        request.transport.close()
        return web.Response(text="answer" * 1000)

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    with pytest.raises(aiohttp.ClientResponseError):
        await client.get("/")


async def test_broken_connection_2(aiohttp_client) -> None:
    async def handler(request):
        resp = web.StreamResponse(headers={"content-length": "1000"})
        await resp.prepare(request)
        await resp.write(b"answer")
        request.transport.close()
        return resp

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/")
    with pytest.raises(aiohttp.ClientPayloadError):
        await resp.read()
    resp.close()


async def test_custom_headers(aiohttp_client) -> None:
    async def handler(request):
        assert request.headers["x-api-key"] == "foo"
        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    async with client.post(
        "/", headers={"Content-Type": "application/json", "x-api-key": "foo"}
    ) as resp:
        assert resp.status == 200


async def test_redirect_to_absolute_url(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(text=request.method)

    async def redirect(request):
        raise web.HTTPFound(location=client.make_url("/"))

    app = web.Application()
    app.router.add_get("/", handler)
    app.router.add_get("/redirect", redirect)

    client = await aiohttp_client(app)
    async with client.get("/redirect") as resp:
        assert 200 == resp.status


async def test_redirect_without_location_header(aiohttp_client) -> None:
    body = b"redirect"

    async def handler_redirect(request):
        return web.Response(status=301, body=body)

    app = web.Application()
    app.router.add_route("GET", "/redirect", handler_redirect)
    client = await aiohttp_client(app)

    resp = await client.get("/redirect")
    data = await resp.read()
    assert data == body


async def test_chunked_deprecated(aiohttp_client) -> None:
    async def handler_redirect(request):
        return web.Response(status=301)

    app = web.Application()
    app.router.add_route("GET", "/redirect", handler_redirect)
    client = await aiohttp_client(app)

    with pytest.warns(DeprecationWarning):
        await client.post("/", chunked=1024)


INVALID_URL_WITH_ERROR_MESSAGE_YARL_NEW = (
    # yarl.URL.__new__ raises ValueError
    ("http://:/", "http://:/"),
    ("http://example.org:non_int_port/", "http://example.org:non_int_port/"),
)

INVALID_URL_WITH_ERROR_MESSAGE_YARL_ORIGIN = (
    # # yarl.URL.origin raises ValueError
    ("http:/", "http:///"),
    ("http:/example.com", "http:///example.com"),
    ("http:///example.com", "http:///example.com"),
)

NON_HTTP_URL_WITH_ERROR_MESSAGE = (
    ("call:+380123456789", r"call:\+380123456789"),
    ("skype:handle", "skype:handle"),
    ("slack://instance/room", "slack://instance/room"),
    ("steam:code", "steam:code"),
    ("twitter://handle", "twitter://handle"),
    ("bluesky://profile/d:i:d", "bluesky://profile/d:i:d"),
)


@pytest.mark.parametrize(
    ("url", "error_message_url", "expected_exception_class"),
    (
        *(
            (url, message, InvalidUrlClientError)
            for (url, message) in INVALID_URL_WITH_ERROR_MESSAGE_YARL_NEW
        ),
        *(
            (url, message, InvalidUrlClientError)
            for (url, message) in INVALID_URL_WITH_ERROR_MESSAGE_YARL_ORIGIN
        ),
        *(
            (url, message, NonHttpUrlClientError)
            for (url, message) in NON_HTTP_URL_WITH_ERROR_MESSAGE
        ),
    ),
)
async def test_invalid_and_non_http_url(
    url: Any, error_message_url: Any, expected_exception_class: Any
) -> None:
    async with aiohttp.ClientSession() as http_session:
        with pytest.raises(
            expected_exception_class, match=rf"^{error_message_url}( - [A-Za-z ]+)?"
        ):
            await http_session.get(url)


@pytest.mark.parametrize(
    ("invalid_redirect_url", "error_message_url", "expected_exception_class"),
    (
        *(
            (url, message, InvalidUrlRedirectClientError)
            for (url, message) in INVALID_URL_WITH_ERROR_MESSAGE_YARL_ORIGIN
            + INVALID_URL_WITH_ERROR_MESSAGE_YARL_NEW
        ),
        *(
            (url, message, NonHttpUrlRedirectClientError)
            for (url, message) in NON_HTTP_URL_WITH_ERROR_MESSAGE
        ),
    ),
)
async def test_invalid_redirect_url(
    aiohttp_client: Any,
    invalid_redirect_url: Any,
    error_message_url: str,
    expected_exception_class: Any,
) -> None:
    headers = {hdrs.LOCATION: invalid_redirect_url}

    async def generate_redirecting_response(request):
        return web.Response(status=301, headers=headers)

    app = web.Application()
    app.router.add_get("/redirect", generate_redirecting_response)
    client = await aiohttp_client(app)

    with pytest.raises(
        expected_exception_class, match=rf"^{error_message_url}( - [A-Za-z ]+)?"
    ):
        await client.get("/redirect")


@pytest.mark.parametrize(
    ("invalid_redirect_url", "error_message_url", "expected_exception_class"),
    (
        *(
            (url, message, InvalidUrlRedirectClientError)
            for (url, message) in INVALID_URL_WITH_ERROR_MESSAGE_YARL_ORIGIN
            + INVALID_URL_WITH_ERROR_MESSAGE_YARL_NEW
        ),
        *(
            (url, message, NonHttpUrlRedirectClientError)
            for (url, message) in NON_HTTP_URL_WITH_ERROR_MESSAGE
        ),
    ),
)
async def test_invalid_redirect_url_multiple_redirects(
    aiohttp_client: Any,
    invalid_redirect_url: Any,
    error_message_url: str,
    expected_exception_class: Any,
) -> None:
    app = web.Application()

    for path, location in [
        ("/redirect", "/redirect1"),
        ("/redirect1", "/redirect2"),
        ("/redirect2", invalid_redirect_url),
    ]:

        async def generate_redirecting_response(request):
            return web.Response(status=301, headers={hdrs.LOCATION: location})

        app.router.add_get(path, generate_redirecting_response)

    client = await aiohttp_client(app)

    with pytest.raises(
        expected_exception_class, match=rf"^{error_message_url}( - [A-Za-z ]+)?"
    ):
        await client.get("/redirect")


@pytest.mark.parametrize(
    ("status", "expected_ok"),
    (
        (200, True),
        (201, True),
        (301, True),
        (400, False),
        (403, False),
        (500, False),
    ),
)
async def test_ok_from_status(aiohttp_client, status, expected_ok) -> None:
    async def handler(request):
        return web.Response(status=status, body=b"")

    app = web.Application()
    app.router.add_route("GET", "/endpoint", handler)
    client = await aiohttp_client(app, raise_for_status=False)
    async with client.get("/endpoint") as resp:
        assert resp.ok is expected_ok


async def test_raise_for_status(aiohttp_client) -> None:
    async def handler_redirect(request):
        raise web.HTTPBadRequest()

    app = web.Application()
    app.router.add_route("GET", "/", handler_redirect)
    client = await aiohttp_client(app, raise_for_status=True)

    with pytest.raises(aiohttp.ClientResponseError):
        await client.get("/")


async def test_raise_for_status_per_request(aiohttp_client) -> None:
    async def handler_redirect(request):
        raise web.HTTPBadRequest()

    app = web.Application()
    app.router.add_route("GET", "/", handler_redirect)
    client = await aiohttp_client(app)

    with pytest.raises(aiohttp.ClientResponseError):
        await client.get("/", raise_for_status=True)


async def test_raise_for_status_disable_per_request(aiohttp_client) -> None:
    async def handler_redirect(request):
        raise web.HTTPBadRequest()

    app = web.Application()
    app.router.add_route("GET", "/", handler_redirect)
    client = await aiohttp_client(app, raise_for_status=True)

    async with client.get("/", raise_for_status=False) as resp:
        assert 400 == resp.status


async def test_request_raise_for_status_default(aiohttp_server) -> None:
    async def handler(request):
        raise web.HTTPBadRequest()

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with aiohttp.request("GET", server.make_url("/")) as resp:
        assert resp.status == 400


async def test_request_raise_for_status_disabled(aiohttp_server) -> None:
    async def handler(request):
        raise web.HTTPBadRequest()

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)
    url = server.make_url("/")

    async with aiohttp.request("GET", url, raise_for_status=False) as resp:
        assert resp.status == 400


async def test_request_raise_for_status_enabled(aiohttp_server) -> None:
    async def handler(request):
        raise web.HTTPBadRequest()

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)
    url = server.make_url("/")

    with pytest.raises(aiohttp.ClientResponseError):
        async with aiohttp.request("GET", url, raise_for_status=True):
            assert False, "never executed"  # pragma: no cover


async def test_session_raise_for_status_coro(aiohttp_client) -> None:
    async def handle(request):
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_route("GET", "/", handle)

    raise_for_status_called = 0

    async def custom_r4s(response):
        nonlocal raise_for_status_called
        raise_for_status_called += 1
        assert response.status == 200
        assert response.request_info.method == "GET"

    client = await aiohttp_client(app, raise_for_status=custom_r4s)
    await client.get("/")
    assert raise_for_status_called == 1
    await client.get("/", raise_for_status=True)
    assert raise_for_status_called == 1  # custom_r4s not called again
    await client.get("/", raise_for_status=False)
    assert raise_for_status_called == 1  # custom_r4s not called again


async def test_request_raise_for_status_coro(aiohttp_client) -> None:
    async def handle(request):
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_route("GET", "/", handle)

    raise_for_status_called = 0

    async def custom_r4s(response):
        nonlocal raise_for_status_called
        raise_for_status_called += 1
        assert response.status == 200
        assert response.request_info.method == "GET"

    client = await aiohttp_client(app)
    await client.get("/", raise_for_status=custom_r4s)
    assert raise_for_status_called == 1
    await client.get("/", raise_for_status=True)
    assert raise_for_status_called == 1  # custom_r4s not called again
    await client.get("/", raise_for_status=False)
    assert raise_for_status_called == 1  # custom_r4s not called again


async def test_invalid_idna() -> None:
    session = aiohttp.ClientSession()
    try:
        with pytest.raises(aiohttp.InvalidURL):
            await session.get("http://\u2061owhefopw.com")
    finally:
        await session.close()


async def test_creds_in_auth_and_url() -> None:
    session = aiohttp.ClientSession()
    try:
        with pytest.raises(ValueError):
            await session.get(
                "http://user:pass@example.com", auth=aiohttp.BasicAuth("user2", "pass2")
            )
    finally:
        await session.close()


async def test_creds_in_auth_and_redirect_url(
    create_server_for_url_and_handler: Callable[[URL, Handler], Awaitable[TestServer]],
) -> None:
    """Verify that credentials in redirect URLs can and do override any previous credentials."""
    url_from = URL("http://example.com")
    url_to = URL("http://user@example.com")
    redirected = False

    async def srv(request: web.Request) -> web.Response:
        nonlocal redirected

        assert request.host == url_from.host

        if not redirected:
            redirected = True
            raise web.HTTPMovedPermanently(url_to)

        return web.Response()

    server = await create_server_for_url_and_handler(url_from, srv)

    etc_hosts = {
        (url_from.host, 80): server,
    }

    class FakeResolver(AbstractResolver):
        async def resolve(
            self,
            host: str,
            port: int = 0,
            family: socket.AddressFamily = socket.AF_INET,
        ) -> List[ResolveResult]:
            server = etc_hosts[(host, port)]
            assert server.port is not None

            return [
                {
                    "hostname": host,
                    "host": server.host,
                    "port": server.port,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": socket.AI_NUMERICHOST,
                }
            ]

        async def close(self) -> None:
            """Dummy"""

    connector = aiohttp.TCPConnector(resolver=FakeResolver(), ssl=False)

    async with (
        aiohttp.ClientSession(connector=connector) as client,
        client.get(url_from, auth=aiohttp.BasicAuth("user", "pass")) as resp,
    ):
        assert len(resp.history) == 1
        assert str(resp.url) == "http://example.com"
        assert resp.status == 200
        assert (
            resp.request_info.headers.get("authorization") == "Basic dXNlcjo="
        ), "Expected redirect credentials to take precedence over provided auth"


@pytest.fixture
def create_server_for_url_and_handler(aiohttp_server, tls_certificate_authority):
    def create(url, srv):
        app = web.Application()
        app.router.add_route("GET", url.path, srv)

        kwargs = {}
        if url.scheme == "https":
            cert = tls_certificate_authority.issue_cert(
                url.host, "localhost", "127.0.0.1"
            )
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            cert.configure_cert(ssl_ctx)
            kwargs["ssl"] = ssl_ctx
        return aiohttp_server(app, **kwargs)

    return create


@pytest.mark.parametrize(
    ["url_from", "url_to"],
    [
        ["http://host1.com/path1", "http://host2.com/path2"],
        ["http://host1.com/path1", "https://host1.com/path1"],
        ["https://host1.com/path1", "http://host1.com/path2"],
    ],
    ids=(
        "entirely different hosts",
        "http -> https",
        "https -> http",
    ),
)
async def test_drop_auth_on_redirect_to_other_host(
    create_server_for_url_and_handler,
    url_from,
    url_to,
) -> None:
    url_from, url_to = URL(url_from), URL(url_to)

    async def srv_from(request):
        assert request.host == url_from.host
        assert request.headers["Authorization"] == "Basic dXNlcjpwYXNz"
        raise web.HTTPFound(url_to)

    async def srv_to(request):
        assert request.host == url_to.host
        assert "Authorization" not in request.headers, "Header wasn't dropped"
        return web.Response()

    server_from = await create_server_for_url_and_handler(url_from, srv_from)
    server_to = await create_server_for_url_and_handler(url_to, srv_to)

    assert (
        url_from.host != url_to.host or server_from.scheme != server_to.scheme
    ), "Invalid test case, host or scheme must differ"

    protocol_port_map = {
        "http": 80,
        "https": 443,
    }
    etc_hosts = {
        (url_from.host, protocol_port_map[server_from.scheme]): server_from,
        (url_to.host, protocol_port_map[server_to.scheme]): server_to,
    }

    class FakeResolver(AbstractResolver):
        async def resolve(self, host, port=0, family=socket.AF_INET):
            server = etc_hosts[(host, port)]

            return [
                {
                    "hostname": host,
                    "host": server.host,
                    "port": server.port,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": socket.AI_NUMERICHOST,
                }
            ]

        async def close(self):
            pass

    connector = aiohttp.TCPConnector(resolver=FakeResolver(), ssl=False)

    async with aiohttp.ClientSession(connector=connector) as client:
        resp = await client.get(
            url_from,
            auth=aiohttp.BasicAuth("user", "pass"),
        )
        assert resp.status == 200
        resp = await client.get(
            url_from,
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        assert resp.status == 200


async def test_auth_persist_on_redirect_to_other_host_with_global_auth(
    create_server_for_url_and_handler,
) -> None:
    url_from = URL("http://host1.com/path1")
    url_to = URL("http://host2.com/path2")

    async def srv_from(request: web.Request):
        assert request.host == url_from.host
        assert request.headers["Authorization"] == "Basic dXNlcjpwYXNz"
        raise web.HTTPFound(url_to)

    async def srv_to(request: web.Request) -> web.Response:
        assert request.host == url_to.host
        assert "Authorization" in request.headers, "Header was dropped"
        return web.Response()

    server_from = await create_server_for_url_and_handler(url_from, srv_from)
    server_to = await create_server_for_url_and_handler(url_to, srv_to)

    assert (
        url_from.host != url_to.host or server_from.scheme != server_to.scheme
    ), "Invalid test case, host or scheme must differ"

    protocol_port_map = {
        "http": 80,
        "https": 443,
    }
    etc_hosts = {
        (url_from.host, protocol_port_map[server_from.scheme]): server_from,
        (url_to.host, protocol_port_map[server_to.scheme]): server_to,
    }

    class FakeResolver(AbstractResolver):
        async def resolve(
            self,
            host: str,
            port: int = 0,
            family: socket.AddressFamily = socket.AF_INET,
        ):
            server = etc_hosts[(host, port)]
            assert server.port is not None

            return [
                {
                    "hostname": host,
                    "host": server.host,
                    "port": server.port,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": socket.AI_NUMERICHOST,
                }
            ]

        async def close(self) -> None:
            """Dummy"""

    connector = aiohttp.TCPConnector(resolver=FakeResolver(), ssl=False)

    async with aiohttp.ClientSession(
        connector=connector, auth=aiohttp.BasicAuth("user", "pass")
    ) as client:
        resp = await client.get(url_from)
        assert resp.status == 200


async def test_drop_auth_on_redirect_to_other_host_with_global_auth_and_base_url(
    create_server_for_url_and_handler,
) -> None:
    url_from = URL("http://host1.com/path1")
    url_to = URL("http://host2.com/path2")

    async def srv_from(request: web.Request):
        assert request.host == url_from.host
        assert request.headers["Authorization"] == "Basic dXNlcjpwYXNz"
        raise web.HTTPFound(url_to)

    async def srv_to(request: web.Request) -> web.Response:
        assert request.host == url_to.host
        assert "Authorization" not in request.headers, "Header was not dropped"
        return web.Response()

    server_from = await create_server_for_url_and_handler(url_from, srv_from)
    server_to = await create_server_for_url_and_handler(url_to, srv_to)

    assert (
        url_from.host != url_to.host or server_from.scheme != server_to.scheme
    ), "Invalid test case, host or scheme must differ"

    protocol_port_map = {
        "http": 80,
        "https": 443,
    }
    etc_hosts = {
        (url_from.host, protocol_port_map[server_from.scheme]): server_from,
        (url_to.host, protocol_port_map[server_to.scheme]): server_to,
    }

    class FakeResolver(AbstractResolver):
        async def resolve(
            self,
            host: str,
            port: int = 0,
            family: socket.AddressFamily = socket.AF_INET,
        ):
            server = etc_hosts[(host, port)]
            assert server.port is not None

            return [
                {
                    "hostname": host,
                    "host": server.host,
                    "port": server.port,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": socket.AI_NUMERICHOST,
                }
            ]

        async def close(self) -> None:
            """Dummy"""

    connector = aiohttp.TCPConnector(resolver=FakeResolver(), ssl=False)

    async with aiohttp.ClientSession(
        connector=connector,
        base_url="http://host1.com",
        auth=aiohttp.BasicAuth("user", "pass"),
    ) as client:
        resp = await client.get("/path1")
        assert resp.status == 200


async def test_async_with_session() -> None:
    async with aiohttp.ClientSession() as session:
        pass

    assert session.closed


async def test_session_close_awaitable() -> None:
    session = aiohttp.ClientSession()
    await session.close()

    assert session.closed


async def test_close_resp_on_error_async_with_session(aiohttp_server) -> None:
    async def handler(request):
        resp = web.StreamResponse(headers={"content-length": "100"})
        await resp.prepare(request)
        await asyncio.sleep(0.1)
        return resp

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with aiohttp.ClientSession() as session:
        with pytest.raises(RuntimeError):
            async with session.get(server.make_url("/")) as resp:
                resp.content.set_exception(RuntimeError())
                await resp.read()

        assert len(session._connector._conns) == 0


async def test_release_resp_on_normal_exit_from_cm(aiohttp_server) -> None:
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with aiohttp.ClientSession() as session:
        async with session.get(server.make_url("/")) as resp:
            await resp.read()

        assert len(session._connector._conns) == 1


async def test_non_close_detached_session_on_error_cm(aiohttp_server) -> None:
    async def handler(request):
        resp = web.StreamResponse(headers={"content-length": "100"})
        await resp.prepare(request)
        await asyncio.sleep(0.1)
        return resp

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    session = aiohttp.ClientSession()
    cm = session.get(server.make_url("/"))
    assert not session.closed
    with pytest.raises(RuntimeError):
        async with cm as resp:
            resp.content.set_exception(RuntimeError())
            await resp.read()
    assert not session.closed


async def test_close_detached_session_on_non_existing_addr() -> None:
    class FakeResolver(AbstractResolver):
        async def resolve(host, port=0, family=socket.AF_INET):
            return {}

        async def close(self):
            pass

    connector = aiohttp.TCPConnector(resolver=FakeResolver())

    session = aiohttp.ClientSession(connector=connector)

    async with session:
        cm = session.get("http://non-existing.example.com")
        assert not session.closed
        with pytest.raises(Exception):
            await cm

    assert session.closed


async def test_aiohttp_request_context_manager(aiohttp_server) -> None:
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with aiohttp.request("GET", server.make_url("/")) as resp:
        await resp.read()
        assert resp.status == 200


async def test_aiohttp_request_ctx_manager_close_sess_on_error(
    ssl_ctx, aiohttp_server
) -> None:
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app, ssl=ssl_ctx)

    cm = aiohttp.request("GET", server.make_url("/"))

    with pytest.raises(aiohttp.ClientConnectionError):
        async with cm:
            pass

    assert cm._session.closed
    # Allow event loop to process transport cleanup
    # on Python < 3.11
    await asyncio.sleep(0)


async def test_aiohttp_request_ctx_manager_not_found() -> None:

    with pytest.raises(aiohttp.ClientConnectionError):
        async with aiohttp.request("GET", "http://wrong-dns-name.com"):
            assert False, "never executed"  # pragma: no cover


async def test_raising_client_connector_dns_error_on_dns_failure() -> None:
    """Verify that the exception raised when a DNS lookup fails is specific to DNS."""
    with mock.patch(
        "aiohttp.connector.TCPConnector._resolve_host", autospec=True, spec_set=True
    ) as mock_resolve_host:
        mock_resolve_host.side_effect = OSError(None, "DNS lookup failed")
        with pytest.raises(aiohttp.ClientConnectorDNSError, match="DNS lookup failed"):
            async with aiohttp.request("GET", "http://wrong-dns-name.com"):
                assert False, "never executed"


async def test_aiohttp_request_coroutine(aiohttp_server: AiohttpServer) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    not_an_awaitable = aiohttp.request("GET", server.make_url("/"))
    with pytest.raises(
        TypeError,
        match="^object _SessionRequestContextManager "
        "can't be used in 'await' expression$",
    ):
        await not_an_awaitable  # type: ignore[misc]

    await not_an_awaitable._coro  # coroutine 'ClientSession._request' was never awaited
    await server.close()


async def test_aiohttp_request_ssl(
    aiohttp_server: AiohttpServer,
    ssl_ctx: ssl.SSLContext,
    client_ssl_ctx: ssl.SSLContext,
) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app, ssl=ssl_ctx)

    async with aiohttp.request("GET", server.make_url("/"), ssl=client_ssl_ctx) as resp:
        assert resp.status == 200


async def test_yield_from_in_session_request(aiohttp_client: AiohttpClient) -> None:
    # a test for backward compatibility with yield from syntax
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app)
    async with client.get("/") as resp:
        assert resp.status == 200


async def test_close_context_manager(aiohttp_client) -> None:
    # a test for backward compatibility with yield from syntax
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app)
    ctx = client.get("/")
    ctx.close()
    assert not ctx._coro.cr_running


async def test_session_auth(aiohttp_client) -> None:
    async def handler(request):
        return web.json_response({"headers": dict(request.headers)})

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app, auth=aiohttp.BasicAuth("login", "pass"))

    r = await client.get("/")
    assert r.status == 200
    content = await r.json()
    assert content["headers"]["Authorization"] == "Basic bG9naW46cGFzcw=="


async def test_session_auth_override(aiohttp_client) -> None:
    async def handler(request):
        return web.json_response({"headers": dict(request.headers)})

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app, auth=aiohttp.BasicAuth("login", "pass"))

    r = await client.get("/", auth=aiohttp.BasicAuth("other_login", "pass"))
    assert r.status == 200
    content = await r.json()
    val = content["headers"]["Authorization"]
    assert val == "Basic b3RoZXJfbG9naW46cGFzcw=="


async def test_session_auth_header_conflict(aiohttp_client) -> None:
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app, auth=aiohttp.BasicAuth("login", "pass"))
    headers = {"Authorization": "Basic b3RoZXJfbG9naW46cGFzcw=="}
    with pytest.raises(ValueError):
        await client.get("/", headers=headers)


async def test_session_headers(aiohttp_client) -> None:
    async def handler(request):
        return web.json_response({"headers": dict(request.headers)})

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app, headers={"X-Real-IP": "192.168.0.1"})

    r = await client.get("/")
    assert r.status == 200
    content = await r.json()
    assert content["headers"]["X-Real-IP"] == "192.168.0.1"


async def test_session_headers_merge(aiohttp_client) -> None:
    async def handler(request):
        return web.json_response({"headers": dict(request.headers)})

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(
        app, headers=[("X-Real-IP", "192.168.0.1"), ("X-Sent-By", "requests")]
    )

    r = await client.get("/", headers={"X-Sent-By": "aiohttp"})
    assert r.status == 200
    content = await r.json()
    assert content["headers"]["X-Real-IP"] == "192.168.0.1"
    assert content["headers"]["X-Sent-By"] == "aiohttp"


async def test_multidict_headers(aiohttp_client) -> None:
    async def handler(request):
        assert await request.read() == data
        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)

    client = await aiohttp_client(app)

    data = b"sample data"

    async with client.post(
        "/", data=data, headers=MultiDict({"Content-Length": str(len(data))})
    ) as r:
        assert r.status == 200


async def test_request_conn_closed(aiohttp_client) -> None:
    async def handler(request):
        request.transport.close()
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app)
    with pytest.raises(aiohttp.ServerDisconnectedError) as excinfo:
        resp = await client.get("/")
        await resp.read()

    assert str(excinfo.value) != ""


async def test_dont_close_explicit_connector(aiohttp_client) -> None:
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app)
    r = await client.get("/")
    await r.read()

    assert 1 == len(client.session.connector._conns)


async def test_server_close_keepalive_connection() -> None:
    loop = asyncio.get_event_loop()

    class Proto(asyncio.Protocol):
        def connection_made(self, transport):
            self.transp = transport
            self.data = b""

        def data_received(self, data):
            self.data += data
            if data.endswith(b"\r\n\r\n"):
                self.transp.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"CONTENT-LENGTH: 2\r\n"
                    b"CONNECTION: close\r\n"
                    b"\r\n"
                    b"ok"
                )
                self.transp.close()

        def connection_lost(self, exc):
            self.transp = None

    server = await loop.create_server(Proto, "127.0.0.1", unused_port())

    addr = server.sockets[0].getsockname()

    connector = aiohttp.TCPConnector(limit=1)
    session = aiohttp.ClientSession(connector=connector)

    url = "http://{}:{}/".format(*addr)
    for i in range(2):
        r = await session.request("GET", url)
        await r.read()
        assert 0 == len(connector._conns)
    await session.close()
    await connector.close()
    server.close()
    await server.wait_closed()


async def test_handle_keepalive_on_closed_connection() -> None:
    loop = asyncio.get_event_loop()

    class Proto(asyncio.Protocol):
        def connection_made(self, transport):
            self.transp = transport
            self.data = b""

        def data_received(self, data):
            self.data += data
            if data.endswith(b"\r\n\r\n"):
                self.transp.write(b"HTTP/1.1 200 OK\r\nCONTENT-LENGTH: 2\r\n\r\nok")
                self.transp.close()

        def connection_lost(self, exc):
            self.transp = None

    server = await loop.create_server(Proto, "127.0.0.1", unused_port())

    addr = server.sockets[0].getsockname()

    async with aiohttp.TCPConnector(limit=1) as connector:
        async with aiohttp.ClientSession(connector=connector) as session:
            url = "http://{}:{}/".format(*addr)

            r = await session.request("GET", url)
            await r.read()
            assert 1 == len(connector._conns)
            closed_conn = next(iter(connector._conns.values()))

            await session.request("GET", url)
            assert 1 == len(connector._conns)
            new_conn = next(iter(connector._conns.values()))
            assert closed_conn is not new_conn

    server.close()
    await server.wait_closed()


async def test_error_in_performing_request(ssl_ctx, aiohttp_client, aiohttp_server):
    async def handler(request):
        return web.Response()

    def exception_handler(loop, context):
        # skip log messages about destroyed but pending tasks
        pass

    loop = asyncio.get_event_loop()
    loop.set_exception_handler(exception_handler)

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    server = await aiohttp_server(app, ssl=ssl_ctx)

    conn = aiohttp.TCPConnector(limit=1)
    client = await aiohttp_client(server, connector=conn)

    with pytest.raises(aiohttp.ClientConnectionError):
        await client.get("/")

    # second try should not hang
    with pytest.raises(aiohttp.ClientConnectionError):
        await client.get("/")


async def test_await_after_cancelling(aiohttp_client) -> None:
    loop = asyncio.get_event_loop()

    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    client = await aiohttp_client(app)

    fut1 = loop.create_future()
    fut2 = loop.create_future()

    async def fetch1():
        resp = await client.get("/")
        assert resp.status == 200
        fut1.set_result(None)
        with pytest.raises(asyncio.CancelledError):
            await fut2
        resp.release()

    async def fetch2():
        await fut1
        resp = await client.get("/")
        assert resp.status == 200

    async def canceller():
        await fut1
        fut2.cancel()

    await asyncio.gather(fetch1(), fetch2(), canceller())


async def test_async_payload_generator(aiohttp_client) -> None:
    async def handler(request):
        data = await request.read()
        assert data == b"1234567890" * 100
        return web.Response()

    app = web.Application()
    app.add_routes([web.post("/", handler)])

    client = await aiohttp_client(app)

    async def gen():
        for i in range(100):
            yield b"1234567890"

    async with client.post("/", data=gen()) as resp:
        assert resp.status == 200


async def test_read_from_closed_response(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(body=b"data")

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)

    async with client.get("/") as resp:
        assert resp.status == 200

    with pytest.raises(aiohttp.ClientConnectionError):
        await resp.read()


async def test_read_from_closed_response2(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(body=b"data")

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)

    async with client.get("/") as resp:
        assert resp.status == 200
        await resp.read()

    with pytest.raises(aiohttp.ClientConnectionError):
        await resp.read()


async def test_read_after_catch_raise_for_status(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=b"data", status=404)

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)

    async with client.get("/") as resp:
        with pytest.raises(ClientResponseError, match="404"):
            # Should not release response when in async with context.
            resp.raise_for_status()

        result = await resp.read()
        assert result == b"data"


async def test_read_after_raise_outside_context(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=b"data", status=404)

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)

    resp = await client.get("/")
    with pytest.raises(ClientResponseError, match="404"):
        # No async with, so should release and therefore read() will fail.
        resp.raise_for_status()

    with pytest.raises(aiohttp.ClientConnectionError, match=r"^Connection closed$"):
        await resp.read()


async def test_read_from_closed_content(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=b"data")

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)

    async with client.get("/") as resp:
        assert resp.status == 200

    with pytest.raises(aiohttp.ClientConnectionError):
        await resp.content.readline()


async def test_read_timeout(aiohttp_client) -> None:
    async def handler(request):
        await asyncio.sleep(5)
        return web.Response()

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    timeout = aiohttp.ClientTimeout(sock_read=0.1)
    client = await aiohttp_client(app, timeout=timeout)

    with pytest.raises(aiohttp.ServerTimeoutError):
        await client.get("/")


async def test_socket_timeout(aiohttp_client: Any) -> None:
    async def handler(request):
        await asyncio.sleep(5)
        return web.Response()

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    timeout = aiohttp.ClientTimeout(sock_read=0.1)
    client = await aiohttp_client(app, timeout=timeout)

    with pytest.raises(SocketTimeoutError):
        await client.get("/")


async def test_read_timeout_closes_connection(aiohttp_client: AiohttpClient) -> None:
    request_count = 0

    async def handler(request):
        nonlocal request_count
        request_count += 1
        if request_count < 3:
            await asyncio.sleep(0.5)
        return web.Response(body=f"request:{request_count}")

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    timeout = aiohttp.ClientTimeout(total=0.1)
    client: TestClient = await aiohttp_client(app, timeout=timeout)
    with pytest.raises(asyncio.TimeoutError):
        await client.get("/")

    # Make sure its really closed
    assert not client.session.connector._conns

    with pytest.raises(asyncio.TimeoutError):
        await client.get("/")

    # Make sure its really closed
    assert not client.session.connector._conns
    result = await client.get("/")
    assert await result.read() == b"request:3"

    # Make sure its not closed
    assert client.session.connector._conns


async def test_read_timeout_on_prepared_response(aiohttp_client: Any) -> None:
    async def handler(request):
        resp = aiohttp.web.StreamResponse()
        await resp.prepare(request)
        await asyncio.sleep(5)
        await resp.drain()
        return resp

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    timeout = aiohttp.ClientTimeout(sock_read=0.1)
    client = await aiohttp_client(app, timeout=timeout)

    with pytest.raises(aiohttp.ServerTimeoutError):
        async with await client.get("/") as resp:
            await resp.read()


async def test_timeout_with_full_buffer(aiohttp_client) -> None:
    async def handler(request):
        """Server response that never ends and always has more data available."""
        resp = web.StreamResponse()
        await resp.prepare(request)
        while True:
            await resp.write(b"1" * 1000)
            await asyncio.sleep(0.01)

    async def request(client: TestClient[web.Request, web.Application]) -> None:
        timeout = aiohttp.ClientTimeout(total=0.5)
        async with await client.get("/", timeout=timeout) as resp:
            with pytest.raises(asyncio.TimeoutError):
                async for data in resp.content.iter_chunked(1):
                    await asyncio.sleep(0.01)

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)
    # wait_for() used just to ensure that a failing test doesn't hang.
    await asyncio.wait_for(request(client), 1)


async def test_read_bufsize_session_default(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(body=b"1234567")

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app, read_bufsize=2)

    async with await client.get("/") as resp:
        assert resp.content.get_read_buffer_limits() == (2, 4)


async def test_read_bufsize_explicit(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(body=b"1234567")

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)

    async with await client.get("/", read_bufsize=4) as resp:
        assert resp.content.get_read_buffer_limits() == (4, 8)


async def test_http_empty_data_text(aiohttp_client) -> None:
    async def handler(request):
        data = await request.read()
        ret = "ok" if data == b"" else "fail"
        resp = web.Response(text=ret)
        resp.headers["Content-Type"] = request.headers["Content-Type"]
        return resp

    app = web.Application()
    app.add_routes([web.post("/", handler)])

    client = await aiohttp_client(app)

    async with await client.post("/", data="") as resp:
        assert resp.status == 200
        assert await resp.text() == "ok"
        assert resp.headers["Content-Type"] == "text/plain; charset=utf-8"


async def test_max_field_size_session_default(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(headers={"Custom": "x" * 8190})

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)

    async with await client.get("/") as resp:
        assert resp.headers["Custom"] == "x" * 8190


async def test_max_field_size_session_default_fail(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(headers={"Custom": "x" * 8191})

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)
    with pytest.raises(aiohttp.ClientResponseError):
        await client.get("/")


async def test_max_field_size_session_explicit(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(headers={"Custom": "x" * 8191})

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app, max_field_size=8191)

    async with await client.get("/") as resp:
        assert resp.headers["Custom"] == "x" * 8191


async def test_max_field_size_request_explicit(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(headers={"Custom": "x" * 8191})

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)

    async with await client.get("/", max_field_size=8191) as resp:
        assert resp.headers["Custom"] == "x" * 8191


async def test_max_line_size_session_default(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(status=200, reason="x" * 8190)

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)

    async with await client.get("/") as resp:
        assert resp.reason == "x" * 8190


async def test_max_line_size_session_default_fail(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(status=200, reason="x" * 8192)

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)
    with pytest.raises(aiohttp.ClientResponseError):
        await client.get("/")


async def test_max_line_size_session_explicit(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(status=200, reason="x" * 8191)

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app, max_line_size=8191)

    async with await client.get("/") as resp:
        assert resp.reason == "x" * 8191


async def test_max_line_size_request_explicit(aiohttp_client) -> None:
    async def handler(request):
        return web.Response(status=200, reason="x" * 8191)

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)

    async with await client.get("/", max_line_size=8191) as resp:
        assert resp.reason == "x" * 8191


async def test_rejected_upload(
    aiohttp_client: AiohttpClient, tmp_path: pathlib.Path
) -> None:
    async def ok_handler(request: web.Request) -> web.Response:
        return web.Response()

    async def not_ok_handler(request):
        raise web.HTTPBadRequest()

    app = web.Application()
    app.router.add_get("/ok", ok_handler)
    app.router.add_post("/not_ok", not_ok_handler)
    client = await aiohttp_client(app)

    file_size_bytes = 1024 * 1024
    file_path = tmp_path / "uploaded.txt"
    file_path.write_text("0" * file_size_bytes, encoding="utf8")

    with open(file_path, "rb") as file:
        data = {"file": file}
        async with client.post("/not_ok", data=data) as resp_not_ok:
            assert resp_not_ok.status == 400

    async with client.get("/ok", timeout=aiohttp.ClientTimeout(total=1)) as resp_ok:
        assert resp_ok.status == 200


@pytest.mark.parametrize(
    ("value", "exc_type"),
    [(42, TypeError), ("InvalidUrl", InvalidURL)],
)
async def test_request_with_wrong_proxy(
    aiohttp_client: AiohttpClient, value: Any, exc_type: Type[Exception]
) -> None:
    app = web.Application()
    session = await aiohttp_client(app)

    with pytest.raises(exc_type):
        await session.get("/", proxy=value)  # type: ignore[arg-type]


async def test_raise_for_status_is_none(aiohttp_client: AiohttpClient) -> None:
    async def handler(_: web.Request) -> web.Response:
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)
    session = await aiohttp_client(app, raise_for_status=None)  # type: ignore[arg-type]

    await session.get("/")


async def test_exception_when_read_outside_of_session(
    aiohttp_server: AiohttpServer,
) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=b"1" * 1000000)

    app = web.Application()
    app.router.add_get("/", handler)

    server = await aiohttp_server(app)
    async with aiohttp.ClientSession() as sess:
        resp = await sess.get(server.make_url("/"))

    with pytest.raises(RuntimeError, match="Connection closed"):
        await resp.read()


async def test_content_length_limit_enforced(aiohttp_server: AiohttpServer) -> None:
    """Test that Content-Length header value limits the amount of data sent to the server."""
    received_data = bytearray()

    async def handler(request: web.Request) -> web.Response:
        # Read all data from the request and store it
        data = await request.read()
        received_data.extend(data)
        return web.Response(text="OK")

    app = web.Application()
    app.router.add_post("/", handler)

    server = await aiohttp_server(app)

    # Create data larger than what we'll limit with Content-Length
    data = b"X" * 1000
    # Only send 500 bytes even though data is 1000 bytes
    headers = {"Content-Length": "500"}

    async with aiohttp.ClientSession() as session:
        await session.post(server.make_url("/"), data=data, headers=headers)

    # Verify only 500 bytes (not the full 1000) were received by the server
    assert len(received_data) == 500
    assert received_data == b"X" * 500


async def test_content_length_limit_with_multiple_reads(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test that Content-Length header value limits multi read data properly."""
    received_data = bytearray()

    async def handler(request: web.Request) -> web.Response:
        # Read all data from the request and store it
        data = await request.read()
        received_data.extend(data)
        return web.Response(text="OK")

    app = web.Application()
    app.router.add_post("/", handler)

    server = await aiohttp_server(app)

    # Create an async generator of data
    async def data_generator() -> AsyncIterator[bytes]:
        yield b"Chunk1" * 100  # 600 bytes
        yield b"Chunk2" * 100  # another 600 bytes

    # Limit to 800 bytes even though we'd generate 1200 bytes
    headers = {"Content-Length": "800"}

    async with aiohttp.ClientSession() as session:
        async with session.post(
            server.make_url("/"), data=data_generator(), headers=headers
        ) as resp:
            await resp.read()  # Ensure response is fully read and connection cleaned up

    # Verify only 800 bytes (not the full 1200) were received by the server
    assert len(received_data) == 800
    # First chunk fully sent (600 bytes)
    assert received_data.startswith(b"Chunk1" * 100)

    # The rest should be from the second chunk (the exact split might vary by implementation)
    assert b"Chunk2" in received_data  # Some part of the second chunk was sent
    # 200 bytes from the second chunk
    assert len(received_data) - len(b"Chunk1" * 100) == 200


async def test_post_connection_cleanup_with_bytesio(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test that connections are properly cleaned up when using BytesIO data."""

    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=b"")

    app = web.Application()
    app.router.add_post("/hello", handler)
    client = await aiohttp_client(app)

    # Test with direct bytes and BytesIO multiple times to ensure connection cleanup
    for _ in range(10):
        async with client.post(
            "/hello",
            data=b"x",
            headers={"Content-Length": "1"},
        ) as response:
            response.raise_for_status()

        assert client._session.connector is not None
        assert len(client._session.connector._conns) == 1

        x = io.BytesIO(b"x")
        async with client.post(
            "/hello",
            data=x,
            headers={"Content-Length": "1"},
        ) as response:
            response.raise_for_status()

        assert len(client._session.connector._conns) == 1


async def test_post_connection_cleanup_with_file(
    aiohttp_client: AiohttpClient, here: pathlib.Path
) -> None:
    """Test that connections are properly cleaned up when using file data."""

    async def handler(request: web.Request) -> web.Response:
        await request.read()
        return web.Response(body=b"")

    app = web.Application()
    app.router.add_post("/hello", handler)
    client = await aiohttp_client(app)

    test_file = here / "data.unknown_mime_type"

    # Test with direct bytes and file multiple times to ensure connection cleanup
    for _ in range(10):
        async with client.post(
            "/hello",
            data=b"xx",
            headers={"Content-Length": "2"},
        ) as response:
            response.raise_for_status()

        assert client._session.connector is not None
        assert len(client._session.connector._conns) == 1
        fh = await asyncio.get_running_loop().run_in_executor(
            None, open, test_file, "rb"
        )

        async with client.post(
            "/hello",
            data=fh,
            headers={"Content-Length": str(test_file.stat().st_size)},
        ) as response:
            response.raise_for_status()

        assert len(client._session.connector._conns) == 1


async def test_post_content_exception_connection_kept(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test that connections are kept after content.set_exception() with POST."""

    async def handler(request: web.Request) -> web.Response:
        await request.read()
        return web.Response(
            body=b"x" * 1000
        )  # Larger response to ensure it's not pre-buffered

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    # POST request with body - connection should be closed after content exception
    resp = await client.post("/", data=b"request body")

    with pytest.raises(RuntimeError):
        async with resp:
            assert resp.status == 200
            resp.content.set_exception(RuntimeError("Simulated error"))
            await resp.read()

    assert resp.closed

    # Wait for any pending operations to complete
    await resp.wait_for_close()

    assert client._session.connector is not None
    # Connection is kept because content.set_exception() is a client-side operation
    # that doesn't affect the underlying connection state
    assert len(client._session.connector._conns) == 1


async def test_network_error_connection_closed(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test that connections are closed after network errors."""

    async def handler(request: web.Request) -> NoReturn:
        # Read the request body
        await request.read()

        # Start sending response but close connection before completing
        response = web.StreamResponse()
        response.content_length = 1000  # Promise 1000 bytes
        await response.prepare(request)

        # Send partial data then force close the connection
        await response.write(b"x" * 100)  # Only send 100 bytes
        # Force close the transport to simulate network error
        assert request.transport is not None
        request.transport.close()
        assert False, "Will not return"

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    # POST request that will fail due to network error
    with pytest.raises(aiohttp.ClientPayloadError):
        resp = await client.post("/", data=b"request body")
        async with resp:
            await resp.read()  # This should fail

    # Give event loop a chance to process connection cleanup
    await asyncio.sleep(0)

    assert client._session.connector is not None
    # Connection should be closed due to network error
    assert len(client._session.connector._conns) == 0


async def test_client_side_network_error_connection_closed(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test that connections are closed after client-side network errors."""
    handler_done = asyncio.Event()

    async def handler(request: web.Request) -> NoReturn:
        # Read the request body
        await request.read()

        # Start sending a large response
        response = web.StreamResponse()
        response.content_length = 10000  # Promise 10KB
        await response.prepare(request)

        # Send some data
        await response.write(b"x" * 1000)

        # Keep the response open - we'll interrupt from client side
        await asyncio.wait_for(handler_done.wait(), timeout=5.0)
        assert False, "Will not return"

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    # POST request that will fail due to client-side network error
    with pytest.raises(aiohttp.ClientPayloadError):
        resp = await client.post("/", data=b"request body")
        async with resp:
            # Simulate client-side network error by closing the transport
            # This simulates connection reset, network failure, etc.
            assert resp.connection is not None
            assert resp.connection.protocol is not None
            assert resp.connection.protocol.transport is not None
            resp.connection.protocol.transport.close()

            # This should fail with connection error
            await resp.read()

    # Signal handler to finish
    handler_done.set()

    # Give event loop a chance to process connection cleanup
    await asyncio.sleep(0)

    assert client._session.connector is not None
    # Connection should be closed due to client-side network error
    assert len(client._session.connector._conns) == 0


async def test_empty_response_non_chunked(aiohttp_client: AiohttpClient) -> None:
    """Test non-chunked response with empty body."""

    async def handler(request: web.Request) -> web.Response:
        # Return empty response with Content-Length: 0
        return web.Response(body=b"", headers={"Content-Length": "0"})

    app = web.Application()
    app.router.add_get("/empty", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/empty")
    assert resp.status == 200
    assert resp.headers.get("Content-Length") == "0"
    data = await resp.read()
    assert data == b""
    resp.close()


async def test_set_eof_on_empty_response(aiohttp_client: AiohttpClient) -> None:
    """Test that triggers set_eof() method."""

    async def handler(request: web.Request) -> web.Response:
        # Return response that completes immediately
        return web.Response(status=204)  # No Content

    app = web.Application()
    app.router.add_get("/no-content", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/no-content")
    assert resp.status == 204
    data = await resp.read()
    assert data == b""
    resp.close()


async def test_bytes_payload_redirect(aiohttp_client: AiohttpClient) -> None:
    """Test that BytesPayload can be reused across redirects."""
    data_received = []

    async def redirect_handler(request: web.Request) -> web.Response:
        data = await request.read()
        data_received.append(("redirect", data))
        # Use 307 to preserve POST method
        raise web.HTTPTemporaryRedirect("/final_destination")

    async def final_handler(request: web.Request) -> web.Response:
        data = await request.read()
        data_received.append(("final", data))
        return web.Response(text=f"Received: {data.decode()}")

    app = web.Application()
    app.router.add_post("/redirect", redirect_handler)
    app.router.add_post("/final_destination", final_handler)

    client = await aiohttp_client(app)

    payload_data = b"test payload data"
    payload = BytesPayload(payload_data)

    resp = await client.post("/redirect", data=payload)
    assert resp.status == 200
    text = await resp.text()
    assert text == "Received: test payload data"
    # Both endpoints should have received the data
    assert data_received == [("redirect", payload_data), ("final", payload_data)]


async def test_string_payload_redirect(aiohttp_client: AiohttpClient) -> None:
    """Test that StringPayload can be reused across redirects."""
    data_received = []

    async def redirect_handler(request: web.Request) -> web.Response:
        data = await request.text()
        data_received.append(("redirect", data))
        # Use 307 to preserve POST method
        raise web.HTTPTemporaryRedirect("/final_destination")

    async def final_handler(request: web.Request) -> web.Response:
        data = await request.text()
        data_received.append(("final", data))
        return web.Response(text=f"Received: {data}")

    app = web.Application()
    app.router.add_post("/redirect", redirect_handler)
    app.router.add_post("/final_destination", final_handler)

    client = await aiohttp_client(app)

    payload_data = "test string payload"
    payload = StringPayload(payload_data)

    resp = await client.post("/redirect", data=payload)
    assert resp.status == 200
    text = await resp.text()
    assert text == "Received: test string payload"
    # Both endpoints should have received the data
    assert data_received == [("redirect", payload_data), ("final", payload_data)]


async def test_async_iterable_payload_redirect(aiohttp_client: AiohttpClient) -> None:
    """Test that AsyncIterablePayload cannot be reused across redirects."""
    data_received = []

    async def redirect_handler(request: web.Request) -> web.Response:
        data = await request.read()
        data_received.append(("redirect", data))
        # Use 307 to preserve POST method
        raise web.HTTPTemporaryRedirect("/final_destination")

    async def final_handler(request: web.Request) -> web.Response:
        data = await request.read()
        data_received.append(("final", data))
        return web.Response(text=f"Received: {data.decode()}")

    app = web.Application()
    app.router.add_post("/redirect", redirect_handler)
    app.router.add_post("/final_destination", final_handler)

    client = await aiohttp_client(app)

    chunks = [b"chunk1", b"chunk2", b"chunk3"]

    async def async_gen() -> AsyncIterator[bytes]:
        for chunk in chunks:
            yield chunk

    payload = AsyncIterablePayload(async_gen())

    resp = await client.post("/redirect", data=payload)
    assert resp.status == 200
    text = await resp.text()
    # AsyncIterablePayload is consumed after first use, so redirect gets empty body
    assert text == "Received: "

    # Only the first endpoint should have received data
    expected_data = b"".join(chunks)
    assert len(data_received) == 2
    assert data_received[0] == ("redirect", expected_data)
    assert data_received[1] == ("final", b"")  # Empty after being consumed


async def test_buffered_reader_payload_redirect(aiohttp_client: AiohttpClient) -> None:
    """Test that BufferedReaderPayload can be reused across redirects."""
    data_received = []

    async def redirect_handler(request: web.Request) -> web.Response:
        data = await request.read()
        data_received.append(("redirect", data))
        # Use 307 to preserve POST method
        raise web.HTTPTemporaryRedirect("/final_destination")

    async def final_handler(request: web.Request) -> web.Response:
        data = await request.read()
        data_received.append(("final", data))
        return web.Response(text=f"Received: {data.decode()}")

    app = web.Application()
    app.router.add_post("/redirect", redirect_handler)
    app.router.add_post("/final_destination", final_handler)

    client = await aiohttp_client(app)

    payload_data = b"buffered reader payload"
    buffer = io.BufferedReader(io.BytesIO(payload_data))  # type: ignore[arg-type]
    payload = BufferedReaderPayload(buffer)

    resp = await client.post("/redirect", data=payload)
    assert resp.status == 200
    text = await resp.text()
    assert text == "Received: buffered reader payload"
    # Both endpoints should have received the data
    assert data_received == [("redirect", payload_data), ("final", payload_data)]


async def test_string_io_payload_redirect(aiohttp_client: AiohttpClient) -> None:
    """Test that StringIOPayload can be reused across redirects."""
    data_received = []

    async def redirect_handler(request: web.Request) -> web.Response:
        data = await request.text()
        data_received.append(("redirect", data))
        # Use 307 to preserve POST method
        raise web.HTTPTemporaryRedirect("/final_destination")

    async def final_handler(request: web.Request) -> web.Response:
        data = await request.text()
        data_received.append(("final", data))
        return web.Response(text=f"Received: {data}")

    app = web.Application()
    app.router.add_post("/redirect", redirect_handler)
    app.router.add_post("/final_destination", final_handler)

    client = await aiohttp_client(app)

    payload_data = "string io payload"
    string_io = io.StringIO(payload_data)
    payload = StringIOPayload(string_io)

    resp = await client.post("/redirect", data=payload)
    assert resp.status == 200
    text = await resp.text()
    assert text == "Received: string io payload"
    # Both endpoints should have received the data
    assert data_received == [("redirect", payload_data), ("final", payload_data)]


async def test_bytes_io_payload_redirect(aiohttp_client: AiohttpClient) -> None:
    """Test that BytesIOPayload can be reused across redirects."""
    data_received = []

    async def redirect_handler(request: web.Request) -> web.Response:
        data = await request.read()
        data_received.append(("redirect", data))
        # Use 307 to preserve POST method
        raise web.HTTPTemporaryRedirect("/final_destination")

    async def final_handler(request: web.Request) -> web.Response:
        data = await request.read()
        data_received.append(("final", data))
        return web.Response(text=f"Received: {data.decode()}")

    app = web.Application()
    app.router.add_post("/redirect", redirect_handler)
    app.router.add_post("/final_destination", final_handler)

    client = await aiohttp_client(app)

    payload_data = b"bytes io payload"
    bytes_io = io.BytesIO(payload_data)
    payload = BytesIOPayload(bytes_io)

    resp = await client.post("/redirect", data=payload)
    assert resp.status == 200
    text = await resp.text()
    assert text == "Received: bytes io payload"
    # Both endpoints should have received the data
    assert data_received == [("redirect", payload_data), ("final", payload_data)]


async def test_multiple_redirects_with_bytes_payload(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test BytesPayload with multiple redirects."""
    data_received = []

    async def redirect1_handler(request: web.Request) -> web.Response:
        data = await request.read()
        data_received.append(("redirect1", data))
        # Use 307 to preserve POST method
        raise web.HTTPTemporaryRedirect("/redirect2")

    async def redirect2_handler(request: web.Request) -> web.Response:
        data = await request.read()
        data_received.append(("redirect2", data))
        # Use 307 to preserve POST method
        raise web.HTTPTemporaryRedirect("/final_destination")

    async def final_handler(request: web.Request) -> web.Response:
        data = await request.read()
        data_received.append(("final", data))
        return web.Response(text=f"Received after 2 redirects: {data.decode()}")

    app = web.Application()
    app.router.add_post("/redirect", redirect1_handler)
    app.router.add_post("/redirect2", redirect2_handler)
    app.router.add_post("/final_destination", final_handler)

    client = await aiohttp_client(app)

    payload_data = b"multi-redirect-test"
    payload = BytesPayload(payload_data)

    resp = await client.post("/redirect", data=payload)
    assert resp.status == 200
    text = await resp.text()
    assert text == f"Received after 2 redirects: {payload_data.decode()}"
    # All 3 endpoints should have received the same data
    assert data_received == [
        ("redirect1", payload_data),
        ("redirect2", payload_data),
        ("final", payload_data),
    ]


async def test_redirect_with_empty_payload(aiohttp_client: AiohttpClient) -> None:
    """Test redirects with empty payloads."""
    data_received = []

    async def redirect_handler(request: web.Request) -> web.Response:
        data = await request.read()
        data_received.append(("redirect", data))
        # Use 307 to preserve POST method
        raise web.HTTPTemporaryRedirect("/final_destination")

    async def final_handler(request: web.Request) -> web.Response:
        data = await request.read()
        data_received.append(("final", data))
        return web.Response(text="Done")

    app = web.Application()
    app.router.add_post("/redirect", redirect_handler)
    app.router.add_post("/final_destination", final_handler)

    client = await aiohttp_client(app)

    # Test with empty BytesPayload
    payload = BytesPayload(b"")
    resp = await client.post("/redirect", data=payload)
    assert resp.status == 200
    assert data_received == [("redirect", b""), ("final", b"")]


async def test_redirect_preserves_content_type(aiohttp_client: AiohttpClient) -> None:
    """Test that content-type is preserved across redirects."""
    content_types = []

    async def redirect_handler(request: web.Request) -> web.Response:
        content_types.append(("redirect", request.content_type))
        # Use 307 to preserve POST method
        raise web.HTTPTemporaryRedirect("/final_destination")

    async def final_handler(request: web.Request) -> web.Response:
        content_types.append(("final", request.content_type))
        return web.Response(text="Done")

    app = web.Application()
    app.router.add_post("/redirect", redirect_handler)
    app.router.add_post("/final_destination", final_handler)

    client = await aiohttp_client(app)

    # StringPayload should set content-type with charset
    payload = StringPayload("test data")
    resp = await client.post("/redirect", data=payload)
    assert resp.status == 200
    # Both requests should have the same content type
    assert len(content_types) == 2
    assert content_types[0][1] == "text/plain"
    assert content_types[1][1] == "text/plain"


class MockedBytesPayload(BytesPayload):
    """A BytesPayload that tracks whether close() was called."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.close_called = False

    async def close(self) -> None:
        self.close_called = True
        await super().close()


async def test_too_many_redirects_closes_payload(aiohttp_client: AiohttpClient) -> None:
    """Test that TooManyRedirects exception closes the request payload."""

    async def redirect_handler(request: web.Request) -> web.Response:
        # Read the payload to simulate server processing
        await request.read()
        count = int(request.match_info.get("count", 0))
        # Use 307 to preserve POST method
        return web.Response(
            status=307, headers={hdrs.LOCATION: f"/redirect/{count + 1}"}
        )

    app = web.Application()
    app.router.add_post(r"/redirect/{count:\d+}", redirect_handler)

    client = await aiohttp_client(app)

    # Create a mocked payload to verify close() is called
    payload = MockedBytesPayload(b"test payload")

    with pytest.raises(TooManyRedirects):
        await client.post("/redirect/0", data=payload, max_redirects=2)

    assert (
        payload.close_called
    ), "Payload.close() was not called when TooManyRedirects was raised"


async def test_invalid_url_redirect_closes_payload(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test that InvalidUrlRedirectClientError exception closes the request payload."""

    async def redirect_handler(request: web.Request) -> web.Response:
        # Read the payload to simulate server processing
        await request.read()
        # Return an invalid URL that will cause ValueError in URL parsing
        # Using a URL with invalid port that's out of range
        return web.Response(
            status=307, headers={hdrs.LOCATION: "http://example.com:999999/path"}
        )

    app = web.Application()
    app.router.add_post("/redirect", redirect_handler)

    client = await aiohttp_client(app)

    # Create a mocked payload to verify close() is called
    payload = MockedBytesPayload(b"test payload")

    with pytest.raises(
        InvalidUrlRedirectClientError,
        match="Server attempted redirecting to a location that does not look like a URL",
    ):
        await client.post("/redirect", data=payload)

    assert (
        payload.close_called
    ), "Payload.close() was not called when InvalidUrlRedirectClientError was raised"


async def test_non_http_redirect_closes_payload(aiohttp_client: AiohttpClient) -> None:
    """Test that NonHttpUrlRedirectClientError exception closes the request payload."""

    async def redirect_handler(request: web.Request) -> web.Response:
        # Read the payload to simulate server processing
        await request.read()
        # Return a non-HTTP scheme URL
        return web.Response(
            status=307, headers={hdrs.LOCATION: "ftp://example.com/file"}
        )

    app = web.Application()
    app.router.add_post("/redirect", redirect_handler)

    client = await aiohttp_client(app)

    # Create a mocked payload to verify close() is called
    payload = MockedBytesPayload(b"test payload")

    with pytest.raises(NonHttpUrlRedirectClientError):
        await client.post("/redirect", data=payload)

    assert (
        payload.close_called
    ), "Payload.close() was not called when NonHttpUrlRedirectClientError was raised"


async def test_invalid_redirect_origin_closes_payload(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test that InvalidUrlRedirectClientError exception (invalid origin) closes the request payload."""

    async def redirect_handler(request: web.Request) -> web.Response:
        # Read the payload to simulate server processing
        await request.read()
        # Return a URL that will fail origin() check - using a relative URL without host
        return web.Response(status=307, headers={hdrs.LOCATION: "http:///path"})

    app = web.Application()
    app.router.add_post("/redirect", redirect_handler)

    client = await aiohttp_client(app)

    # Create a mocked payload to verify close() is called
    payload = MockedBytesPayload(b"test payload")

    with pytest.raises(
        InvalidUrlRedirectClientError, match="Invalid redirect URL origin"
    ):
        await client.post("/redirect", data=payload)

    assert (
        payload.close_called
    ), "Payload.close() was not called when InvalidUrlRedirectClientError (invalid origin) was raised"


async def test_amazon_like_cookie_scenario(aiohttp_client: AiohttpClient) -> None:
    """Test real-world cookie scenario similar to Amazon."""

    class FakeResolver(AbstractResolver):
        def __init__(self, port: int):
            self._port = port

        async def resolve(
            self, host: str, port: int = 0, family: int = 0
        ) -> List[ResolveResult]:
            if host in ("amazon.it", "www.amazon.it"):
                return [
                    {
                        "hostname": host,
                        "host": "127.0.0.1",
                        "port": self._port,
                        "family": socket.AF_INET,
                        "proto": 0,
                        "flags": 0,
                    }
                ]
            assert False, f"Unexpected host: {host}"

        async def close(self) -> None:
            """Close the resolver if needed."""

    async def handler(request: web.Request) -> web.Response:
        response = web.Response(text="Login successful")

        # Simulate Amazon-like cookies from the issue
        cookies = [
            "session-id=146-7423990-7621939; Domain=.amazon.it; "
            "Expires=Mon, 31-May-2027 10:00:00 GMT; Path=/; "
            "Secure; HttpOnly",
            "session-id=147-8529641-8642103; Domain=.www.amazon.it; "
            "Expires=Mon, 31-May-2027 10:00:00 GMT; Path=/; HttpOnly",
            "session-id-time=2082758401l; Domain=.amazon.it; "
            "Expires=Mon, 31-May-2027 10:00:00 GMT; Path=/; Secure",
            "session-id-time=2082758402l; Domain=.www.amazon.it; "
            "Expires=Mon, 31-May-2027 10:00:00 GMT; Path=/",
            "ubid-acbit=257-7531983-5395266; Domain=.amazon.it; "
            "Expires=Mon, 31-May-2027 10:00:00 GMT; Path=/; Secure",
            'x-acbit="KdvJzu8W@Fx6Jj3EuNFLuP0N7OtkuCfs"; Version=1; '
            "Domain=.amazon.it; Path=/; Secure; HttpOnly",
            "at-acbit=Atza|IwEBIM-gLr8; Domain=.amazon.it; "
            "Expires=Mon, 31-May-2027 10:00:00 GMT; Path=/; "
            "Secure; HttpOnly",
            'sess-at-acbit="4+6VzSJPHIFD/OqO264hFxIng8Y="; '
            "Domain=.amazon.it; Expires=Mon, 31-May-2027 10:00:00 GMT; "
            "Path=/; Secure; HttpOnly",
            "lc-acbit=it_IT; Domain=.amazon.it; "
            "Expires=Mon, 31-May-2027 10:00:00 GMT; Path=/",
            "i18n-prefs=EUR; Domain=.amazon.it; "
            "Expires=Mon, 31-May-2027 10:00:00 GMT; Path=/",
            "av-profile=null; Domain=.amazon.it; "
            "Expires=Mon, 31-May-2027 10:00:00 GMT; Path=/; Secure",
            'user-pref-token="Am81ywsJ69xObBnuJ2FbilVH0mg="; '
            "Domain=.amazon.it; Path=/; Secure",
        ]

        for cookie in cookies:
            response.headers.add("Set-Cookie", cookie)

        return response

    app = web.Application()
    app.router.add_get("/", handler)

    # Get the test server
    server = await aiohttp_client(app)
    port = server.port

    # Create a new client session with our fake resolver
    resolver = FakeResolver(port)

    async with (
        aiohttp.TCPConnector(resolver=resolver, force_close=True) as connector,
        aiohttp.ClientSession(connector=connector) as session,
    ):
        # Make request to www.amazon.it which will resolve to
        # 127.0.0.1:port. This allows cookies for both .amazon.it
        # and .www.amazon.it domains
        resp = await session.get(f"http://www.amazon.it:{port}/")

        # Check headers
        cookie_headers = resp.headers.getall("Set-Cookie")
        assert (
            len(cookie_headers) == 12
        ), f"Expected 12 headers, got {len(cookie_headers)}"

        # Check parsed cookies - SimpleCookie only keeps the last
        # cookie with each name. So we expect 10 unique cookie names
        # (not 12)
        expected_cookie_names = {
            "session-id",  # Will only have one
            "session-id-time",  # Will only have one
            "ubid-acbit",
            "x-acbit",
            "at-acbit",
            "sess-at-acbit",
            "lc-acbit",
            "i18n-prefs",
            "av-profile",
            "user-pref-token",
        }
        assert set(resp.cookies.keys()) == expected_cookie_names
        assert (
            len(resp.cookies) == 10
        ), f"Expected 10 cookies in SimpleCookie, got {len(resp.cookies)}"

        # The important part: verify the session's cookie jar has
        # all cookies. The cookie jar should have all 12 cookies,
        # not just 10
        jar_cookies = list(session.cookie_jar)
        assert (
            len(jar_cookies) == 12
        ), f"Expected 12 cookies in jar, got {len(jar_cookies)}"

        # Verify we have both session-id cookies with different domains
        session_ids = [c for c in jar_cookies if c.key == "session-id"]
        assert (
            len(session_ids) == 2
        ), f"Expected 2 session-id cookies, got {len(session_ids)}"

        # Verify the domains are different
        session_id_domains = {c["domain"] for c in session_ids}
        assert session_id_domains == {
            "amazon.it",
            "www.amazon.it",
        }, f"Got domains: {session_id_domains}"

        # Verify we have both session-id-time cookies with different
        # domains
        session_id_times = [c for c in jar_cookies if c.key == "session-id-time"]
        assert (
            len(session_id_times) == 2
        ), f"Expected 2 session-id-time cookies, got {len(session_id_times)}"

        # Now test that the raw headers were properly preserved
        assert resp._raw_cookie_headers is not None
        assert (
            len(resp._raw_cookie_headers) == 12
        ), "All raw headers should be preserved"
