# HTTP client functional tests against aiohttp.web server

import asyncio
import datetime
import http.cookies
import io
import json
import pathlib
import socket
import ssl
import sys
import tarfile
import time
import zipfile
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    List,
    NoReturn,
    Optional,
    Type,
    Union,
)
from unittest import mock

import pytest
import trustme
from multidict import MultiDict
from pytest_mock import MockerFixture
from yarl import URL

import aiohttp
from aiohttp import Fingerprint, ServerFingerprintMismatch, hdrs, web
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
from aiohttp.pytest_plugin import AiohttpClient, AiohttpServer
from aiohttp.test_utils import TestClient, TestServer, unused_port
from aiohttp.typedefs import Handler


@pytest.fixture
def here() -> pathlib.Path:
    return pathlib.Path(__file__).parent


@pytest.fixture
def fname(here: pathlib.Path) -> pathlib.Path:
    return here / "conftest.py"


async def test_keepalive_two_requests_success(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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

    assert client._session.connector is not None
    assert 1 == len(client._session.connector._conns)


async def test_keepalive_after_head_requests_success(
    aiohttp_client: AiohttpClient,
) -> None:
    async def handler(request: web.Request) -> web.Response:
        body = await request.read()
        assert b"" == body
        return web.Response(body=b"OK")

    cnt_conn_reuse = 0

    async def on_reuseconn(session: object, ctx: object, params: object) -> None:
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
    aiohttp_client: AiohttpClient, status: int
) -> None:
    async def handler(request: web.Request) -> web.Response:
        body = await request.read()
        assert b"" == body
        return web.Response(status=status)

    cnt_conn_reuse = 0

    async def on_reuseconn(session: object, ctx: object, params: object) -> None:
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
    aiohttp_client: AiohttpClient, status: int
) -> None:
    async def handler(request: web.Request) -> web.StreamResponse:
        stream_response = web.StreamResponse(status=status)
        await stream_response.prepare(request)
        return stream_response

    cnt_conn_reuse = 0

    async def on_reuseconn(session: object, ctx: object, params: object) -> None:
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


async def test_keepalive_response_released(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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

    assert client._session.connector is not None
    assert 1 == len(client._session.connector._conns)


async def test_upgrade_connection_not_released_after_read(
    aiohttp_client: AiohttpClient,
) -> None:
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


async def test_keepalive_server_force_close_connection(
    aiohttp_client: AiohttpClient,
) -> None:
    async def handler(request: web.Request) -> web.Response:
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

    assert client._session.connector is not None
    assert 0 == len(client._session.connector._conns)


async def test_keepalive_timeout_async_sleep() -> None:
    async def handler(request: web.Request) -> web.Response:
        body = await request.read()
        assert b"" == body
        return web.Response(body=b"OK")

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    runner = web.AppRunner(app, tcp_keepalive=True, keepalive_timeout=0.001)
    await runner.setup()

    port = unused_port()
    site = web.TCPSite(runner, host="localhost", port=port)
    await site.start()

    try:
        async with aiohttp.ClientSession() as sess:
            resp1 = await sess.get(f"http://localhost:{port}/")
            await resp1.read()
            # wait for server keepalive_timeout
            await asyncio.sleep(0.01)
            resp2 = await sess.get(f"http://localhost:{port}/")
            await resp2.read()
    finally:
        await asyncio.gather(runner.shutdown(), site.stop())


@pytest.mark.skipif(
    sys.version_info[:2] == (3, 11),
    reason="https://github.com/pytest-dev/pytest/issues/10763",
)
async def test_keepalive_timeout_sync_sleep() -> None:
    async def handler(request: web.Request) -> web.Response:
        body = await request.read()
        assert b"" == body
        return web.Response(body=b"OK")

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    runner = web.AppRunner(app, tcp_keepalive=True, keepalive_timeout=0.001)
    await runner.setup()

    port = unused_port()
    site = web.TCPSite(runner, host="localhost", port=port)
    await site.start()

    try:
        async with aiohttp.ClientSession() as sess:
            resp1 = await sess.get(f"http://localhost:{port}/")
            await resp1.read()
            # wait for server keepalive_timeout
            # time.sleep is a more challenging scenario than asyncio.sleep
            time.sleep(0.01)
            resp2 = await sess.get(f"http://localhost:{port}/")
            await resp2.read()
    finally:
        await asyncio.gather(runner.shutdown(), site.stop())


async def test_release_early(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        await request.read()
        return web.Response(body=b"OK")

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    client = await aiohttp_client(app)
    resp = await client.get("/")
    assert resp.closed
    await resp.wait_for_close()
    assert client._session.connector is not None
    assert 1 == len(client._session.connector._conns)


async def test_HTTP_304(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_stream_request_on_server_eof(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(text="OK", status=200)

    app = web.Application()
    app.add_routes([web.get("/", handler)])
    app.add_routes([web.put("/", handler)])

    client = await aiohttp_client(app)

    async def data_gen() -> AsyncIterator[bytes]:
        for _ in range(2):
            yield b"just data"
            await asyncio.sleep(0.1)

    assert client.session.connector is not None
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


async def test_stream_request_on_server_eof_nested(
    aiohttp_client: AiohttpClient,
) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(text="OK", status=200)

    app = web.Application()
    app.add_routes([web.get("/", handler)])
    app.add_routes([web.put("/", handler)])

    client = await aiohttp_client(app)

    async def data_gen() -> AsyncIterator[bytes]:
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


async def test_HTTP_304_WITH_BODY(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_auto_header_user_agent(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        assert "aiohttp" in request.headers["user-agent"]
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    async with client.get("/") as resp:
        assert 200 == resp.status


async def test_skip_auto_headers_user_agent(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        assert hdrs.USER_AGENT not in request.headers
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    async with client.get("/", skip_auto_headers=["user-agent"]) as resp:
        assert 200 == resp.status


async def test_skip_default_auto_headers_user_agent(
    aiohttp_client: AiohttpClient,
) -> None:
    async def handler(request: web.Request) -> web.Response:
        assert hdrs.USER_AGENT not in request.headers
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app, skip_auto_headers=["user-agent"])

    async with client.get("/") as resp:
        assert 200 == resp.status


async def test_skip_auto_headers_content_type(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        assert hdrs.CONTENT_TYPE not in request.headers
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    async with client.get("/", skip_auto_headers=["content-type"]) as resp:
        assert 200 == resp.status


async def test_post_data_bytesio(aiohttp_client: AiohttpClient) -> None:
    data = b"some buffer"

    async def handler(request: web.Request) -> web.Response:
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


async def test_post_data_with_bytesio_file(aiohttp_client: AiohttpClient) -> None:
    data = b"some buffer"

    async def handler(request: web.Request) -> web.Response:
        post_data = await request.post()
        assert ["file"] == list(post_data.keys())
        file_field = post_data["file"]
        assert isinstance(file_field, web.FileField)
        assert data == file_field.file.read()
        return web.Response()

    app = web.Application()
    app.router.add_route("POST", "/", handler)
    client = await aiohttp_client(app)

    with io.BytesIO(data) as file_handle:
        async with client.post("/", data={"file": file_handle}) as resp:
            assert 200 == resp.status


async def test_post_data_stringio(aiohttp_client: AiohttpClient) -> None:
    data = "some buffer"

    async def handler(request: web.Request) -> web.Response:
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


async def test_post_data_textio_encoding(aiohttp_client: AiohttpClient) -> None:
    data = "текст"

    async def handler(request: web.Request) -> web.Response:
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


async def test_ssl_client(
    aiohttp_server: AiohttpServer,
    ssl_ctx: ssl.SSLContext,
    aiohttp_client: AiohttpClient,
    client_ssl_ctx: ssl.SSLContext,
) -> None:
    connector = aiohttp.TCPConnector(ssl=client_ssl_ctx)

    async def handler(request: web.Request) -> web.Response:
        return web.Response(text="Test message")

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    server = await aiohttp_server(app, ssl=ssl_ctx)
    client = await aiohttp_client(server, connector=connector)

    resp = await client.get("/")
    assert 200 == resp.status
    txt = await resp.text()
    assert txt == "Test message"


async def test_tcp_connector_fingerprint_ok(
    aiohttp_server: AiohttpServer,
    aiohttp_client: AiohttpClient,
    ssl_ctx: ssl.SSLContext,
    tls_certificate_fingerprint_sha256: bytes,
) -> None:
    tls_fingerprint = Fingerprint(tls_certificate_fingerprint_sha256)

    async def handler(request: web.Request) -> web.Response:
        return web.Response(text="Test message")

    connector = aiohttp.TCPConnector(ssl=tls_fingerprint)
    app = web.Application()
    app.router.add_route("GET", "/", handler)
    server = await aiohttp_server(app, ssl=ssl_ctx)
    client = await aiohttp_client(server, connector=connector)

    async with client.get("/") as resp:
        assert resp.status == 200


async def test_tcp_connector_fingerprint_fail(
    aiohttp_server: AiohttpServer,
    aiohttp_client: AiohttpClient,
    ssl_ctx: ssl.SSLContext,
    tls_certificate_fingerprint_sha256: bytes,
) -> None:
    async def handler(request: web.Request) -> NoReturn:
        assert False

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


async def test_format_task_get(aiohttp_server: AiohttpServer) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_str_params(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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

    async def handler_ok(request: web.Request) -> web.Response:
        assert request.rel_url.query_string == "a=redirect"
        return web.Response(status=200)

    app = web.Application()
    app.router.add_route("GET", "/ok", handler_ok)
    app.router.add_route("GET", "/redirect", handler_redirect)
    client = await aiohttp_client(app)

    async with client.get("/redirect", params={"a": "initial"}) as resp:
        assert resp.status == 200


async def test_drop_fragment_on_redirect(aiohttp_client: AiohttpClient) -> None:
    async def handler_redirect(request: web.Request) -> web.Response:
        return web.Response(status=301, headers={"Location": "/ok#fragment"})

    async def handler_ok(request: web.Request) -> web.Response:
        return web.Response(status=200)

    app = web.Application()
    app.router.add_route("GET", "/ok", handler_ok)
    app.router.add_route("GET", "/redirect", handler_redirect)
    client = await aiohttp_client(app)

    async with client.get("/redirect") as resp:
        assert resp.status == 200
        assert resp.url.path == "/ok"


async def test_drop_fragment(aiohttp_client: AiohttpClient) -> None:
    async def handler_ok(request: web.Request) -> web.Response:
        return web.Response(status=200)

    app = web.Application()
    app.router.add_route("GET", "/ok", handler_ok)
    client = await aiohttp_client(app)

    async with client.get("/ok#fragment") as resp:
        assert resp.status == 200
        assert resp.url.path == "/ok"


async def test_history(aiohttp_client: AiohttpClient) -> None:
    async def handler_redirect(request: web.Request) -> web.Response:
        return web.Response(status=301, headers={"Location": "/ok"})

    async def handler_ok(request: web.Request) -> web.Response:
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


async def test_keepalive_closed_by_server(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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

    assert client._session.connector is not None
    assert 0 == len(client._session.connector._conns)


async def test_wait_for(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=b"OK")

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    resp = await asyncio.wait_for(client.get("/"), 10)
    assert resp.status == 200
    txt = await resp.text()
    assert txt == "OK"


async def test_raw_headers(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_host_header_first(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        assert list(request.headers)[0] == hdrs.HOST
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    async with client.get("/") as resp:
        assert resp.status == 200


async def test_empty_header_values(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_204_with_gzipped_content_encoding(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.StreamResponse:
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


async def test_timeout_on_reading_headers(
    aiohttp_client: AiohttpClient, mocker: MockerFixture
) -> None:
    async def handler(request: web.Request) -> NoReturn:
        await asyncio.sleep(0.1)
        assert False

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    with pytest.raises(asyncio.TimeoutError):
        await client.get("/", timeout=aiohttp.ClientTimeout(total=0.01))


async def test_timeout_on_conn_reading_headers(
    aiohttp_client: AiohttpClient, mocker: MockerFixture
) -> None:
    # tests case where user did not set a connection timeout

    async def handler(request: web.Request) -> NoReturn:
        await asyncio.sleep(0.1)
        assert False

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    conn = aiohttp.TCPConnector()
    client = await aiohttp_client(app, connector=conn)

    with pytest.raises(asyncio.TimeoutError):
        await client.get("/", timeout=aiohttp.ClientTimeout(total=0.01))


async def test_timeout_on_session_read_timeout(
    aiohttp_client: AiohttpClient, mocker: MockerFixture
) -> None:
    async def handler(request: web.Request) -> NoReturn:
        await asyncio.sleep(0.1)
        assert False

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    conn = aiohttp.TCPConnector()
    client = await aiohttp_client(
        app, connector=conn, timeout=aiohttp.ClientTimeout(sock_read=0.01)
    )

    with pytest.raises(asyncio.TimeoutError):
        await client.get("/")


async def test_read_timeout_between_chunks(
    aiohttp_client: AiohttpClient, mocker: MockerFixture
) -> None:
    async def handler(request: web.Request) -> web.StreamResponse:
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


async def test_read_timeout_on_reading_chunks(
    aiohttp_client: AiohttpClient, mocker: MockerFixture
) -> None:
    async def handler(request: web.Request) -> NoReturn:
        resp = aiohttp.web.StreamResponse()
        await resp.prepare(request)
        await resp.write(b"data\n")
        await asyncio.sleep(1)
        assert False

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    # A timeout of 0.2 seconds should apply per read.
    timeout = aiohttp.ClientTimeout(sock_read=0.2)
    client = await aiohttp_client(app, timeout=timeout)

    async with await client.get("/") as resp:
        assert (await resp.content.read(5)) == b"data\n"
        with pytest.raises(asyncio.TimeoutError):
            await resp.content.read()


async def test_read_timeout_on_write(aiohttp_client: AiohttpClient) -> None:
    async def gen_payload() -> AsyncIterator[bytes]:
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


async def test_timeout_on_reading_data(
    aiohttp_client: AiohttpClient, mocker: MockerFixture
) -> None:
    loop = asyncio.get_event_loop()

    fut = loop.create_future()

    async def handler(request: web.Request) -> web.StreamResponse:
        resp = web.StreamResponse(headers={"content-length": "100"})
        await resp.prepare(request)
        fut.set_result(None)
        await asyncio.sleep(0.2)
        return resp

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/", timeout=aiohttp.ClientTimeout(1))
    await fut

    with pytest.raises(asyncio.TimeoutError):
        await resp.read()


async def test_timeout_none(
    aiohttp_client: AiohttpClient, mocker: MockerFixture
) -> None:
    async def handler(request: web.Request) -> web.StreamResponse:
        resp = web.StreamResponse()
        await resp.prepare(request)
        return resp

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    async with client.get("/", timeout=None) as resp:
        assert resp.status == 200


async def test_readline_error_on_conn_close(aiohttp_client: AiohttpClient) -> None:
    loop = asyncio.get_event_loop()

    async def handler(request: web.Request) -> NoReturn:
        resp = web.StreamResponse()
        await resp.prepare(request)

        # make sure connection is closed by client.
        with pytest.raises(aiohttp.ServerDisconnectedError):
            for _ in range(10):
                await resp.write(b"data\n")
                await asyncio.sleep(0.5)
        assert False

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
                assert data
                assert data == b"data"
                if not timer_started:
                    loop.call_later(1.0, resp.release)
                    timer_started = True
    finally:
        await session.close()


async def test_no_error_on_conn_close_if_eof(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.StreamResponse:
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


async def test_error_not_overwrote_on_conn_close(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.StreamResponse:
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


async def test_HTTP_200_OK_METHOD(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_HTTP_200_OK_METHOD_connector(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_HTTP_302_REDIRECT_GET(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(text=request.method)

    async def redirect(request: web.Request) -> NoReturn:
        raise web.HTTPFound(location="/")

    app = web.Application()
    app.router.add_get("/", handler)
    app.router.add_get("/redirect", redirect)
    client = await aiohttp_client(app)

    async with client.get("/redirect") as resp:
        assert 200 == resp.status
        assert 1 == len(resp.history)


async def test_HTTP_302_REDIRECT_HEAD(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(text=request.method)

    async def redirect(request: web.Request) -> NoReturn:
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


async def test_HTTP_302_REDIRECT_NON_HTTP(aiohttp_client: AiohttpClient) -> None:
    async def redirect(request: web.Request) -> NoReturn:
        raise web.HTTPFound(location="ftp://127.0.0.1/test/")

    app = web.Application()
    app.router.add_get("/redirect", redirect)
    client = await aiohttp_client(app)

    with pytest.raises(NonHttpUrlRedirectClientError):
        await client.get("/redirect")


async def test_HTTP_302_REDIRECT_POST(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(text=request.method)

    async def redirect(request: web.Request) -> NoReturn:
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


async def test_HTTP_302_REDIRECT_POST_with_content_length_hdr(
    aiohttp_client: AiohttpClient,
) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(text=request.method)

    async def redirect(request: web.Request) -> NoReturn:
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


async def test_HTTP_307_REDIRECT_POST(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(text=request.method)

    async def redirect(request: web.Request) -> NoReturn:
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


async def test_HTTP_308_PERMANENT_REDIRECT_POST(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(text=request.method)

    async def redirect(request: web.Request) -> NoReturn:
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


async def test_HTTP_302_max_redirects(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> NoReturn:
        assert False

    async def redirect(request: web.Request) -> NoReturn:
        count = int(request.match_info["count"])
        assert count
        raise web.HTTPFound(location=f"/redirect/{count - 1}")

    app = web.Application()
    app.router.add_get("/", handler)
    app.router.add_get(r"/redirect/{count:\d+}", redirect)
    client = await aiohttp_client(app)

    with pytest.raises(TooManyRedirects) as ctx:
        await client.get("/redirect/5", max_redirects=2)
    assert 2 == len(ctx.value.history)
    assert ctx.value.request_info.url.path == "/redirect/5"
    assert ctx.value.request_info.method == "GET"


async def test_HTTP_200_GET_WITH_PARAMS(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_HTTP_200_GET_WITH_MultiDict_PARAMS(
    aiohttp_client: AiohttpClient,
) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_HTTP_200_GET_WITH_MIXED_PARAMS(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_POST_DATA(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_POST_DATA_with_explicit_formdata(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_POST_DATA_with_charset(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        mp = await request.multipart()
        part = await mp.next()
        assert isinstance(part, aiohttp.BodyPartReader)
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


async def test_POST_DATA_formdats_with_charset(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        mp = await request.post()
        assert "name" in mp
        assert isinstance(mp["name"], str)
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


async def test_POST_DATA_with_charset_post(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        data = await request.post()
        assert isinstance(data["name"], str)
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


async def test_POST_MultiDict(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


@pytest.mark.parametrize("data", (None, b""))
async def test_GET_DEFLATE(
    aiohttp_client: AiohttpClient, data: Optional[bytes]
) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.json_response({"ok": True})

    write_mock = None
    original_write_bytes = ClientRequest.write_bytes

    async def write_bytes(
        self: ClientRequest, writer: StreamWriter, conn: Connection
    ) -> None:
        nonlocal write_mock
        original_write = writer._write

        with mock.patch.object(
            writer, "_write", autospec=True, spec_set=True, side_effect=original_write
        ) as write_mock:
            await original_write_bytes(self, writer, conn)

    with mock.patch.object(ClientRequest, "write_bytes", write_bytes):
        app = web.Application()
        app.router.add_get("/", handler)
        client = await aiohttp_client(app)

        async with client.get("/", data=data, compress=True) as resp:
            assert resp.status == 200
            content = await resp.json()
            assert content == {"ok": True}

    assert write_mock is not None
    # No chunks should have been sent for an empty body.
    write_mock.assert_not_called()


async def test_POST_DATA_DEFLATE(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        data = await request.post()
        return web.json_response(dict(data))

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    # True is not a valid type, but still tested for backwards compatibility.
    resp = await client.post("/", data={"some": "data"}, compress=True)
    assert 200 == resp.status
    content = await resp.json()
    assert content == {"some": "data"}
    resp.close()


async def test_POST_FILES(aiohttp_client: AiohttpClient, fname: pathlib.Path) -> None:
    async def handler(request: web.Request) -> web.Response:
        data = await request.post()
        assert isinstance(data["some"], web.FileField)
        assert data["some"].filename == fname.name
        with fname.open("rb") as f:
            content1 = f.read()
        content2 = data["some"].file.read()
        assert content1 == content2
        assert isinstance(data["test"], web.FileField)
        assert data["test"].file.read() == b"data"
        assert isinstance(data["some"], web.FileField)
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


async def test_POST_FILES_DEFLATE(
    aiohttp_client: AiohttpClient, fname: pathlib.Path
) -> None:
    async def handler(request: web.Request) -> web.Response:
        data = await request.post()
        assert isinstance(data["some"], web.FileField)
        assert data["some"].filename == fname.name
        with fname.open("rb") as f:
            content1 = f.read()
        content2 = data["some"].file.read()
        data["some"].file.close()
        assert content1 == content2
        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    with fname.open("rb") as f:
        async with client.post(
            "/", data={"some": f}, chunked=True, compress="deflate"
        ) as resp:
            assert 200 == resp.status


async def test_POST_bytes(aiohttp_client: AiohttpClient) -> None:
    body = b"0" * 12345

    async def handler(request: web.Request) -> web.Response:
        data = await request.read()
        assert body == data
        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    async with client.post("/", data=body) as resp:
        assert 200 == resp.status


async def test_POST_bytes_too_large(aiohttp_client: AiohttpClient) -> None:
    body = b"0" * (2**20 + 1)

    async def handler(request: web.Request) -> web.Response:
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


async def test_POST_FILES_STR(
    aiohttp_client: AiohttpClient, fname: pathlib.Path
) -> None:
    async def handler(request: web.Request) -> web.Response:
        data = await request.post()
        with fname.open("rb") as f:
            content1 = f.read().decode()
        content2 = data["some"]
        assert content1 == content2
        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    with fname.open("rb") as f:
        async with client.post("/", data={"some": f.read().decode()}) as resp:
            assert 200 == resp.status


async def test_POST_FILES_STR_SIMPLE(
    aiohttp_client: AiohttpClient, fname: pathlib.Path
) -> None:
    async def handler(request: web.Request) -> web.Response:
        data = await request.read()
        with fname.open("rb") as f:
            content = f.read()
        assert content == data
        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    with fname.open("rb") as f:
        async with client.post("/", data=f.read()) as resp:
            assert 200 == resp.status


async def test_POST_FILES_LIST(
    aiohttp_client: AiohttpClient, fname: pathlib.Path
) -> None:
    async def handler(request: web.Request) -> web.Response:
        data = await request.post()
        assert isinstance(data["some"], web.FileField)
        assert fname.name == data["some"].filename
        with fname.open("rb") as f:
            content = f.read()
        assert content == data["some"].file.read()
        data["some"].file.close()
        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    with fname.open("rb") as f:
        async with client.post("/", data=[("some", f)]) as resp:
            assert 200 == resp.status


async def test_POST_FILES_CT(
    aiohttp_client: AiohttpClient, fname: pathlib.Path
) -> None:
    async def handler(request: web.Request) -> web.Response:
        data = await request.post()
        assert isinstance(data["some"], web.FileField)
        assert fname.name == data["some"].filename
        assert "text/plain" == data["some"].content_type
        with fname.open("rb") as f:
            content = f.read()
        assert content == data["some"].file.read()
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


async def test_POST_FILES_SINGLE(
    aiohttp_client: AiohttpClient, fname: pathlib.Path
) -> None:
    async def handler(request: web.Request) -> web.Response:
        data = await request.text()
        with fname.open("rb") as f:
            content = f.read().decode()
            assert content == data
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


async def test_POST_FILES_SINGLE_content_disposition(
    aiohttp_client: AiohttpClient, fname: pathlib.Path
) -> None:
    async def handler(request: web.Request) -> web.Response:
        data = await request.text()
        with fname.open("rb") as f:
            content = f.read().decode()
            assert content == data
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


async def test_POST_FILES_SINGLE_BINARY(
    aiohttp_client: AiohttpClient, fname: pathlib.Path
) -> None:
    async def handler(request: web.Request) -> web.Response:
        data = await request.read()
        with fname.open("rb") as f:
            content = f.read()
        assert content == data
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


async def test_POST_FILES_IO(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        data = await request.post()
        assert isinstance(data["unknown"], web.FileField)
        assert b"data" == data["unknown"].file.read()
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


async def test_POST_FILES_IO_WITH_PARAMS(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        data = await request.post()
        assert data["test"] == "true"
        assert isinstance(data["unknown"], web.FileField)
        assert data["unknown"].content_type == "application/octet-stream"
        assert data["unknown"].filename == "unknown"
        assert data["unknown"].file.read() == b"data"
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


async def test_POST_FILES_WITH_DATA(
    aiohttp_client: AiohttpClient, fname: pathlib.Path
) -> None:
    async def handler(request: web.Request) -> web.Response:
        data = await request.post()
        assert data["test"] == "true"
        assert isinstance(data["some"], web.FileField)
        assert data["some"].content_type in [
            "text/x-python",
            "text/plain",
            "application/octet-stream",
        ]
        assert data["some"].filename == fname.name
        with fname.open("rb") as f:
            assert data["some"].file.read() == f.read()
            data["some"].file.close()

        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    with fname.open("rb") as f:
        async with client.post("/", data={"test": "true", "some": f}) as resp:
            assert 200 == resp.status


async def test_POST_STREAM_DATA(
    aiohttp_client: AiohttpClient, fname: pathlib.Path
) -> None:
    async def handler(request: web.Request) -> web.Response:
        assert request.content_type == "application/octet-stream"
        content = await request.read()
        with fname.open("rb") as f:
            expected = f.read()
            assert request.content_length == len(expected)
            assert content == expected

        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    with fname.open("rb") as f:
        data_size = len(f.read())

    async def gen(fname: pathlib.Path) -> AsyncIterator[bytes]:
        with fname.open("rb") as f:
            data = f.read(100)
            while data:
                yield data
                data = f.read(100)

    async with client.post(
        "/", data=gen(fname), headers={"Content-Length": str(data_size)}
    ) as resp:
        assert 200 == resp.status


async def test_json(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_json_custom(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        assert request.content_type == "application/json"
        data = await request.json()
        return web.Response(body=aiohttp.JsonPayload(data))

    used = False

    def dumps(obj: Any) -> str:
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


async def test_expect_continue(aiohttp_client: AiohttpClient) -> None:
    expect_called = False

    async def handler(request: web.Request) -> web.Response:
        data = await request.post()
        assert data == {"some": "data"}
        return web.Response()

    async def expect_handler(request: web.Request) -> None:
        nonlocal expect_called
        expect = request.headers[hdrs.EXPECT]
        assert expect.lower() == "100-continue"
        assert request.transport is not None
        request.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        expect_called = True

    app = web.Application()
    app.router.add_post("/", handler, expect_handler=expect_handler)
    client = await aiohttp_client(app)

    async with client.post("/", data={"some": "data"}, expect100=True) as resp:
        assert 200 == resp.status
    assert expect_called


async def test_encoding_deflate(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_encoding_deflate_nochunk(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_encoding_gzip(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_encoding_gzip_write_by_chunks(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.StreamResponse:
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


async def test_encoding_gzip_nochunk(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_bad_payload_compression(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_bad_payload_chunked_encoding(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.StreamResponse:
        resp = web.StreamResponse()
        resp.force_close()
        resp._length_check = False
        resp.headers["Transfer-Encoding"] = "chunked"
        writer = await resp.prepare(request)
        assert writer is not None
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


async def test_no_payload_304_with_chunked_encoding(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test a 304 response with no payload with chunked set should have it removed."""

    async def handler(request: web.Request) -> web.StreamResponse:
        resp = web.StreamResponse(status=304)
        resp.enable_chunked_encoding()
        resp._length_check = False
        resp.headers["Transfer-Encoding"] = "chunked"
        writer = await resp.prepare(request)
        assert writer is not None
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


async def test_head_request_with_chunked_encoding(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test a head response with chunked set should have it removed."""

    async def handler(request: web.Request) -> web.StreamResponse:
        resp = web.StreamResponse(status=200)
        resp.enable_chunked_encoding()
        resp._length_check = False
        resp.headers["Transfer-Encoding"] = "chunked"
        writer = await resp.prepare(request)
        assert writer is not None
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


async def test_no_payload_200_with_chunked_encoding(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test chunked is preserved on a 200 response with no payload."""

    async def handler(request: web.Request) -> web.StreamResponse:
        resp = web.StreamResponse(status=200)
        resp.enable_chunked_encoding()
        resp._length_check = False
        resp.headers["Transfer-Encoding"] = "chunked"
        writer = await resp.prepare(request)
        assert writer is not None
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


async def test_bad_payload_content_length(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_payload_content_length_by_chunks(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.StreamResponse:
        resp = web.StreamResponse(headers={"content-length": "2"})
        await resp.prepare(request)
        await resp.write(b"answer")
        await resp.write(b"two")
        assert request.transport is not None
        request.transport.close()
        return resp

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/")
    data = await resp.read()
    assert data == b"an"
    resp.close()


async def test_chunked(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_shortcuts(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_cookies(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        assert request.cookies.keys() == {"test1", "test3"}
        assert request.cookies["test1"] == "123"
        assert request.cookies["test3"] == "456"
        return web.Response()

    c: "http.cookies.Morsel[str]" = http.cookies.Morsel()
    c.set("test3", "456", "456")

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app, cookies={"test1": "123", "test2": c})

    async with client.get("/") as resp:
        assert 200 == resp.status


async def test_cookies_per_request(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        assert request.cookies.keys() == {"test1", "test3", "test4", "test6"}
        assert request.cookies["test1"] == "123"
        assert request.cookies["test3"] == "456"
        assert request.cookies["test4"] == "789"
        assert request.cookies["test6"] == "abc"
        return web.Response()

    c: "http.cookies.Morsel[str]" = http.cookies.Morsel()
    c.set("test3", "456", "456")

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app, cookies={"test1": "123", "test2": c})

    rc: "http.cookies.Morsel[str]" = http.cookies.Morsel()
    rc.set("test6", "abc", "abc")

    cookies: Dict[str, Union[str, "http.cookies.Morsel[str]"]]
    cookies = {"test4": "789", "test5": rc}
    async with client.get("/", cookies=cookies) as resp:
        assert 200 == resp.status


async def test_cookies_redirect(aiohttp_client: AiohttpClient) -> None:
    async def redirect1(request: web.Request) -> web.Response:
        ret = web.Response(status=301, headers={"Location": "/redirect2"})
        ret.set_cookie("c", "1")
        return ret

    async def redirect2(request: web.Request) -> web.Response:
        ret = web.Response(status=301, headers={"Location": "/"})
        ret.set_cookie("c", "2")
        return ret

    async def handler(request: web.Request) -> web.Response:
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


async def test_cookies_on_empty_session_jar(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        assert "custom-cookie" in request.cookies
        assert request.cookies["custom-cookie"] == "abc"
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app, cookies=None)

    async with client.get("/", cookies={"custom-cookie": "abc"}) as resp:
        assert 200 == resp.status


async def test_morsel_with_attributes(aiohttp_client: AiohttpClient) -> None:
    # A comment from original test:
    #
    # No cookie attribute should pass here
    # they are only used as filters
    # whether to send particular cookie or not.
    # E.g. if cookie expires it just becomes thrown away.
    # Server who sent the cookie with some attributes
    # already knows them, no need to send this back again and again

    async def handler(request: web.Request) -> web.Response:
        assert request.cookies.keys() == {"test3"}
        assert request.cookies["test3"] == "456"
        return web.Response()

    c: "http.cookies.Morsel[str]" = http.cookies.Morsel()
    c.set("test3", "456", "456")
    c["httponly"] = True
    c["secure"] = True
    c["max-age"] = 1000

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app, cookies={"test2": c})

    async with client.get("/") as resp:
        assert 200 == resp.status


async def test_set_cookies(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        ret = web.Response()
        ret.set_cookie("c1", "cookie1")
        ret.set_cookie("c2", "cookie2")
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

    with mock.patch("aiohttp.client_reqrep.client_logger") as m_log:
        async with client.get("/") as resp:
            assert 200 == resp.status
            cookie_names = {c.key for c in client.session.cookie_jar}
        assert cookie_names == {"c1", "c2"}

        m_log.warning.assert_called_with("Can not load response cookies: %s", mock.ANY)


async def test_set_cookies_expired(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_set_cookies_max_age(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_set_cookies_max_age_overflow(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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
            assert cookie.key == "overflow"
            assert int(cookie["max-age"]) == int(overflow)


async def test_request_conn_error() -> None:
    client = aiohttp.ClientSession()
    with pytest.raises(aiohttp.ClientConnectionError):
        await client.get("http://0.0.0.0:1")
    await client.close()


@pytest.mark.xfail
async def test_broken_connection(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        assert request.transport is not None
        request.transport.close()
        return web.Response(text="answer" * 1000)

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    with pytest.raises(aiohttp.ClientResponseError):
        await client.get("/")


async def test_broken_connection_2(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.StreamResponse:
        resp = web.StreamResponse(headers={"content-length": "1000"})
        await resp.prepare(request)
        await resp.write(b"answer")
        assert request.transport is not None
        request.transport.close()
        return resp

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/")
    with pytest.raises(aiohttp.ClientPayloadError):
        await resp.read()
    resp.close()


async def test_custom_headers(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        assert request.headers["x-api-key"] == "foo"
        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    async with client.post(
        "/", headers={"Content-Type": "application/json", "x-api-key": "foo"}
    ) as resp:
        assert resp.status == 200


async def test_redirect_to_absolute_url(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(text=request.method)

    async def redirect(request: web.Request) -> NoReturn:
        raise web.HTTPFound(location=client.make_url("/"))

    app = web.Application()
    app.router.add_get("/", handler)
    app.router.add_get("/redirect", redirect)

    client = await aiohttp_client(app)
    async with client.get("/redirect") as resp:
        assert 200 == resp.status


async def test_redirect_without_location_header(aiohttp_client: AiohttpClient) -> None:
    body = b"redirect"

    async def handler_redirect(request: web.Request) -> web.Response:
        return web.Response(status=301, body=body)

    app = web.Application()
    app.router.add_route("GET", "/redirect", handler_redirect)
    client = await aiohttp_client(app)

    resp = await client.get("/redirect")
    data = await resp.read()
    assert data == body


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
    url: str, error_message_url: str, expected_exception_class: Type[Exception]
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
    aiohttp_client: AiohttpClient,
    invalid_redirect_url: str,
    error_message_url: str,
    expected_exception_class: Type[Exception],
) -> None:
    headers = {hdrs.LOCATION: invalid_redirect_url}

    async def generate_redirecting_response(request: web.Request) -> web.Response:
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
    aiohttp_client: AiohttpClient,
    invalid_redirect_url: str,
    error_message_url: str,
    expected_exception_class: Type[Exception],
) -> None:
    app = web.Application()

    for path, location in [
        ("/redirect", "/redirect1"),
        ("/redirect1", "/redirect2"),
        ("/redirect2", invalid_redirect_url),
    ]:

        async def generate_redirecting_response(request: web.Request) -> web.Response:
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
async def test_ok_from_status(
    aiohttp_client: AiohttpClient, status: int, expected_ok: bool
) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(status=status, body=b"")

    app = web.Application()
    app.router.add_route("GET", "/endpoint", handler)
    client = await aiohttp_client(app, raise_for_status=False)
    async with client.get("/endpoint") as resp:
        assert resp.ok is expected_ok


async def test_raise_for_status(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        raise web.HTTPBadRequest()

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app, raise_for_status=True)

    with pytest.raises(aiohttp.ClientResponseError):
        await client.get("/")


async def test_raise_for_status_per_request(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        raise web.HTTPBadRequest()

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    with pytest.raises(aiohttp.ClientResponseError):
        await client.get("/", raise_for_status=True)


async def test_raise_for_status_disable_per_request(
    aiohttp_client: AiohttpClient,
) -> None:
    async def handler(request: web.Request) -> web.Response:
        raise web.HTTPBadRequest()

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app, raise_for_status=True)

    async with client.get("/", raise_for_status=False) as resp:
        assert 400 == resp.status


async def test_request_raise_for_status_default(aiohttp_server: AiohttpServer) -> None:
    async def handler(request: web.Request) -> web.Response:
        raise web.HTTPBadRequest()

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with aiohttp.request("GET", server.make_url("/")) as resp:
        assert resp.status == 400


async def test_request_raise_for_status_disabled(aiohttp_server: AiohttpServer) -> None:
    async def handler(request: web.Request) -> web.Response:
        raise web.HTTPBadRequest()

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)
    url = server.make_url("/")

    async with aiohttp.request("GET", url, raise_for_status=False) as resp:
        assert resp.status == 400


async def test_request_raise_for_status_enabled(aiohttp_server: AiohttpServer) -> None:
    async def handler(request: web.Request) -> web.Response:
        raise web.HTTPBadRequest()

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)
    url = server.make_url("/")

    with pytest.raises(aiohttp.ClientResponseError):
        async with aiohttp.request("GET", url, raise_for_status=True):
            assert False, "never executed"  # pragma: no cover


async def test_session_raise_for_status_coro(aiohttp_client: AiohttpClient) -> None:
    async def handle(request: web.Request) -> web.Response:
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_route("GET", "/", handle)

    raise_for_status_called = 0

    async def custom_r4s(response: aiohttp.ClientResponse) -> None:
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


async def test_request_raise_for_status_coro(aiohttp_client: AiohttpClient) -> None:
    async def handle(request: web.Request) -> web.Response:
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_route("GET", "/", handle)

    raise_for_status_called = 0

    async def custom_r4s(response: aiohttp.ClientResponse) -> None:
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


@pytest.fixture
def create_server_for_url_and_handler(
    aiohttp_server: AiohttpServer, tls_certificate_authority: trustme.CA
) -> Callable[[URL, Handler], Awaitable[TestServer]]:
    def create(url: URL, srv: Handler) -> Awaitable[TestServer]:
        app = web.Application()
        app.router.add_route("GET", url.path, srv)

        if url.scheme == "https":
            assert url.host
            cert = tls_certificate_authority.issue_cert(
                url.host, "localhost", "127.0.0.1"
            )
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            cert.configure_cert(ssl_ctx)
            return aiohttp_server(app, ssl=ssl_ctx)
        return aiohttp_server(app)

    return create


@pytest.mark.parametrize(
    ["url_from_s", "url_to_s", "is_drop_header_expected"],
    [
        [
            "http://host1.com/path1",
            "http://host2.com/path2",
            True,
        ],
        ["http://host1.com/path1", "https://host1.com/path1", False],
        ["https://host1.com/path1", "http://host1.com/path2", True],
    ],
    ids=(
        "entirely different hosts",
        "http -> https",
        "https -> http",
    ),
)
async def test_drop_auth_on_redirect_to_other_host(
    create_server_for_url_and_handler: Callable[[URL, Handler], Awaitable[TestServer]],
    url_from_s: str,
    url_to_s: str,
    is_drop_header_expected: bool,
) -> None:
    url_from, url_to = URL(url_from_s), URL(url_to_s)

    async def srv_from(request: web.Request) -> NoReturn:
        assert request.host == url_from.host
        assert request.headers["Authorization"] == "Basic dXNlcjpwYXNz"
        raise web.HTTPFound(url_to)

    async def srv_to(request: web.Request) -> web.Response:
        assert request.host == url_to.host
        if is_drop_header_expected:
            assert "Authorization" not in request.headers, "Header wasn't dropped"
        else:
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
    create_server_for_url_and_handler: Callable[[URL, Handler], Awaitable[TestServer]],
) -> None:
    url_from = URL("http://host1.com/path1")
    url_to = URL("http://host2.com/path2")

    async def srv_from(request: web.Request) -> NoReturn:
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

    async with aiohttp.ClientSession(
        connector=connector, auth=aiohttp.BasicAuth("user", "pass")
    ) as client:
        resp = await client.get(url_from)
        assert resp.status == 200


async def test_drop_auth_on_redirect_to_other_host_with_global_auth_and_base_url(
    create_server_for_url_and_handler: Callable[[URL, Handler], Awaitable[TestServer]],
) -> None:
    url_from = URL("http://host1.com/path1")
    url_to = URL("http://host2.com/path2")

    async def srv_from(request: web.Request) -> NoReturn:
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


async def test_close_resp_on_error_async_with_session(
    aiohttp_server: AiohttpServer,
) -> None:
    async def handler(request: web.Request) -> NoReturn:
        resp = web.StreamResponse(headers={"content-length": "100"})
        await resp.prepare(request)
        await asyncio.sleep(0.1)
        assert False

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with aiohttp.ClientSession() as session:
        with pytest.raises(RuntimeError):
            async with session.get(server.make_url("/")) as resp:
                resp.content.set_exception(RuntimeError())
                await resp.read()

        assert session._connector is not None
        assert len(session._connector._conns) == 0


async def test_release_resp_on_normal_exit_from_cm(
    aiohttp_server: AiohttpServer,
) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with aiohttp.ClientSession() as session:
        async with session.get(server.make_url("/")) as resp:
            await resp.read()

        assert session._connector is not None
        assert len(session._connector._conns) == 1


async def test_non_close_detached_session_on_error_cm(
    aiohttp_server: AiohttpServer,
) -> None:
    async def handler(request: web.Request) -> NoReturn:
        resp = web.StreamResponse(headers={"content-length": "100"})
        await resp.prepare(request)
        await asyncio.sleep(0.1)
        assert False

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
        async def resolve(
            self,
            host: str,
            port: int = 0,
            family: socket.AddressFamily = socket.AF_INET,
        ) -> List[ResolveResult]:
            return []

        async def close(self) -> None:
            """Dummy"""

    connector = aiohttp.TCPConnector(resolver=FakeResolver())

    session = aiohttp.ClientSession(connector=connector)

    async with session:
        cm = session.get("http://non-existing.example.com")
        assert not session.closed
        with pytest.raises(Exception):
            await cm

    assert session.closed


async def test_aiohttp_request_context_manager(aiohttp_server: AiohttpServer) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with aiohttp.request("GET", server.make_url("/")) as resp:
        await resp.read()
        assert resp.status == 200


async def test_aiohttp_request_ctx_manager_close_sess_on_error(
    ssl_ctx: ssl.SSLContext, aiohttp_server: AiohttpServer
) -> None:
    async def handler(request: web.Request) -> NoReturn:
        assert False

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app, ssl=ssl_ctx)

    cm = aiohttp.request("GET", server.make_url("/"))

    with pytest.raises(aiohttp.ClientConnectionError):
        async with cm:
            pass

    assert cm._session.closed


async def test_aiohttp_request_ctx_manager_not_found() -> None:
    with pytest.raises(aiohttp.ClientConnectionError):
        async with aiohttp.request("GET", "http://wrong-dns-name.com"):
            assert False, "never executed"  # pragma: no cover


async def test_aiohttp_request_ctx_manager_not_found_exception_is_dns_specific() -> (
    None
):
    # The error raised should be specific to DNS
    with pytest.raises(aiohttp.ClientConnectorDNSError):
        async with aiohttp.request("GET", "http://wrong-dns-name.com"):
            assert False, "never executed"  # pragma: no cover


async def test_aiohttp_request_connector_error_non_dns() -> None:
    # A non-dns counterpart to test_aiohttp_request_ctx_manager_not_found_exception_is_dns_specific
    with pytest.raises(aiohttp.ClientConnectorError) as excinfo:
        async with aiohttp.request("GET", "http://localhost:1/"):
            assert False, "never executed"  # pragma: no cover
    assert not isinstance(excinfo.value, aiohttp.ClientConnectorDNSError)


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


async def test_yield_from_in_session_request(aiohttp_client: AiohttpClient) -> None:
    # a test for backward compatibility with yield from syntax
    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app)
    async with client.get("/") as resp:
        assert resp.status == 200


async def test_close_context_manager(aiohttp_client: AiohttpClient) -> None:
    # a test for backward compatibility with yield from syntax
    async def handler(request: web.Request) -> NoReturn:
        assert False

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app)
    ctx = client.get("/")
    ctx.close()
    assert not ctx._coro.cr_running


async def test_session_auth(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.json_response({"headers": dict(request.headers)})

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app, auth=aiohttp.BasicAuth("login", "pass"))

    r = await client.get("/")
    assert r.status == 200
    content = await r.json()
    assert content["headers"]["Authorization"] == "Basic bG9naW46cGFzcw=="


async def test_session_auth_override(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.json_response({"headers": dict(request.headers)})

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app, auth=aiohttp.BasicAuth("login", "pass"))

    r = await client.get("/", auth=aiohttp.BasicAuth("other_login", "pass"))
    assert r.status == 200
    content = await r.json()
    val = content["headers"]["Authorization"]
    assert val == "Basic b3RoZXJfbG9naW46cGFzcw=="


async def test_session_auth_header_conflict(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> NoReturn:
        assert False

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app, auth=aiohttp.BasicAuth("login", "pass"))
    headers = {"Authorization": "Basic b3RoZXJfbG9naW46cGFzcw=="}
    with pytest.raises(ValueError):
        await client.get("/", headers=headers)


async def test_session_headers(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.json_response({"headers": dict(request.headers)})

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app, headers={"X-Real-IP": "192.168.0.1"})

    r = await client.get("/")
    assert r.status == 200
    content = await r.json()
    assert content["headers"]["X-Real-IP"] == "192.168.0.1"


async def test_session_headers_merge(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_multidict_headers(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_request_conn_closed(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        assert request.transport is not None
        request.transport.close()
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app)
    with pytest.raises(aiohttp.ServerDisconnectedError) as excinfo:
        resp = await client.get("/")
        await resp.read()

    assert str(excinfo.value) != ""


async def test_dont_close_explicit_connector(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app)
    r = await client.get("/")
    await r.read()

    assert client.session.connector is not None
    assert 1 == len(client.session.connector._conns)


async def test_server_close_keepalive_connection() -> None:
    loop = asyncio.get_event_loop()

    class Proto(asyncio.Protocol):
        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            assert isinstance(transport, asyncio.Transport)
            self.transp: Optional[asyncio.Transport] = transport
            self.data = b""

        def data_received(self, data: bytes) -> None:
            self.data += data
            assert data.endswith(b"\r\n\r\n")
            assert self.transp is not None
            self.transp.write(
                b"HTTP/1.1 200 OK\r\n"
                b"CONTENT-LENGTH: 2\r\n"
                b"CONNECTION: close\r\n"
                b"\r\n"
                b"ok"
            )
            self.transp.close()

        def connection_lost(self, exc: Optional[BaseException]) -> None:
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
        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            assert isinstance(transport, asyncio.Transport)
            self.transp: Optional[asyncio.Transport] = transport
            self.data = b""

        def data_received(self, data: bytes) -> None:
            self.data += data
            assert data.endswith(b"\r\n\r\n")
            assert self.transp is not None
            self.transp.write(b"HTTP/1.1 200 OK\r\nCONTENT-LENGTH: 2\r\n\r\nok")
            self.transp.close()

        def connection_lost(self, exc: Optional[BaseException]) -> None:
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


async def test_error_in_performing_request(
    ssl_ctx: ssl.SSLContext,
    aiohttp_client: AiohttpClient,
    aiohttp_server: AiohttpServer,
) -> None:
    async def handler(request: web.Request) -> NoReturn:
        assert False

    def exception_handler(loop: object, context: object) -> None:
        """Skip log messages about destroyed but pending tasks"""

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


async def test_await_after_cancelling(aiohttp_client: AiohttpClient) -> None:
    loop = asyncio.get_event_loop()

    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    client = await aiohttp_client(app)

    fut1 = loop.create_future()
    fut2 = loop.create_future()

    async def fetch1() -> None:
        resp = await client.get("/")
        assert resp.status == 200
        fut1.set_result(None)
        with pytest.raises(asyncio.CancelledError):
            await fut2
        resp.release()

    async def fetch2() -> None:
        await fut1
        resp = await client.get("/")
        assert resp.status == 200

    async def canceller() -> None:
        await fut1
        fut2.cancel()

    await asyncio.gather(fetch1(), fetch2(), canceller())


async def test_async_payload_generator(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        data = await request.read()
        assert data == b"1234567890" * 100
        return web.Response()

    app = web.Application()
    app.add_routes([web.post("/", handler)])

    client = await aiohttp_client(app)

    async def gen() -> AsyncIterator[bytes]:
        for i in range(100):
            yield b"1234567890"

    async with client.post("/", data=gen()) as resp:
        assert resp.status == 200


async def test_read_from_closed_response(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=b"data")

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)

    async with client.get("/") as resp:
        assert resp.status == 200

    with pytest.raises(aiohttp.ClientConnectionError):
        await resp.read()


async def test_read_from_closed_response2(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=b"data")

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)

    async with client.get("/") as resp:
        assert resp.status == 200
        await resp.read()

    with pytest.raises(aiohttp.ClientConnectionError):
        await resp.read()


async def test_json_from_closed_response(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.json_response(42)

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)

    async with client.get("/") as resp:
        assert resp.status == 200
        await resp.read()

    # Should not allow reading outside of resp context even when body is available.
    with pytest.raises(aiohttp.ClientConnectionError):
        await resp.json()


async def test_text_from_closed_response(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(text="data")

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)

    async with client.get("/") as resp:
        assert resp.status == 200
        await resp.read()

    # Should not allow reading outside of resp context even when body is available.
    with pytest.raises(aiohttp.ClientConnectionError):
        await resp.text()


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


async def test_read_timeout(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> NoReturn:
        await asyncio.sleep(5)
        assert False

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    timeout = aiohttp.ClientTimeout(sock_read=0.1)
    client = await aiohttp_client(app, timeout=timeout)

    with pytest.raises(aiohttp.ServerTimeoutError):
        await client.get("/")


async def test_socket_timeout(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> NoReturn:
        await asyncio.sleep(5)
        assert False

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    timeout = aiohttp.ClientTimeout(sock_read=0.1)
    client = await aiohttp_client(app, timeout=timeout)

    with pytest.raises(SocketTimeoutError):
        await client.get("/")


async def test_read_timeout_closes_connection(aiohttp_client: AiohttpClient) -> None:
    request_count = 0

    async def handler(request: web.Request) -> web.Response:
        nonlocal request_count
        request_count += 1
        if request_count < 3:
            await asyncio.sleep(0.5)
        return web.Response(body=f"request:{request_count}")

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    timeout = aiohttp.ClientTimeout(total=0.1)
    client = await aiohttp_client(app, timeout=timeout)
    with pytest.raises(asyncio.TimeoutError):
        await client.get("/")

    # Make sure its really closed
    assert client.session.connector is not None
    assert not client.session.connector._conns

    with pytest.raises(asyncio.TimeoutError):
        await client.get("/")

    # Make sure its really closed
    assert not client.session.connector._conns
    result = await client.get("/")
    assert await result.read() == b"request:3"

    # Make sure its not closed
    assert client.session.connector._conns


async def test_read_timeout_on_prepared_response(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> NoReturn:
        resp = aiohttp.web.StreamResponse()
        await resp.prepare(request)
        await asyncio.sleep(5)
        assert False

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    timeout = aiohttp.ClientTimeout(sock_read=0.1)
    client = await aiohttp_client(app, timeout=timeout)

    with pytest.raises(aiohttp.ServerTimeoutError):
        async with await client.get("/") as resp:
            await resp.read()


async def test_timeout_with_full_buffer(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_read_bufsize_session_default(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=b"1234567")

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app, read_bufsize=2)

    async with await client.get("/") as resp:
        assert resp.content.get_read_buffer_limits() == (2, 4)


async def test_read_bufsize_explicit(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=b"1234567")

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)

    async with await client.get("/", read_bufsize=4) as resp:
        assert resp.content.get_read_buffer_limits() == (4, 8)


async def test_http_empty_data_text(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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


async def test_max_field_size_session_default(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(headers={"Custom": "x" * 8190})

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)

    async with await client.get("/") as resp:
        assert resp.headers["Custom"] == "x" * 8190


async def test_max_field_size_session_default_fail(
    aiohttp_client: AiohttpClient,
) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(headers={"Custom": "x" * 8191})

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)
    with pytest.raises(aiohttp.ClientResponseError):
        await client.get("/")


async def test_max_field_size_session_explicit(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(headers={"Custom": "x" * 8191})

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app, max_field_size=8191)

    async with await client.get("/") as resp:
        assert resp.headers["Custom"] == "x" * 8191


async def test_max_field_size_request_explicit(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(headers={"Custom": "x" * 8191})

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)

    async with await client.get("/", max_field_size=8191) as resp:
        assert resp.headers["Custom"] == "x" * 8191


async def test_max_line_size_session_default(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(status=200, reason="x" * 8190)

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)

    async with await client.get("/") as resp:
        assert resp.reason == "x" * 8190


async def test_max_line_size_session_default_fail(
    aiohttp_client: AiohttpClient,
) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(status=200, reason="x" * 8192)

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app)
    with pytest.raises(aiohttp.ClientResponseError):
        await client.get("/")


async def test_max_line_size_session_explicit(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(status=200, reason="x" * 8191)

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    client = await aiohttp_client(app, max_line_size=8191)

    async with await client.get("/") as resp:
        assert resp.reason == "x" * 8191


async def test_max_line_size_request_explicit(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
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

    async def not_ok_handler(request: web.Request) -> NoReturn:
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


async def test_request_with_wrong_ssl_type(aiohttp_client: AiohttpClient) -> None:
    app = web.Application()
    session = await aiohttp_client(app)

    with pytest.raises(TypeError, match="ssl should be SSLContext, Fingerprint, .*"):
        await session.get("/", ssl=42)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("value", "exc_type"),
    [(42, TypeError), ("InvalidUrl", InvalidURL)],
)
async def test_request_with_wrong_proxy(
    aiohttp_client: AiohttpClient, value: Union[int, str], exc_type: Type[Exception]
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
    session = await aiohttp_client(app, raise_for_status=None)

    await session.get("/")


async def test_header_too_large_error(aiohttp_client: AiohttpClient) -> None:
    """By default when not specifying `max_field_size` requests should fail with a 400 status code."""

    async def handler(_: web.Request) -> web.Response:
        return web.Response(headers={"VeryLargeHeader": "x" * 10000})

    app = web.Application()
    app.add_routes([web.get("/", handler)])
    client = await aiohttp_client(app)

    with pytest.raises(
        aiohttp.ClientResponseError, match="Got more than 8190 bytes*"
    ) as exc_info:
        await client.get("/")
    assert exc_info.value.status == 400


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
