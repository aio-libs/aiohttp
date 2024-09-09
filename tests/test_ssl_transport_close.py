import asyncio
import platform
import ssl
import sys
import warnings
from typing import Any, Tuple, cast

import pytest

from aiohttp import TCPConnector, web
from aiohttp.client import ServerDisconnectedError
from aiohttp.pytest_plugin import AiohttpClient, AiohttpServer
from aiohttp.test_utils import TestClient, TestServer


async def handle_root(request: web.Request) -> web.Response:
    """respond after server was restarted, forcing connection_lost"""
    cq = request.app["cq"]
    dq = request.app["dq"]

    await dq.put(0)

    await cq.get()
    cq.task_done()

    return web.Response(text="")


async def _prepare(
    aiohttp_server: Any,
    aiohttp_client: Any,
    ssl_ctx: ssl.SSLContext,
    client_ssl_ctx: ssl.SSLContext,
    cq: "asyncio.Queue[int]",
    dq: "asyncio.Queue[int]",
) -> Tuple[TestServer, TestClient]:
    app = web.Application()
    app["cq"] = cq
    app["dq"] = dq
    app.router.add_get("/", handle_root)
    server = await aiohttp_server(app, port=0, ssl=ssl_ctx)

    session = await aiohttp_client(server, connector=TCPConnector(ssl=client_ssl_ctx))

    # replace SockSite … it is different and blocks
    await dq.put(0)
    await _restart(server.runner, ssl_ctx, session.port, cq, dq)
    await cq.get()

    return server, session


async def _restart(
    runner: web.BaseRunner,
    ssl_ctx: ssl.SSLContext,
    port: int,
    cq: "asyncio.Queue[int]",
    dq: "asyncio.Queue[int]",
) -> None:
    """restart service to force connection_lost"""
    await dq.get()
    dq.task_done()
    site = next(iter(runner.sites))
    await site.stop()
    await cq.put(0)
    site = web.TCPSite(
        runner, "127.0.0.1", port=port, ssl_context=ssl_ctx
    )
    await site.start()


def _ssl_resource_warnings(w: warnings.WarningMessage) -> bool:
    unclosed_transport_msg = (
        "unclosed transport <asyncio.sslproto._SSLProtocolTransport object at"
    )
    return (
        w.category == ResourceWarning
        and w.filename.endswith("sslproto.py")
        and cast(Warning, w.message).args[0].startswith(unclosed_transport_msg)
    )


async def _run(
    aiohttp_server: AiohttpServer,
    aiohttp_client: AiohttpClient,
    recwarn: pytest.WarningsRecorder,
    ssl_ctx: ssl.SSLContext,
    client_ssl_ctx: ssl.SSLContext,
    cq: "asyncio.Queue[int]",
    dq: "asyncio.Queue[int]",
) -> None:
    """run for two processed client requests"""
    server, session = await _prepare(
        aiohttp_server, aiohttp_client, ssl_ctx, client_ssl_ctx, cq, dq
    )
    assert server.runner is not None and session.port is not None
    for i in range(3):
        try:
            jobs: Any = []
            jobs.append(session.get("/"))
            jobs.append(_restart(server.runner, ssl_ctx, session.port, cq, dq))
            await asyncio.gather(*jobs)
        except ServerDisconnectedError:
            # Restarting the service will cause the client connections to fail
            # this is expected and not a failure.
            pass
        finally:
            await asyncio.sleep(0.1)

        assert not len(
            list(filter(_ssl_resource_warnings, recwarn))
        ), "unclosed transport"


@pytest.mark.xfail(
    sys.version_info < (3, 11) and platform.python_implementation() != "PyPy",
    reason="Working on 3.11+ and Pypy.",
)
def test_unclosed_transport_asyncio_sslproto_SSLProtocolTransport(
    loop: asyncio.AbstractEventLoop,
    aiohttp_server: AiohttpServer,
    aiohttp_client: AiohttpClient,
    recwarn: pytest.WarningsRecorder,
    ssl_ctx: ssl.SSLContext,
    client_ssl_ctx: ssl.SSLContext,
) -> None:
    cq: "asyncio.Queue[int]" = asyncio.Queue()
    dq: "asyncio.Queue[int]" = asyncio.Queue()
    loop.set_debug(True)
    loop.run_until_complete(
        _run(
            aiohttp_server,
            aiohttp_client,
            recwarn,
            ssl_ctx,
            client_ssl_ctx,
            cq,
            dq,
        )
    )
