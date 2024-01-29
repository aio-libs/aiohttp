import asyncio

import aiohttp
from aiohttp import web


async def handle_root(request):
    """
    respond after server was restarted, forcing connection_lost
    """
    cq = request.app["cq"]
    dq = request.app["dq"]

    await dq.put(0)

    await cq.get()
    cq.task_done()

    return web.Response(text="")


async def _prepare(aiohttp_server, aiohttp_client, ssl_ctx, client_ssl_ctx, cq, dq):
    app = web.Application()
    app["cq"] = cq
    app["dq"] = dq
    app.router.add_get("/", handle_root)
    server = await aiohttp_server(app, port=0, ssl=ssl_ctx)

    session = await aiohttp_client(
        server, connector=aiohttp.TCPConnector(ssl=client_ssl_ctx)
    )

    # replace SockSite … it is different and blocks
    await dq.put(0)
    await _restart(server.runner, ssl_ctx, session.port, cq, dq)
    await cq.get()

    return server, session


async def _close(server, session):
    await server.close()
    await session.close()


async def _restart(runner, ssl_ctx, port, cq, dq):
    """
    restart service to force connection_lost
    """
    await dq.get()
    dq.task_done()
    for s in list(runner.sites):
        await s.stop()
        await cq.put(0)
        s = web.TCPSite(
            runner, "127.0.0.1", port=port, ssl_context=ssl_ctx, shutdown_timeout=1.0
        )
        await s.start()
        break


def _ssl_resource_warnings(w):
    unclosed_transport_msg = (
        "unclosed transport <asyncio.sslproto._SSLProtocolTransport object at"
    )
    return (
        w.category == ResourceWarning
        and w.filename.endswith("sslproto.py")
        and w.message.args[0].startswith(unclosed_transport_msg)
    )


async def _run(
    loop, aiohttp_server, aiohttp_client, recwarn, ssl_ctx, client_ssl_ctx, cq, dq
):
    """
    run for two processed client requests
    """
    server, session = await _prepare(
        aiohttp_server, aiohttp_client, ssl_ctx, client_ssl_ctx, cq, dq
    )
    for i in range(3):
        try:
            jobs = []
            jobs.append(session.get("/"))
            jobs.append(_restart(server.runner, ssl_ctx, session.port, cq, dq))
            await asyncio.gather(*jobs)
        except aiohttp.client.ServerDisconnectedError:
            pass
        finally:
            await asyncio.sleep(0.1)

        assert not len(list(filter(_ssl_resource_warnings, recwarn)))

    await _close(server, session)


def test_unclosed_transport_asyncio_sslproto_SSLProtocolTransport(
    aiohttp_server, aiohttp_client, recwarn, ssl_ctx, client_ssl_ctx
):
    loop = asyncio.get_event_loop()

    cq = asyncio.Queue()
    dq = asyncio.Queue()
    loop.set_debug(True)
    loop.run_until_complete(
        _run(
            loop,
            aiohttp_server,
            aiohttp_client,
            recwarn,
            ssl_ctx,
            client_ssl_ctx,
            cq,
            dq,
        )
    )
    loop.close()
