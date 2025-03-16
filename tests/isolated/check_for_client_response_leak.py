import asyncio
import contextlib
import gc
import sys

from aiohttp import ClientError, ClientSession, web
from aiohttp.test_utils import get_unused_port_socket

gc.set_debug(gc.DEBUG_LEAK)


async def main() -> None:
    app = web.Application()

    async def stream_handler(request: web.Request) -> web.Response:
        assert request.transport is not None
        request.transport.close()  # Forcefully closing connection
        return web.Response()

    app.router.add_get("/stream", stream_handler)
    sock = get_unused_port_socket("127.0.0.1")
    port = sock.getsockname()[1]

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.SockSite(runner, sock)
    await site.start()

    session = ClientSession()

    async def fetch_stream(url: str) -> None:
        """Fetch a stream and read a few bytes from it."""
        with contextlib.suppress(ClientError):
            await session.get(url)

    client_task = asyncio.create_task(fetch_stream(f"http://localhost:{port}/stream"))
    await client_task
    gc.collect()
    client_response_present = any(
        type(obj).__name__ == "ClientResponse" for obj in gc.garbage
    )
    await session.close()
    await runner.cleanup()
    sys.exit(1 if client_response_present else 0)


asyncio.run(main())
