import asyncio
import gc
import sys
from typing import NoReturn

from aiohttp import ClientSession, web
from aiohttp.test_utils import get_unused_port_socket

gc.set_debug(gc.DEBUG_LEAK)


async def main() -> None:
    app = web.Application()

    async def handler(request: web.Request) -> NoReturn:
        await request.json()

    app.router.add_route("GET", "/json", handler)
    sock = get_unused_port_socket("127.0.0.1")
    port = sock.getsockname()[1]

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.SockSite(runner, sock)
    await site.start()

    async with ClientSession() as session:
        async with session.get(f"http://127.0.0.1:{port}/json") as resp:
            await resp.read()

    # Give time for the cancelled task to be collected
    await asyncio.sleep(0.5)
    gc.collect()
    request_present = any(type(obj).__name__ == "Request" for obj in gc.garbage)
    await session.close()
    await runner.cleanup()
    sys.exit(1 if request_present else 0)


asyncio.run(main())
