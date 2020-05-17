import asyncio
from asyncio import AbstractEventLoop

from aiohttp import web
from aiohttp.web_request import BaseRequest


async def handler(request: BaseRequest) -> web.StreamResponse:
    return web.Response(text="OK")


async def main(loop: AbstractEventLoop) -> None:
    server = web.Server(handler)
    await loop.create_server(server, "127.0.0.1", 8080)
    print("======= Serving on http://127.0.0.1:8080/ ======")

    # pause here for very long time by serving HTTP requests and
    # waiting for keyboard interruption
    await asyncio.sleep(100 * 3600)


loop = asyncio.get_event_loop()

try:
    loop.run_until_complete(main(loop))
except KeyboardInterrupt:
    pass
loop.close()
