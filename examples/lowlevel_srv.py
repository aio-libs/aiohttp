import asyncio
import contextlib

from aiohttp import web, web_request


async def handler(request: web_request.BaseRequest) -> web.StreamResponse:
    return web.Response(text="OK")


async def main() -> None:
    server = web.Server(handler)
    await asyncio.get_running_loop().create_server(server, "127.0.0.1", 8080)
    print("======= Serving on http://127.0.0.1:8080/ ======")

    # pause here for very long time by serving HTTP requests and
    # waiting for keyboard interruption
    await asyncio.sleep(100 * 3600)


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
