import asyncio
import contextlib
import gc
from time import time

import objgraph

import aiohttp
from aiohttp import web
from aiohttp.test_utils import get_unused_port_socket


def get_garbage():
    result = []
    gc.collect()
    for obj in gc.garbage:
        obj_name = type(obj).__name__
        result.append(f"{obj_name}")
        if obj_name in ("ClientResponse",):
            print("ClientResponse not collected!")
            objgraph.show_backrefs(
                obj,
                max_depth=30,
                too_many=50,
                filename=f"/tmp/{int(time() * 1000)}err_referrers.png",
            )

    return result


class Client:
    def __init__(self):
        self.session = aiohttp.ClientSession()
        self.response = None

    async def fetch_stream(self, url):
        try:
            self.response = await self.session.get(url)
            if self.response.status == 200:
                while True:
                    chunk = await self.response.content.readexactly(6)
                    print(f"received: {chunk.decode().strip()}")
            else:
                print(f"response status code: {self.response.status}")
        except (
            aiohttp.ClientConnectorError,
            aiohttp.ServerDisconnectedError,
            aiohttp.ClientPayloadError,
            asyncio.IncompleteReadError,
        ) as e:
            print(f"connection error ({type(e).__name__})")
        except Exception as e:
            print(f"unexpected error: {e}")
        finally:
            self.response = None  # Explicitly clear response
            self.session = None  # This should close the session, but memory leak persists due to traceback references.


async def main():
    app = web.Application()

    async def stream_handler(request: web.Request) -> web.Response:
        if writer := request.transport:
            writer.close()  # Forcefully closing connection

        return web.Response()

    app.router.add_get("/stream", stream_handler)
    sock = get_unused_port_socket("127.0.0.1")
    port = sock.getsockname()[1]

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.SockSite(runner, sock)
    await site.start()

    session = aiohttp.ClientSession()

    async def fetch_stream(url: str) -> None:
        """Fetch a stream and read a few bytes from it."""
        with contextlib.suppress(aiohttp.ClientError):
            response = await session.get(url)
            while True:
                await response.content.readexactly(6)

    client = Client()

    client_task = asyncio.create_task(
        client.fetch_stream(f"http://localhost:{port}/stream")
    )
    await client_task
    await asyncio.sleep(0.5)  # Allow time for cleanup
    print("garbage:")
    gc.collect()

    for obj in gc.garbage:
        print(f"garbage: ({type(obj).__name__})")

    assert not any(
        type(obj).__name__ == "ClientResponse" for obj in gc.garbage
    ), "ClientResponse not collected!"
    get_garbage()
    await session.close()
    await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
