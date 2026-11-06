import asyncio
import contextlib
import gc
import socket
import sys

from aiohttp import ClientConnectorError, ClientSession

gc.set_debug(gc.DEBUG_LEAK)


async def main() -> None:
    # A bound socket that does not listen: connecting to it is refused.
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

        async with ClientSession() as session:
            with contextlib.suppress(ClientConnectorError):
                await session.get(f"http://127.0.0.1:{port}/")
            gc.collect()
    connector_error_present = any(
        type(obj).__name__ == "ClientConnectorError" for obj in gc.garbage
    )
    sys.exit(1 if connector_error_present else 0)


asyncio.run(main())
