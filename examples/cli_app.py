#!/usr/bin/env python3
"""
Example of serving an Application using the `aiohttp.web` CLI.

Serve this app using::

    $ python -m aiohttp.web -H localhost -P 8080 --repeat 10 cli_app:init \
    > "Hello World"

Here ``--repeat`` & ``"Hello World"`` are application specific command-line
arguments. `aiohttp.web` only parses & consumes the command-line arguments it
needs (i.e. ``-H``, ``-P`` & ``entry-func``) and passes on any additional
arguments to the `cli_app:init` function for processing.
"""

import asyncio
from argparse import ArgumentParser, Namespace
from collections.abc import Sequence

from aiohttp import ClientSession, web

args_key = web.AppKey("args_key", Namespace)


async def display_message(req: web.Request) -> web.StreamResponse:
    args = req.app[args_key]
    text = "\n".join([args.message] * args.repeat)
    return web.Response(text=text)


def init(argv: Sequence[str] | None) -> web.Application:
    arg_parser = ArgumentParser(
        prog="aiohttp.web ...", description="Application CLI", add_help=False
    )

    # Positional argument
    arg_parser.add_argument("message", help="message to print")

    # Optional argument
    arg_parser.add_argument(
        "--repeat", help="number of times to repeat message", type=int, default="1"
    )

    # Avoid conflict with -h from `aiohttp.web` CLI parser
    arg_parser.add_argument(
        "--app-help", help="show this message and exit", action="help"
    )

    args = arg_parser.parse_args(argv)

    app = web.Application()
    app[args_key] = args
    app.router.add_get("/", display_message)

    return app


async def run_test_server() -> tuple[web.AppRunner, int]:
    """Start the server on a dynamic port for testing."""
    runner = web.AppRunner(init(["--repeat", "3", "Hello"]))
    await runner.setup()
    site = web.TCPSite(runner, "localhost", 0)
    await site.start()
    assert site._server is not None
    port: int = site._server.sockets[0].getsockname()[1]
    return runner, port


async def run_tests(port: int) -> None:
    """Run all tests against the server."""
    base_url = f"http://localhost:{port}"
    async with ClientSession() as session:
        async with session.get(f"{base_url}/") as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "Hello\nHello\nHello"
            print("OK: GET / -> Hello repeated 3 times")

    print("\nAll tests passed!")


async def main() -> None:
    runner, port = await run_test_server()
    try:
        await run_tests(port)
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
