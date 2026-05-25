#!/usr/bin/env python3
import argparse
import asyncio
import os
import pathlib
import ssl
import tempfile
from logging import basicConfig, getLogger
import uvloop

from aiohttp import web


HOST = "0.0.0.0"
TLS_PORT = 8443
KTLS_PORT = 8444
FILE_SIZE = 2 * 1024 * 1024 * 1024
STATIC_DIR = pathlib.Path(tempfile.gettempdir()) / "aiohttp-ktls-static"
HUGE_FILE = STATIC_DIR / "huge.bin"


def make_huge_file() -> pathlib.Path:
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    if not HUGE_FILE.exists() or HUGE_FILE.stat().st_size != FILE_SIZE:
        with HUGE_FILE.open("wb") as f:
            f.truncate(FILE_SIZE)
    return HUGE_FILE


def make_ssl_context(*, enable_ktls: bool) -> ssl.SSLContext:
    here = pathlib.Path(__file__).parent
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(here / "server.crt", here / "server.key")

    if enable_ktls:
        ssl_context.options |= ssl.OP_ENABLE_KTLS

    return ssl_context


async def huge_file(request: web.Request) -> web.FileResponse:
    return web.FileResponse(make_huge_file())


def make_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/huge.bin", huge_file)
    return app


async def main(args) -> None:
    huge_path = make_huge_file()

    if args.asyncio_debug:
        asyncio.get_running_loop().set_debug(True)

    runner = web.AppRunner(make_app())
    await runner.setup()

    plain_tls_site = web.TCPSite(
        runner,
        args.host,
        args.tls_port,
        ssl_context=make_ssl_context(enable_ktls=False),
    )
    ktls_site = web.TCPSite(
        runner,
        args.host,
        args.ktls_port,
        ssl_context=make_ssl_context(enable_ktls=True),
    )

    try:
        await plain_tls_site.start()
        await ktls_site.start()

        print(f"Serving {huge_path} ({FILE_SIZE} bytes)")
        print(f"TLS without KTLS: https://{args.host}:{plain_tls_site.port}/huge.bin")
        print(f"TLS with KTLS:    https://{args.host}:{ktls_site.port}/huge.bin")

        await asyncio.Event().wait()
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Serve one 50 MiB file from two HTTPS ports, one with KTLS enabled."
        )
    )
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--tls-port", type=int, default=TLS_PORT)
    parser.add_argument("--ktls-port", type=int, default=KTLS_PORT)
    parser.add_argument("--uvloop", action="store_true", help="Use uvloop")
    parser.add_argument("--asyncio-debug", action="store_true", help="Enable loop debugging")
    parser.add_argument("--level", type=str, default="INFO", help="Logging level")

    args = parser.parse_args()

    if args.uvloop:
        uvloop.install()

    basicConfig(level=args.level)

    asyncio.run(main(args))
