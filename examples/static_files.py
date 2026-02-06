#!/usr/bin/env python3
import pathlib

from aiohttp import web


def init() -> web.Application:
    app = web.Application()
    app.router.add_static("/", pathlib.Path(__file__).parent, show_index=True)
    return app


if __name__ == "__main__":
    web.run_app(init())
