#!/usr/bin/env python3
import pathlib
from typing import TypedDict

from aiohttp import web


class EmptyDict(TypedDict):
    pass


app: web.Application[EmptyDict] = web.Application()
app.router.add_static("/", pathlib.Path(__file__).parent, show_index=True)

web.run_app(app)
