#!/usr/bin/env python3
from pathlib import Path

from aiohttp import web

app = web.Application()
app.router.add_static("/", Path(__file__).parent, show_index=True)

web.run_app(app)
