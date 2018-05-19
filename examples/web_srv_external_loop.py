#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-
import asyncio
from aiohttp import web, web_runner


class WebServer(object):
    def __init__(self, address='127.0.0.1', port=8080, loop=None):
        self.address = address
        self.port = port
        if loop is None:
            loop = asyncio.get_event_loop()
        self.loop = loop
        asyncio.ensure_future(self.start(), loop=self.loop)

    async def start(self):
        self.app = web.Application(loop=self.loop, debug=True)
        self.setup_routes()
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web_runner.TCPSite(self.runner,
                                       self.address, self.port,
                                       loop=self.loop)
        await self.site.start()
        print('------ serving on %s:%d ------'
              % (self.address, self.port))

    def setup_routes(self):
        self.app.router.add_get('/', self.index)

    async def index(self, request):
        return web.Response(text='Hello Aiohttp!!')


class LoopTester(object):
    def __init__(self, loop=None):
        if loop is None:
            loop = asyncio.get_event_loop()
        self.loop = loop
        self.counter = 0
        asyncio.ensure_future(self.run(), loop=self.loop)

    async def run(self):
        while self.loop.is_running():
            print('basic test %d' % (self.counter))
            self.counter += 1
            await asyncio.sleep(1)


if __name__ == '__main__':
    import logging

    loop = asyncio.get_event_loop()
    logging.basicConfig(level=logging.DEBUG)
    loop.set_debug(False)
    lt = LoopTester(loop=loop)
    ws = WebServer(loop=loop)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        tasks = asyncio.gather(
            *asyncio.Task.all_tasks(loop=loop),
            loop=loop,
            return_exceptions=True)
        tasks.add_done_callback(lambda t: loop.stop())
        tasks.cancel()
