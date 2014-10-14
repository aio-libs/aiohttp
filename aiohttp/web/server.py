import asyncio

from aiohttp.server import ServerHttpProtocol

from .request import Request


class RequestHandler(ServerHttpProtocol):

    def __init__(self, hostname, router, **kwargs):
        super().__init__(**kwargs)
        self._hostname = hostname
        self._router = router

    @asyncio.coroutine
    def handle_request(self, message, payload):
        match = self._router.match()
        request = Request(self._hostname, message, payload, loop=self._loop)


class Server:

    def __init__(self, *, hostname, loop=None, **kwargs):
        self._hostname = hostname
        self._kwargs = kwargs
        if loop is None:
            loop = asyncio.get_event_loop()

    def make_handler(self):
        return RequestHandler(self._hostname, self._router, **self._kwargs)
