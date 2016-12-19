import asyncio
import pathlib
import socket
import ssl

import aiohttp
from aiohttp import web
from aiohttp.resolver import DefaultResolver
from aiohttp.test_utils import unused_port


def http_method(method, path):
    def wrapper(func):
        func.__method__ = method
        func.__path__ = path
        return func
    return wrapper


def head(path):
    return http_method('HEAD', path)


def get(path):
    return http_method('GET', path)


def delete(path):
    return http_method('DELETE', path)


def options(path):
    return http_method('OPTIONS', path)


def patch(path):
    return http_method('PATCH', path)


def post(path):
    return http_method('POST', path)


def put(path):
    return http_method('PUT', path)


def trace(path):
    return http_method('TRACE', path)


class FakeResolver:
    _LOCAL_HOST = {0: '127.0.0.1',
                   socket.AF_INET: '127.0.0.1',
                   socket.AF_INET6: '::1'}

    def __init__(self, fakes, *, loop):
        """fakes -- dns -> port dict"""
        self._fakes = fakes
        self._resolver = DefaultResolver(loop=loop)

    async def resolve(self, host, port=0, family=socket.AF_INET):
        fake_port = self._fakes.get(host)
        if fake_port is not None:
            return [{'hostname': host,
                     'host': self._LOCAL_HOST[family], 'port': fake_port,
                     'family': family, 'proto': 0,
                     'flags': socket.AI_NUMERICHOST}]
        else:
            return await self._resolver.resolve(host, port, family)


class FakeFacebook:

    def __init__(self, *, loop):
        self.loop = loop
        self.app = web.Application(loop=loop)
        for name in dir(self.__class__):
            func = getattr(self.__class__, name)
            if hasattr(func, '__method__'):
                self.app.router.add_route(func.__method__,
                                          func.__path__,
                                          getattr(self, name))
        self.handler = None
        self.server = None
        here = pathlib.Path(__file__)
        ssl_cert = here.parent / 'server.crt'
        ssl_key = here.parent / 'server.key'
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.load_cert_chain(str(ssl_cert), str(ssl_key))

    async def start(self):
        port = unused_port()
        self.handler = self.app.make_handler()
        self.server = await self.loop.create_server(self.handler,
                                                    '127.0.0.1', port,
                                                    ssl=self.ssl_context)
        return {'graph.facebook.com': port}

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()
        await self.app.shutdown()
        await self.handler.shutdown()
        await self.app.cleanup()

    @get('/v2.7/me')
    async def on_me(self, request):
        return web.json_response({
            "name": "John Doe",
            "id": "12345678901234567"
        })

    @get('/v2.7/me/friends')
    async def on_my_friends(self, request):
        return web.json_response({
            "data": [
                {
                    "name": "Bill Doe",
                    "id": "233242342342"
                },
                {
                    "name": "Mary Doe",
                    "id": "2342342343222"
                },
                {
                    "name": "Alex Smith",
                    "id": "234234234344"
                },
            ],
            "paging": {
                "cursors": {
                    "before": "QVFIUjRtc2c5NEl0ajN",
                    "after": "QVFIUlpFQWM0TmVuaDRad0dt",
                },
                "next": ("https://graph.facebook.com/v2.7/12345678901234567/"
                         "friends?access_token=EAACEdEose0cB")
            },
            "summary": {
                "total_count": 3
            }})


async def main(loop):
    token = "ER34gsSGGS34XCBKd7u"

    fake_facebook = FakeFacebook(loop=loop)
    info = await fake_facebook.start()
    resolver = FakeResolver(info, loop=loop)
    connector = aiohttp.TCPConnector(loop=loop, resolver=resolver,
                                     verify_ssl=False)

    async with aiohttp.ClientSession(connector=connector,
                                     loop=loop) as session:
        async with session.get('https://graph.facebook.com/v2.7/me',
                               params={'access_token': token}) as resp:
            print(await resp.json())

        async with session.get('https://graph.facebook.com/v2.7/me/friends',
                               params={'access_token': token}) as resp:
            print(await resp.json())

    await fake_facebook.stop()


loop = asyncio.get_event_loop()
loop.run_until_complete(main(loop))
