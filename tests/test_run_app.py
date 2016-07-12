import asyncio
import ssl

from unittest import mock
from aiohttp import web


def test_run_app_http(loop):
    loop = mock.Mock(spec=asyncio.AbstractEventLoop, wrap=loop)
    loop.call_later(0.01, loop.stop)

    app = web.Application(loop=loop)

    web.run_app(app)

    loop.close.assert_called_with()
    loop.create_server.assert_called_with(mock.ANY, '0.0.0.0', 8080,
                                          ssl=None, backlog=128)


def test_run_app_https(loop):
    loop = mock.Mock(spec=asyncio.AbstractEventLoop, wrap=loop)
    loop.call_later(0.01, loop.stop)

    app = web.Application(loop=loop)

    ssl_context = ssl.create_default_context()

    web.run_app(app, ssl_context=ssl_context)

    loop.close.assert_called_with()
    loop.create_server.assert_called_with(mock.ANY, '0.0.0.0', 8443,
                                          ssl=ssl_context, backlog=128)


def test_run_app_nondefault_host_port(loop, unused_port):
    port = unused_port
    host = 'localhost'

    loop = mock.Mock(spec=asyncio.AbstractEventLoop, wrap=loop)
    loop.call_later(0.01, loop.stop)

    app = web.Application(loop=loop)

    web.run_app(app, host=host, port=port)

    loop.create_server.assert_called_with(mock.ANY, host, port,
                                          ssl=None, backlog=128)


def test_run_app_custom_backlog(loop):
    loop = mock.Mock(spec=asyncio.AbstractEventLoop, wrap=loop)
    loop.call_later(0.01, loop.stop)

    app = web.Application(loop=loop)

    web.run_app(app, backlog=10)

    loop.close.assert_called_with()
    loop.create_server.assert_called_with(mock.ANY, '0.0.0.0', 8080,
                                          ssl=None, backlog=10)
