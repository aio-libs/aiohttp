import asyncio
from unittest import mock

from aiohttp import web
from aiohttp.test_utils import make_mocked_coro


def test_repr(loop):
    app = web.Application(loop=loop)
    manager = app.make_handler()
    handler = manager()

    assert '<RequestHandler none:none disconnected>' == repr(handler)

    handler.transport = object()
    handler._meth = 'GET'
    handler._path = '/index.html'
    assert '<RequestHandler GET:/index.html connected>' == repr(handler)


def test_connections(loop):
    app = web.Application(loop=loop)
    manager = app.make_handler()
    assert manager.connections == []

    handler = object()
    transport = object()
    manager.connection_made(handler, transport)
    assert manager.connections == [handler]

    manager.connection_lost(handler, None)
    assert manager.connections == []


@asyncio.coroutine
def test_finish_connection_no_timeout(loop):
    app = web.Application(loop=loop)
    manager = app.make_handler()

    handler = mock.Mock()
    handler.shutdown = make_mocked_coro(mock.Mock())
    transport = mock.Mock()
    manager.connection_made(handler, transport)

    yield from manager.finish_connections()

    manager.connection_lost(handler, None)
    assert manager.connections == []
    handler.shutdown.assert_called_with(None)


@asyncio.coroutine
def test_finish_connection_timeout(loop):
    app = web.Application(loop=loop)
    manager = app.make_handler()

    handler = mock.Mock()
    handler.shutdown = make_mocked_coro(mock.Mock())
    transport = mock.Mock()
    manager.connection_made(handler, transport)

    yield from manager.finish_connections(timeout=0.1)

    manager.connection_lost(handler, None)
    assert manager.connections == []
    handler.shutdown.assert_called_with(0.1)


def test_secure_proxy_ssl_header_default(loop):
    app = web.Application(loop=loop)
    manager = app.make_handler()
    assert manager.secure_proxy_ssl_header is None
