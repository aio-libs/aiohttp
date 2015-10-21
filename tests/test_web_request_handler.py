import pytest

from aiohttp import web
from unittest import mock


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


@pytest.mark.run_loop
def test_finish_connection_no_timeout(loop):
    app = web.Application(loop=loop)
    manager = app.make_handler()

    handler = mock.Mock()
    transport = mock.Mock()
    manager.connection_made(handler, transport)

    yield from manager.finish_connections()

    manager.connection_lost(handler, None)
    assert manager.connections == []
    handler.closing.assert_called_with(timeout=None)
    transport.close.assert_called_with()


@pytest.mark.run_loop
def test_finish_connection_timeout(loop):
    app = web.Application(loop=loop)
    manager = app.make_handler()

    handler = mock.Mock()
    transport = mock.Mock()
    manager.connection_made(handler, transport)

    yield from manager.finish_connections(timeout=0.1)

    manager.connection_lost(handler, None)
    assert manager.connections == []
    handler.closing.assert_called_with(timeout=0.09)
    transport.close.assert_called_with()
