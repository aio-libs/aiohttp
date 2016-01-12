import asyncio
import pytest
import ssl

from unittest import mock
from aiohttp import web


def test_run_app_http(loop):
    loop = mock.Mock(spec=asyncio.AbstractEventLoop, wrap=loop)
    loop.call_later(0.01, loop.stop)
    app = mock.Mock(wrap=web.Application(loop=loop))

    web.run_app(app, loop=loop)

    app.make_handler.assert_called_with()

    loop.close.assert_called_with()
    app.finish.assert_called_with()
    app.shutdown.assert_called_with()

    loop.create_server.assert_called_with(mock.ANY, '0.0.0.0', 8080, ssl=None)


def test_run_app_https(loop):
    loop = mock.Mock(spec=asyncio.AbstractEventLoop, wrap=loop)
    loop.call_later(0.01, loop.stop)

    app = mock.Mock(wrap=web.Application(loop=loop))

    ssl_context = ssl.create_default_context()

    web.run_app(app, ssl_context=ssl_context, loop=loop)

    app.make_handler.assert_called_with()

    loop.close.assert_called_with()
    app.finish.assert_called_with()
    app.shutdown.assert_called_with()

    loop.create_server.assert_called_with(mock.ANY, '0.0.0.0', 8443,
                                          ssl=ssl_context)


def test_run_app_nondefault_host_port(loop, unused_port):
    port = unused_port()
    host = 'localhost'

    loop = mock.Mock(spec=asyncio.AbstractEventLoop, wrap=loop)
    loop.call_later(0.01, loop.stop)

    app = mock.Mock(wrap=web.Application(loop=loop))

    web.run_app(app, host=host, port=port, loop=loop)

    loop.create_server.assert_called_with(mock.ANY, host, port, ssl=None)


def test_run_app_default_eventloop(loop):
    asyncio.set_event_loop(loop)
    loop.call_later(0.01, loop.stop)

    web.run_app(web.Application())
    # don't analise a return value, jut make sure the call was successful


def test_run_app_exit_with_exception(loop):
    loop = mock.Mock(spec=asyncio.AbstractEventLoop, wrap=loop)

    loop.run_forever.return_value = None  # to disable wrapping
    loop.run_forever.side_effect = exc = RuntimeError()

    app = mock.Mock(wrap=web.Application(loop=loop))

    with pytest.raises(RuntimeError) as ctx:
        web.run_app(app, loop=loop)

    assert ctx.value is exc

    assert not loop.close.called
    app.finish.assert_called_with()
    app.shutdown.assert_called_with()
