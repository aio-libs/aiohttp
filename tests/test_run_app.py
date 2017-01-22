import ssl
from unittest import mock

from aiohttp import web


def test_run_app_http(loop, mocker):
    mocker.spy(loop, 'create_server')
    loop.call_later(0.05, loop.stop)

    app = web.Application(loop=loop)
    mocker.spy(app, 'startup')

    web.run_app(app, print=lambda *args: None)

    assert loop.is_closed()
    loop.create_server.assert_called_with(mock.ANY, '0.0.0.0', 8080,
                                          ssl=None, backlog=128)
    app.startup.assert_called_once_with()


def test_run_app_multi_bind():
    app = mock.Mock()

    web.run_app(app, host=('0.0.0.0', '127.0.0.1'), print=lambda *args: None)

    app.loop.create_server.assert_called_with(
        mock.ANY, ('0.0.0.0', '127.0.0.1'), 8080, ssl=None, backlog=128)


def test_run_app_http_access_format(loop, mocker):
    mocker.spy(loop, 'create_server')
    loop.call_later(0.05, loop.stop)

    app = web.Application(loop=loop)
    mocker.spy(app, 'startup')

    web.run_app(app, print=lambda *args: None, access_log_format='%a')

    assert loop.is_closed()
    cs = loop.create_server
    cs.assert_called_with(mock.ANY, '0.0.0.0', 8080, ssl=None, backlog=128)
    assert cs.call_args[0][0]._kwargs['access_log_format'] == '%a'
    app.startup.assert_called_once_with()


def test_run_app_https(loop, mocker):
    mocker.spy(loop, 'create_server')
    loop.call_later(0.05, loop.stop)

    app = web.Application(loop=loop)
    mocker.spy(app, 'startup')

    ssl_context = ssl.create_default_context()

    web.run_app(app, ssl_context=ssl_context, print=lambda *args: None)

    assert loop.is_closed()
    loop.create_server.assert_called_with(mock.ANY, '0.0.0.0', 8443,
                                          ssl=ssl_context, backlog=128)
    app.startup.assert_called_once_with()


def test_run_app_nondefault_host_port(loop, unused_port, mocker):
    port = unused_port()
    host = 'localhost'

    mocker.spy(loop, 'create_server')
    loop.call_later(0.05, loop.stop)

    app = web.Application(loop=loop)
    mocker.spy(app, 'startup')

    web.run_app(app, host=host, port=port, print=lambda *args: None)

    assert loop.is_closed()
    loop.create_server.assert_called_with(mock.ANY, host, port,
                                          ssl=None, backlog=128)
    app.startup.assert_called_once_with()


def test_run_app_custom_backlog(loop, mocker):
    mocker.spy(loop, 'create_server')
    loop.call_later(0.05, loop.stop)

    app = web.Application(loop=loop)
    mocker.spy(app, 'startup')

    web.run_app(app, backlog=10, print=lambda *args: None)

    assert loop.is_closed()
    loop.create_server.assert_called_with(mock.ANY, '0.0.0.0', 8080,
                                          ssl=None, backlog=10)
    app.startup.assert_called_once_with()
