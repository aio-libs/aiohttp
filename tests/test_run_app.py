import socket
import ssl

from io import StringIO
from unittest import mock

import pytest

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


@pytest.mark.skipif(not hasattr(socket, 'AF_UNIX'),
                    reason="UNIX sockets are not supported")
def test_run_app_http_unix_socket(loop, mocker, shorttmpdir):
    mocker.spy(loop, 'create_unix_server')
    loop.call_later(0.05, loop.stop)

    app = web.Application(loop=loop)
    mocker.spy(app, 'startup')

    sock_path = str(shorttmpdir.join('socket.sock'))
    printed = StringIO()
    web.run_app(app, path=sock_path, print=printed.write)

    assert loop.is_closed()
    loop.create_unix_server.assert_called_with(mock.ANY, sock_path,
                                               ssl=None, backlog=128)
    app.startup.assert_called_once_with()
    assert "http://unix:{}:".format(sock_path) in printed.getvalue()


@pytest.mark.skipif(not hasattr(socket, 'AF_UNIX'),
                    reason="UNIX sockets are not supported")
def test_run_app_https_unix_socket(loop, mocker, shorttmpdir):
    mocker.spy(loop, 'create_unix_server')
    loop.call_later(0.05, loop.stop)

    app = web.Application(loop=loop)
    mocker.spy(app, 'startup')

    sock_path = str(shorttmpdir.join('socket.sock'))
    printed = StringIO()
    ssl_context = ssl.create_default_context()
    web.run_app(app, path=sock_path, ssl_context=ssl_context,
                print=printed.write)

    assert loop.is_closed()
    loop.create_unix_server.assert_called_with(mock.ANY, sock_path,
                                               ssl=ssl_context, backlog=128)
    app.startup.assert_called_once_with()
    assert "https://unix:{}:".format(sock_path) in printed.getvalue()
