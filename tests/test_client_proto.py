import asyncio
from unittest import mock

from yarl import URL

from aiohttp import http
from aiohttp.client_exceptions import ClientOSError, ServerDisconnectedError
from aiohttp.client_proto import ResponseHandler
from aiohttp.client_reqrep import ClientResponse


@asyncio.coroutine
def test_oserror(loop):
    proto = ResponseHandler(loop=loop)
    transport = mock.Mock()
    proto.connection_made(transport)
    proto.connection_lost(OSError())

    assert proto.should_close
    assert isinstance(proto.exception(), ClientOSError)


@asyncio.coroutine
def test_pause_resume_on_error(loop):
    proto = ResponseHandler(loop=loop)

    proto.pause_reading()
    assert proto._reading_paused

    proto.resume_reading()
    assert not proto._reading_paused


@asyncio.coroutine
def test_client_proto_bad_message(loop):
    proto = ResponseHandler(loop=loop)
    transport = mock.Mock()
    proto.connection_made(transport)
    proto.set_response_params(read_until_eof=True)

    proto.data_received(b'HTTP\r\n\r\n')
    assert proto.should_close
    assert transport.close.called
    assert isinstance(proto.exception(), http.HttpProcessingError)


@asyncio.coroutine
def test_uncompleted_message(loop):
    proto = ResponseHandler(loop=loop)
    transport = mock.Mock()
    proto.connection_made(transport)
    proto.set_response_params(read_until_eof=True)

    proto.data_received(b'HTTP/1.1 301 Moved Permanently\r\n'
                        b'Location: http://python.org/')
    proto.connection_lost(None)

    exc = proto.exception()
    assert isinstance(exc, ServerDisconnectedError)
    assert exc.message.code == 301
    assert dict(exc.message.headers) == {'Location': 'http://python.org/'}


@asyncio.coroutine
def test_client_protocol_readuntil_eof(loop):
    proto = ResponseHandler(loop=loop)
    transport = mock.Mock()
    proto.connection_made(transport)
    conn = mock.Mock()
    conn.protocol = proto

    proto.data_received(b'HTTP/1.1 200 Ok\r\n\r\n')

    response = ClientResponse('get', URL('http://def-cl-resp.org'))
    response._post_init(loop, mock.Mock())
    yield from response.start(conn, read_until_eof=True)

    assert not response.content.is_eof()

    proto.data_received(b'0000')
    data = yield from response.content.readany()
    assert data == b'0000'

    proto.data_received(b'1111')
    data = yield from response.content.readany()
    assert data == b'1111'

    proto.connection_lost(None)
    assert response.content.is_eof()
