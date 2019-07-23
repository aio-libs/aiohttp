from unittest import mock

from yarl import URL

from aiohttp import http
from aiohttp.client_exceptions import ClientOSError, ServerDisconnectedError
from aiohttp.client_proto import ResponseHandler
from aiohttp.client_reqrep import ClientResponse
from aiohttp.helpers import TimerNoop


async def test_oserror(loop) -> None:
    proto = ResponseHandler(loop=loop)
    transport = mock.Mock()
    proto.connection_made(transport)
    proto.connection_lost(OSError())

    assert proto.should_close
    assert isinstance(proto.exception(), ClientOSError)


async def test_pause_resume_on_error(loop) -> None:
    proto = ResponseHandler(loop=loop)
    transport = mock.Mock()
    proto.connection_made(transport)

    proto.pause_reading()
    assert proto._reading_paused

    proto.resume_reading()
    assert not proto._reading_paused


async def test_client_proto_bad_message(loop) -> None:
    proto = ResponseHandler(loop=loop)
    transport = mock.Mock()
    proto.connection_made(transport)
    proto.set_response_params()

    proto.data_received(b'HTTP\r\n\r\n')
    assert proto.should_close
    assert transport.close.called
    assert isinstance(proto.exception(), http.HttpProcessingError)


async def test_uncompleted_message(loop) -> None:
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


async def test_client_protocol_readuntil_eof(loop) -> None:
    proto = ResponseHandler(loop=loop)
    transport = mock.Mock()
    proto.connection_made(transport)
    conn = mock.Mock()
    conn.protocol = proto

    proto.data_received(b'HTTP/1.1 200 Ok\r\n\r\n')

    response = ClientResponse('get', URL('http://def-cl-resp.org'),
                              writer=mock.Mock(),
                              continue100=None,
                              timer=TimerNoop(),
                              request_info=mock.Mock(),
                              traces=[],
                              loop=loop,
                              session=mock.Mock())
    proto.set_response_params(read_until_eof=True)
    await response.start(conn)

    assert not response.content.is_eof()

    proto.data_received(b'0000')
    data = await response.content.readany()
    assert data == b'0000'

    proto.data_received(b'1111')
    data = await response.content.readany()
    assert data == b'1111'

    proto.connection_lost(None)
    assert response.content.is_eof()


async def test_empty_data(loop) -> None:
    proto = ResponseHandler(loop=loop)
    proto.data_received(b'')

    # do nothing


async def test_schedule_timeout(loop) -> None:
    proto = ResponseHandler(loop=loop)
    proto.set_response_params(read_timeout=1)
    assert proto._read_timeout_handle is not None


async def test_drop_timeout(loop) -> None:
    proto = ResponseHandler(loop=loop)
    proto.set_response_params(read_timeout=1)
    assert proto._read_timeout_handle is not None
    proto._drop_timeout()
    assert proto._read_timeout_handle is None


async def test_reschedule_timeout(loop) -> None:
    proto = ResponseHandler(loop=loop)
    proto.set_response_params(read_timeout=1)
    assert proto._read_timeout_handle is not None
    h = proto._read_timeout_handle
    proto._reschedule_timeout()
    assert proto._read_timeout_handle is not None
    assert proto._read_timeout_handle is not h


async def test_eof_received(loop) -> None:
    proto = ResponseHandler(loop=loop)
    proto.set_response_params(read_timeout=1)
    assert proto._read_timeout_handle is not None
    proto.eof_received()
    assert proto._read_timeout_handle is None


async def test_parse_only_one_payload_per_client_response(loop) -> None:
    proto = ResponseHandler(loop=loop)
    transport = mock.Mock()
    proto.connection_made(transport)
    conn = mock.Mock()
    conn.protocol = proto

    proto.data_received(b'HTTP/1.1 200 Ok\r\nContent-Length: 20\r\n\r\nbody with content...')
    proto.data_received(b'HTTP/1.1 200 Ok\r\nContent-Length: 5\r\n\r\n11111')
    proto.data_received(b'HTTP/1.1 200 Ok\r\nContent-Length: 5\r\n\r\n22222')
    proto.data_received(b'HTTP/1.1 200 Ok\r\nContent-Length: 5\r\n\r\n33333')

    response = ClientResponse('get', URL('http://example.com/'),
                              writer=mock.Mock(),
                              continue100=None,
                              timer=TimerNoop(),
                              request_info=mock.Mock(),
                              traces=[],
                              loop=loop,
                              session=mock.Mock())
    proto.set_response_params(read_until_eof=True)
    await response.start(conn)
    proto.data_received(b'HTTP/1.1 200 Ok\r\nContent-Length: 5\r\n\r\n44444')

    data = await response.content.readany()

    assert data == b'body with content...'
    assert len(proto._buffer) == 0


async def test_allow_two_payloads_when_first_is_100_continue(loop) -> None:
    proto = ResponseHandler(loop=loop)
    transport = mock.Mock()
    proto.connection_made(transport)
    conn = mock.Mock()
    conn.protocol = proto

    proto.data_received(b'HTTP/1.1 100 Continue\r\n\r\n')
    proto.data_received(b'HTTP/1.1 200 Ok\r\nContent-Length: 5\r\n\r\n12345')

    response = ClientResponse('get', URL('http://example.com/'),
                              writer=mock.Mock(),
                              continue100=loop.create_future(),
                              timer=TimerNoop(),
                              request_info=mock.Mock(),
                              traces=[],
                              loop=loop,
                              session=mock.Mock())
    proto.set_response_params(read_until_eof=True)
    await response.start(conn)

    data = await response.content.readany()

    assert data == b'12345'
    assert response.status == 200
