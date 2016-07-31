from unittest import mock

from aiohttp import parsers


def test_connection_made(loop):
    tr = mock.Mock()

    proto = parsers.StreamProtocol(loop=loop)
    assert proto.transport is None

    proto.connection_made(tr)
    assert proto.transport is tr


def test_connection_lost(loop):
    proto = parsers.StreamProtocol(loop=loop)
    proto.connection_made(mock.Mock())
    proto.connection_lost(None)
    assert proto.transport is None
    assert proto.writer is None
    assert proto.reader._eof


def test_connection_lost_exc(loop):
    proto = parsers.StreamProtocol(loop=loop)
    proto.connection_made(mock.Mock())

    exc = ValueError()
    proto.connection_lost(exc)
    assert proto.reader.exception() is exc


def test_data_received(loop):
    proto = parsers.StreamProtocol(loop=loop)
    proto.connection_made(mock.Mock())
    proto.reader = mock.Mock()

    proto.data_received(b'data')
    proto.reader.feed_data.assert_called_with(b'data')
