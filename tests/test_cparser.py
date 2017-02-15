from unittest import mock

import pytest
from multidict import CIMultiDict

from aiohttp import hdrs
from aiohttp._parser import HttpRequestParser


@pytest.fixture()
def loop():
    return mock.Mock()


@pytest.fixture()
def protocol():
    return mock.Mock()


@pytest.fixture()
def parser(protocol, loop):
    return HttpRequestParser(protocol, loop)


SIMPLE_REQUEST_1 = b'''POST /test.php?a=b+c HTTP/1.2
User-Agent: Fooo
Host: bar
Content-Length: 10

12345'''


def test_simple_post(parser):
    messages, upgraded, tail = parser.feed_data(SIMPLE_REQUEST_1)
    assert len(messages) == 1
    msg, payload = messages[0]

    assert not upgraded
    assert tail is None
    assert msg.method == hdrs.METH_POST
    assert msg.path == '/test.php?a=b+c'
    assert msg.headers == CIMultiDict([('User-Agent', 'Fooo'), ('Host', 'bar'),
                                       ('Content-Length', '10')])

    assert b''.join(payload._buffer) == b'12345'

    messages, upgraded, tail = parser.feed_data(b'67890')
    assert messages == ()
    assert b''.join(payload._buffer) == b'1234567890'
    assert payload.is_eof()


UPGRADE_REQUEST = b'''GET /demo HTTP/1.1
Host: example.com
Connection: Upgrade
Sec-WebSocket-Key2: 12998 5 Y3 1  .P00
Sec-WebSocket-Protocol: sample
Upgrade: WebSocket
Sec-WebSocket-Key1: 4 @1  46546xW%0l 1 5
Origin: http://example.com

Hot diggity dogg'''


def test_upgrade(parser):
    messages, upgraded, tail = parser.feed_data(UPGRADE_REQUEST)
    assert len(messages) == 1
    msg, payload = messages[0]

    assert msg.method == hdrs.METH_GET
    assert msg.path == '/demo'
    assert msg.upgrade

    assert upgraded
    assert tail == b'Hot diggity dogg'


CONNECT_REQUEST_1 = b'''CONNECT http://www.google.com HTTP/1.1
User-Agent: Fooo
Host: bar
Content-Length: 0

12345'''


def test_connect(parser):
    messages, upgraded, tail = parser.feed_data(CONNECT_REQUEST_1)
    assert len(messages) == 1
    msg, payload = messages[0]

    assert msg.method == hdrs.METH_CONNECT
    assert msg.path == 'http://www.google.com'
    assert msg.upgrade

    assert upgraded
    assert tail == b'12345'
