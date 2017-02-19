"""Tests for http/websocket.py"""

import base64
import hashlib
import os
from unittest import mock

import multidict
import pytest
from yarl import URL

from aiohttp import http, http_exceptions
from aiohttp.http import WS_KEY, do_handshake


@pytest.fixture()
def transport():
    return mock.Mock()


@pytest.fixture()
def message():
    headers = multidict.MultiDict()
    return http.RawRequestMessage(
        'GET', '/path', (1, 0), headers, [],
        True, None, True, False, URL('/path'))


def gen_ws_headers(protocols=''):
    key = base64.b64encode(os.urandom(16)).decode()
    hdrs = [('Upgrade', 'websocket'),
            ('Connection', 'upgrade'),
            ('Sec-Websocket-Version', '13'),
            ('Sec-Websocket-Key', key)]
    if protocols:
        hdrs += [('Sec-Websocket-Protocol', protocols)]
    return hdrs, key


def test_not_get(message, transport):
    with pytest.raises(http_exceptions.HttpProcessingError):
        do_handshake('POST', message.headers, transport)


def test_no_upgrade(message, transport):
    with pytest.raises(http_exceptions.HttpBadRequest):
        do_handshake(message.method, message.headers, transport)


def test_no_connection(message, transport):
    message.headers.extend([('Upgrade', 'websocket'),
                            ('Connection', 'keep-alive')])
    with pytest.raises(http_exceptions.HttpBadRequest):
        do_handshake(message.method, message.headers, transport)


def test_protocol_version(message, transport):
    message.headers.extend([('Upgrade', 'websocket'),
                            ('Connection', 'upgrade')])
    with pytest.raises(http_exceptions.HttpBadRequest):
        do_handshake(message.method, message.headers, transport)

    message.headers.extend([('Upgrade', 'websocket'),
                            ('Connection', 'upgrade'),
                            ('Sec-Websocket-Version', '1')])

    with pytest.raises(http_exceptions.HttpBadRequest):
        do_handshake(message.method, message.headers, transport)


def test_protocol_key(message, transport):
    message.headers.extend([('Upgrade', 'websocket'),
                            ('Connection', 'upgrade'),
                            ('Sec-Websocket-Version', '13')])
    with pytest.raises(http_exceptions.HttpBadRequest):
        do_handshake(message.method, message.headers, transport)

    message.headers.extend([('Upgrade', 'websocket'),
                            ('Connection', 'upgrade'),
                            ('Sec-Websocket-Version', '13'),
                            ('Sec-Websocket-Key', '123')])
    with pytest.raises(http_exceptions.HttpBadRequest):
        do_handshake(message.method, message.headers, transport)

    sec_key = base64.b64encode(os.urandom(2))
    message.headers.extend([('Upgrade', 'websocket'),
                            ('Connection', 'upgrade'),
                            ('Sec-Websocket-Version', '13'),
                            ('Sec-Websocket-Key', sec_key.decode())])
    with pytest.raises(http_exceptions.HttpBadRequest):
        do_handshake(message.method, message.headers, transport)


def test_handshake(message, transport):
    hdrs, sec_key = gen_ws_headers()

    message.headers.extend(hdrs)
    status, headers, parser, writer, protocol = do_handshake(
        message.method, message.headers, transport)
    assert status == 101
    assert protocol is None

    key = base64.b64encode(
        hashlib.sha1(sec_key.encode() + WS_KEY).digest())
    headers = dict(headers)
    assert headers['Sec-Websocket-Accept'] == key.decode()


def test_handshake_protocol(message, transport):
    '''Tests if one protocol is returned by do_handshake'''
    proto = 'chat'

    message.headers.extend(gen_ws_headers(proto)[0])
    _, resp_headers, _, _, protocol = do_handshake(
        message.method, message.headers, transport,
        protocols=[proto])

    assert protocol == proto

    # also test if we reply with the protocol
    resp_headers = dict(resp_headers)
    assert resp_headers['Sec-Websocket-Protocol'] == proto


def test_handshake_protocol_agreement(message, transport):
    '''Tests if the right protocol is selected given multiple'''
    best_proto = 'worse_proto'
    wanted_protos = ['best', 'chat', 'worse_proto']
    server_protos = 'worse_proto,chat'

    message.headers.extend(gen_ws_headers(server_protos)[0])
    _, resp_headers, _, _, protocol = do_handshake(
        message.method, message.headers, transport,
        protocols=wanted_protos)

    assert protocol == best_proto


def test_handshake_protocol_unsupported(log, message, transport):
    '''Tests if a protocol mismatch handshake warns and returns None'''
    proto = 'chat'
    message.headers.extend(gen_ws_headers('test')[0])

    with log('aiohttp.websocket') as ctx:
        _, _, _, _, protocol = do_handshake(
            message.method, message.headers, transport,
            protocols=[proto])

        assert protocol is None
    assert (ctx.records[-1].msg ==
            'Client protocols %r don’t overlap server-known ones %r')
