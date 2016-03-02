"""Tests for http/websocket.py"""

import base64
import hashlib
import os
import pytest

from aiohttp import websocket, multidict, protocol, errors
from unittest import mock


@pytest.fixture()
def transport():
    return mock.Mock()


@pytest.fixture()
def message():
    headers = multidict.MultiDict()
    return protocol.RawRequestMessage(
        'GET', '/path', (1, 0), headers, [], True, None)


def gen_ws_headers(protocols=''):
    key = base64.b64encode(os.urandom(16)).decode()
    hdrs = [('UPGRADE', 'websocket'),
            ('CONNECTION', 'upgrade'),
            ('SEC-WEBSOCKET-VERSION', '13'),
            ('SEC-WEBSOCKET-KEY', key)]
    if protocols:
        hdrs += [('SEC-WEBSOCKET-PROTOCOL', protocols)]
    return hdrs, key


def test_not_get(message, transport):
    with pytest.raises(errors.HttpProcessingError):
        websocket.do_handshake('POST', message.headers, transport)


def test_no_upgrade(message, transport):
    with pytest.raises(errors.HttpBadRequest):
        websocket.do_handshake(message.method, message.headers, transport)


def test_no_connection(message, transport):
    message.headers.extend([('UPGRADE', 'websocket'),
                            ('CONNECTION', 'keep-alive')])
    with pytest.raises(errors.HttpBadRequest):
        websocket.do_handshake(message.method, message.headers, transport)


def test_protocol_version(message, transport):
    message.headers.extend([('UPGRADE', 'websocket'),
                            ('CONNECTION', 'upgrade')])
    with pytest.raises(errors.HttpBadRequest):
        websocket.do_handshake(message.method, message.headers, transport)

    message.headers.extend([('UPGRADE', 'websocket'),
                            ('CONNECTION', 'upgrade'),
                            ('SEC-WEBSOCKET-VERSION', '1')])

    with pytest.raises(errors.HttpBadRequest):
        websocket.do_handshake(message.method, message.headers, transport)


def test_protocol_key(message, transport):
    message.headers.extend([('UPGRADE', 'websocket'),
                            ('CONNECTION', 'upgrade'),
                            ('SEC-WEBSOCKET-VERSION', '13')])
    with pytest.raises(errors.HttpBadRequest):
        websocket.do_handshake(message.method, message.headers, transport)

    message.headers.extend([('UPGRADE', 'websocket'),
                            ('CONNECTION', 'upgrade'),
                            ('SEC-WEBSOCKET-VERSION', '13'),
                            ('SEC-WEBSOCKET-KEY', '123')])
    with pytest.raises(errors.HttpBadRequest):
        websocket.do_handshake(message.method, message.headers, transport)

    sec_key = base64.b64encode(os.urandom(2))
    message.headers.extend([('UPGRADE', 'websocket'),
                            ('CONNECTION', 'upgrade'),
                            ('SEC-WEBSOCKET-VERSION', '13'),
                            ('SEC-WEBSOCKET-KEY', sec_key.decode())])
    with pytest.raises(errors.HttpBadRequest):
        websocket.do_handshake(message.method, message.headers, transport)


def test_handshake(message, transport):
    hdrs, sec_key = gen_ws_headers()

    message.headers.extend(hdrs)
    status, headers, parser, writer, protocol = websocket.do_handshake(
        message.method, message.headers, transport)
    assert status == 101
    assert protocol is None

    key = base64.b64encode(
        hashlib.sha1(sec_key.encode() + websocket.WS_KEY).digest())
    headers = dict(headers)
    assert headers['SEC-WEBSOCKET-ACCEPT'] == key.decode()


def test_handshake_protocol(message, transport):
    '''Tests if one protocol is returned by do_handshake'''
    proto = 'chat'

    message.headers.extend(gen_ws_headers(proto)[0])
    _, resp_headers, _, _, protocol = websocket.do_handshake(
        message.method, message.headers, transport,
        protocols=[proto])

    assert protocol == proto

    # also test if we reply with the protocol
    resp_headers = dict(resp_headers)
    assert resp_headers['SEC-WEBSOCKET-PROTOCOL'] == proto


def test_handshake_protocol_agreement(message, transport):
    '''Tests if the right protocol is selected given multiple'''
    best_proto = 'worse_proto'
    wanted_protos = ['best', 'chat', 'worse_proto']
    server_protos = 'worse_proto,chat'

    message.headers.extend(gen_ws_headers(server_protos)[0])
    _, resp_headers, _, _, protocol = websocket.do_handshake(
        message.method, message.headers, transport,
        protocols=wanted_protos)

    assert protocol == best_proto


def test_handshake_protocol_unsupported(log, message, transport):
    '''Tests if a protocol mismatch handshake warns and returns None'''
    proto = 'chat'
    message.headers.extend(gen_ws_headers('test')[0])

    with log('aiohttp.websocket') as ctx:
        _, _, _, _, protocol = websocket.do_handshake(
            message.method, message.headers, transport,
            protocols=[proto])

        assert protocol is None
    assert (ctx.records[-1].msg ==
            'Client protocols %r don’t overlap server-known ones %r')
