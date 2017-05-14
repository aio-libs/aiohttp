import asyncio

import pytest

from aiohttp import payload


@pytest.fixture
def registry():
    old = payload.PAYLOAD_REGISTRY
    reg = payload.PAYLOAD_REGISTRY = payload.PayloadRegistry()
    yield reg
    payload.PAYLOAD_REGISTRY = old


class Payload(payload.Payload):

    @asyncio.coroutine
    def write(self, writer):
        pass


def test_register_type(registry):
    class TestProvider:
        pass

    payload.register_payload(Payload, TestProvider)
    p = payload.get_payload(TestProvider())
    assert isinstance(p, Payload)


def test_payload_ctor():
    p = Payload('test', encoding='utf-8', filename='test.txt')
    assert p._value == 'test'
    assert p._encoding == 'utf-8'
    assert p.size is None
    assert p.filename == 'test.txt'
    assert p.content_type == 'text/plain'


def test_payload_content_type():
    p = Payload('test', headers={'content-type': 'application/json'})
    assert p.content_type == 'application/json'


def test_string_payload():
    p = payload.StringPayload('test')
    assert p.encoding == 'utf-8'
    assert p.content_type == 'text/plain; charset=utf-8'

    p = payload.StringPayload('test', encoding='koi8-r')
    assert p.encoding == 'koi8-r'
    assert p.content_type == 'text/plain; charset=koi8-r'

    p = payload.StringPayload(
        'test', content_type='text/plain; charset=koi8-r')
    assert p.encoding == 'koi8-r'
    assert p.content_type == 'text/plain; charset=koi8-r'
