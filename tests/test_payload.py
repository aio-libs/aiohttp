import array
import json
from io import StringIO
from typing import Any, AsyncIterator, Iterator, Mapping

import pytest

from aiohttp import payload, web


@pytest.fixture
def registry() -> Iterator[payload.PayloadRegistry]:
    old = payload.PAYLOAD_REGISTRY
    reg = payload.PAYLOAD_REGISTRY = payload.PayloadRegistry()
    yield reg
    payload.PAYLOAD_REGISTRY = old


class Payload(payload.Payload):
    async def write(self, writer: Any) -> None:
        pass


def test_register_type(registry: Any) -> None:
    class TestProvider:
        pass

    payload.register_payload(Payload, TestProvider)
    p = payload.get_payload(TestProvider())
    assert isinstance(p, Payload)


def test_register_unsupported_order(registry: Any) -> None:
    class TestProvider:
        pass

    with pytest.raises(ValueError):
        payload.register_payload(Payload, TestProvider, order=object())  # type: ignore


def test_payload_ctor() -> None:
    p = Payload("test", encoding="utf-8", filename="test.txt")
    assert p._value == "test"
    assert p._encoding == "utf-8"
    assert p.size is None
    assert p.filename == "test.txt"
    assert p.content_type == "text/plain"


def test_payload_content_type() -> None:
    p = Payload("test", headers={"content-type": "application/json"})
    assert p.content_type == "application/json"


def test_bytes_payload_default_content_type() -> None:
    p = payload.BytesPayload(b"data")
    assert p.content_type == "application/octet-stream"


def test_bytes_payload_explicit_content_type() -> None:
    p = payload.BytesPayload(b"data", content_type="application/custom")
    assert p.content_type == "application/custom"


def test_bytes_payload_bad_type() -> None:
    with pytest.raises(TypeError):
        payload.BytesPayload(object())  # type: ignore


def test_bytes_payload_memoryview_correct_size() -> None:
    mv = memoryview(array.array("H", [1, 2, 3]))
    p = payload.BytesPayload(mv)
    assert p.size == 6


def test_string_payload() -> None:
    p = payload.StringPayload("test")
    assert p.encoding == "utf-8"
    assert p.content_type == "text/plain; charset=utf-8"

    p = payload.StringPayload("test", encoding="koi8-r")
    assert p.encoding == "koi8-r"
    assert p.content_type == "text/plain; charset=koi8-r"

    p = payload.StringPayload("test", content_type="text/plain; charset=koi8-r")
    assert p.encoding == "koi8-r"
    assert p.content_type == "text/plain; charset=koi8-r"


def test_string_io_payload() -> None:
    s = StringIO("ű" * 5000)
    p = payload.StringIOPayload(s)
    assert p.encoding == "utf-8"
    assert p.content_type == "text/plain; charset=utf-8"
    assert p.size == 10000


def test_async_iterable_payload_default_content_type() -> None:
    async def gen() -> AsyncIterator[bytes]:
        return
        yield b"abc"

    p = payload.AsyncIterablePayload(gen())
    assert p.content_type == "application/octet-stream"


def test_async_iterable_payload_explicit_content_type() -> None:
    async def gen() -> AsyncIterator[bytes]:
        return
        yield b"abc"

    p = payload.AsyncIterablePayload(gen(), content_type="application/custom")
    assert p.content_type == "application/custom"


def test_async_iterable_payload_not_async_iterable() -> None:

    with pytest.raises(TypeError):
        payload.AsyncIterablePayload(object())  # type: ignore


def test_decode_json_payload(registry: Any) -> None:
    j = {"foo": 42}
    p = payload.JsonPayload(j)
    assert json.dumps(j) == p.decode("utf-8")


async def test_json_payload(registry: Any, aiohttp_client: Any) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(body={"foo": 42})

    app = web.Application()
    payload.register_payload(payload.JsonPayload, Mapping)
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.get("/")
    body = json.loads(await resp.text())
    assert "application/json" == resp.content_type
    assert resp.status == 200
    assert "foo" in body
    assert body["foo"] == 42
