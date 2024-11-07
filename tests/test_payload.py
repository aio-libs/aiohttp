import array
from io import StringIO
from typing import AsyncIterator, Iterator

import pytest

from aiohttp import payload
from aiohttp.abc import AbstractStreamWriter


@pytest.fixture
def registry() -> Iterator[payload.PayloadRegistry]:
    old = payload.PAYLOAD_REGISTRY
    reg = payload.PAYLOAD_REGISTRY = payload.PayloadRegistry()
    yield reg
    payload.PAYLOAD_REGISTRY = old


class Payload(payload.Payload):
    def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
        assert False

    async def write(self, writer: AbstractStreamWriter) -> None:
        pass


def test_register_type(registry: payload.PayloadRegistry) -> None:
    class TestProvider:
        pass

    payload.register_payload(Payload, TestProvider)
    p = payload.get_payload(TestProvider())
    assert isinstance(p, Payload)


def test_register_unsupported_order(registry: payload.PayloadRegistry) -> None:
    class TestProvider:
        pass

    with pytest.raises(ValueError):
        payload.register_payload(
            Payload, TestProvider, order=object()  # type: ignore[arg-type]
        )


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
        payload.BytesPayload(object())  # type: ignore[arg-type]


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
        yield b"abc"  # type: ignore[unreachable]  # pragma: no cover

    p = payload.AsyncIterablePayload(gen())
    assert p.content_type == "application/octet-stream"


def test_async_iterable_payload_explicit_content_type() -> None:
    async def gen() -> AsyncIterator[bytes]:
        return
        yield b"abc"  # type: ignore[unreachable]  # pragma: no cover

    p = payload.AsyncIterablePayload(gen(), content_type="application/custom")
    assert p.content_type == "application/custom"


def test_async_iterable_payload_not_async_iterable() -> None:
    with pytest.raises(TypeError):
        payload.AsyncIterablePayload(object())  # type: ignore[arg-type]
