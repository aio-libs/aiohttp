import array
import io
import pathlib
from typing import Any, AsyncIterator, Iterator
from unittest import mock

import pytest

from aiohttp import payload


@pytest.fixture
def registry() -> Iterator[payload.PayloadRegistry]:
    old = payload.PAYLOAD_REGISTRY
    reg = payload.PAYLOAD_REGISTRY = payload.PayloadRegistry()
    yield reg
    payload.PAYLOAD_REGISTRY = old


class Payload(payload.Payload):
    def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
        assert False

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
    s = io.StringIO("ű" * 5000)
    p = payload.StringIOPayload(s)
    assert p.encoding == "utf-8"
    assert p.content_type == "text/plain; charset=utf-8"
    assert p.size == 10000


def test_text_io_payload() -> None:
    filepath = pathlib.Path(__file__).parent / "sample.txt"
    filesize = filepath.stat().st_size
    with filepath.open("r") as f:
        p = payload.TextIOPayload(f)
        assert p.encoding == "utf-8"
        assert p.content_type == "text/plain; charset=utf-8"
        assert p.size == filesize
        assert not f.closed


def test_bytes_io_payload() -> None:
    filepath = pathlib.Path(__file__).parent / "sample.txt"
    filesize = filepath.stat().st_size
    with filepath.open("rb") as f:
        p = payload.BytesIOPayload(f)
        assert p.size == filesize
        assert not f.closed


def test_buffered_reader_payload() -> None:
    filepath = pathlib.Path(__file__).parent / "sample.txt"
    filesize = filepath.stat().st_size
    with filepath.open("rb") as f:
        p = payload.BufferedReaderPayload(f)
        assert p.size == filesize
        assert not f.closed


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
        payload.AsyncIterablePayload(object())  # type: ignore[arg-type]


async def write_mock(*args, **kwargs):
    pass


async def test_string_io_payload_write() -> None:
    content = "ű" * 5000

    s = io.StringIO(content)
    p = payload.StringIOPayload(s)

    with mock.patch("aiohttp.http_writer.StreamWriter") as mock_obj:
        instance = mock_obj.return_value
        instance.write = mock.Mock(write_mock)

        await p.write(instance)
        instance.write.assert_called_once_with(content.encode("utf-8"))

        instance.write.reset_mock()

        await p.write(instance)
        instance.write.assert_called_once_with(content.encode("utf-8"))


async def test_text_io_payload_write() -> None:
    filepath = pathlib.Path(__file__).parent / "sample.txt"
    with filepath.open("r") as f:
        content = f.read()
        f.seek(0)

        p = payload.TextIOPayload(f)

        with mock.patch("aiohttp.http_writer.StreamWriter") as mock_obj:
            instance = mock_obj.return_value
            instance.write = mock.Mock(write_mock)

            await p.write(instance)
            instance.write.assert_called_once_with(content.encode("utf-8"))  # 1 chunk

            instance.write.reset_mock()

            await p.write(instance)
            instance.write.assert_called_once_with(content.encode("utf-8"))  # 1 chunk


async def test_bytes_io_payload_write() -> None:
    filepath = pathlib.Path(__file__).parent / "sample.txt"
    with filepath.open("rb") as f:
        content = f.read()
        with io.BytesIO(content) as bf:

            p = payload.BytesIOPayload(bf)

            with mock.patch("aiohttp.http_writer.StreamWriter") as mock_obj:
                instance = mock_obj.return_value
                instance.write = mock.Mock(write_mock)

                await p.write(instance)
                instance.write.assert_called_once_with(content)  # 1 chunk

                instance.write.reset_mock()

                await p.write(instance)
                instance.write.assert_called_once_with(content)  # 1 chunk


async def test_buffered_reader_payload_write() -> None:
    filepath = pathlib.Path(__file__).parent / "sample.txt"
    with filepath.open("rb") as f:
        content = f.read()
        f.seek(0)

        p = payload.BufferedReaderPayload(f)

        with mock.patch("aiohttp.http_writer.StreamWriter") as mock_obj:
            instance = mock_obj.return_value
            instance.write = mock.Mock(write_mock)

            await p.write(instance)
            instance.write.assert_called_once_with(content)  # 1 chunk

            instance.write.reset_mock()

            await p.write(instance)
            instance.write.assert_called_once_with(content)  # 1 chunk
