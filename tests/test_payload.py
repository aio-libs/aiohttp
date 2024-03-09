import array
from io import StringIO
from typing import Any, AsyncIterator, Iterator

import pytest

from aiohttp import payload


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


def test_send_file_payload_content_type() -> None:
    p = payload.SendFilePayload(payload.SendFile("/sendfile"))
    assert p.content_type == "application/octet-stream"


def test_send_file_payload_not_send_file() -> None:
    with pytest.raises(TypeError):
        payload.SendFilePayload(object())


async def test_send_file_payload_writer() -> None:
    with pytest.raises(TypeError):
        p = payload.SendFilePayload(payload.SendFile("/sendfile"))
        await p.write(object())


def test_send_file_default_chunk_size() -> None:
    sf = payload.SendFile("/sendfile")
    assert sf.chunk_size == 0x7FFF_FFFF


def test_send_file_zero_chunk_size() -> None:
    sf = payload.SendFile("/sendfile", 0)
    assert sf.chunk_size == 0x7FFF_FFFF


def test_send_file_negative_chunk_size() -> None:
    sf = payload.SendFile("/sendfile", -100)
    assert sf.chunk_size == 0x7FFF_FFFF


def test_send_file_positive_chunk_size() -> None:
    sf = payload.SendFile("/sendfile", 1024)
    assert sf.chunk_size == 1024


async def test_send_file_payload_write_correctly() -> None:
    from aiohttp import BodyPartReader, web
    from aiohttp.web import Request, Response

    async def upload(request: Request) -> Response:
        parts = await request.multipart()
        file: BodyPartReader = None
        while field := await parts.next():
            if field.name == "file":
                file = field
                break
        else:
            return Response(body=b"", status=400)
        if file:
            return Response(body=await file.read())
        else:
            return Response(body=b"", status=400)

    server = web.Server(upload)
    runner = web.ServerRunner(server)
    await runner.setup()
    site = web.TCPSite(runner, "localhost", 9001)
    await site.start()

    import pathlib

    import aiohttp

    async with aiohttp.ClientSession() as sess:
        data = aiohttp.FormData(quote_fields=False)
        assert pathlib.Path(__file__).exists()
        data.add_field(
            "file", payload.SendFile(__file__), filename=pathlib.Path(__file__).name
        )
        async with sess.post("http://localhost:9001/upload", data=data) as resp:
            with open(pathlib.Path(__file__), "rb") as fp:
                assert fp.read() == await resp.read()
    await site.stop()
    await runner.cleanup()
    await server.shutdown()
