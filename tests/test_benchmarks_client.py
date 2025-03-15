"""codspeed benchmarks for HTTP client."""

import asyncio

from pytest_codspeed import BenchmarkFixture

from aiohttp import hdrs, web
from aiohttp.pytest_plugin import AiohttpClient


def test_one_hundred_simple_get_requests(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark 100 simple GET requests."""
    message_count = 100

    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_client_benchmark() -> None:
        client = await aiohttp_client(app)
        for _ in range(message_count):
            await client.get("/")
        await client.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_client_benchmark())


def test_one_hundred_simple_get_requests_multiple_methods_route(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark 100 simple GET requests on a route with multiple methods."""
    message_count = 100

    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    app = web.Application()
    # GET intentionally registered last to ensure time complexity
    # of the route lookup is benchmarked
    for method in ("DELETE", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "GET"):
        app.router.add_route(method, "/", handler)

    async def run_client_benchmark() -> None:
        client = await aiohttp_client(app)
        for _ in range(message_count):
            await client.get("/")
        await client.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_client_benchmark())


def test_one_hundred_get_requests_with_1024_chunked_payload(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark 100 GET requests with a small payload of 1024 bytes."""
    message_count = 100
    payload = b"a" * 1024

    async def handler(request: web.Request) -> web.Response:
        resp = web.Response(body=payload)
        resp.enable_chunked_encoding()
        return resp

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_client_benchmark() -> None:
        client = await aiohttp_client(app)
        for _ in range(message_count):
            resp = await client.get("/")
            await resp.read()
        await client.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_client_benchmark())


def test_one_hundred_get_requests_with_30000_chunked_payload(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark 100 GET requests with a payload of 30000 bytes."""
    message_count = 100
    payload = b"a" * 30000

    async def handler(request: web.Request) -> web.Response:
        resp = web.Response(body=payload)
        resp.enable_chunked_encoding()
        return resp

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_client_benchmark() -> None:
        client = await aiohttp_client(app)
        for _ in range(message_count):
            resp = await client.get("/")
            await resp.read()
        await client.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_client_benchmark())


def test_one_hundred_get_requests_with_512kib_chunked_payload(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark 100 GET requests with a payload of 512KiB using read."""
    message_count = 100
    payload = b"a" * (2**19)

    async def handler(request: web.Request) -> web.Response:
        resp = web.Response(body=payload)
        resp.enable_chunked_encoding()
        return resp

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_client_benchmark() -> None:
        client = await aiohttp_client(app)
        for _ in range(message_count):
            resp = await client.get("/")
            await resp.read()
        await client.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_client_benchmark())


def test_one_hundred_get_requests_iter_chunks_on_512kib_chunked_payload(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark 100 GET requests with a payload of 512KiB using iter_chunks."""
    message_count = 100
    payload = b"a" * (2**19)

    async def handler(request: web.Request) -> web.Response:
        resp = web.Response(body=payload)
        resp.enable_chunked_encoding()
        return resp

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_client_benchmark() -> None:
        client = await aiohttp_client(app)
        for _ in range(message_count):
            resp = await client.get("/")
            async for _ in resp.content.iter_chunks():
                pass
        await client.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_client_benchmark())


def test_get_request_with_251308_compressed_chunked_payload(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark compressed GET requests with a payload of 251308."""
    # This payload compresses to 251308 bytes
    payload = b"".join(
        [
            bytes((*range(0, i), *range(i, 0, -1)))
            for _ in range(255)
            for i in range(255)
        ]
    )

    async def handler(request: web.Request) -> web.Response:
        resp = web.Response(body=payload, zlib_executor_size=16384)
        resp.enable_compression()
        return resp

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_client_benchmark() -> None:
        client = await aiohttp_client(app)
        resp = await client.get("/")
        await resp.read()
        await client.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_client_benchmark())


def test_one_hundred_get_requests_with_1024_content_length_payload(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark 100 GET requests with a small payload of 1024 bytes."""
    message_count = 100
    payload = b"a" * 1024
    headers = {hdrs.CONTENT_LENGTH: str(len(payload))}

    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=payload, headers=headers)

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_client_benchmark() -> None:
        client = await aiohttp_client(app)
        for _ in range(message_count):
            resp = await client.get("/")
            await resp.read()
        await client.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_client_benchmark())


def test_one_hundred_get_requests_with_30000_content_length_payload(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark 100 GET requests with a payload of 30000 bytes."""
    message_count = 100
    payload = b"a" * 30000
    headers = {hdrs.CONTENT_LENGTH: str(len(payload))}

    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=payload, headers=headers)

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_client_benchmark() -> None:
        client = await aiohttp_client(app)
        for _ in range(message_count):
            resp = await client.get("/")
            await resp.read()
        await client.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_client_benchmark())


def test_one_hundred_get_requests_with_512kib_content_length_payload(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark 100 GET requests with a payload of 512KiB."""
    message_count = 100
    payload = b"a" * (2**19)
    headers = {hdrs.CONTENT_LENGTH: str(len(payload))}

    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=payload, headers=headers)

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_client_benchmark() -> None:
        client = await aiohttp_client(app)
        for _ in range(message_count):
            resp = await client.get("/")
            await resp.read()
        await client.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_client_benchmark())


def test_one_hundred_simple_post_requests(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark 100 simple POST requests."""
    message_count = 100

    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    app = web.Application()
    app.router.add_route("POST", "/", handler)

    async def run_client_benchmark() -> None:
        client = await aiohttp_client(app)
        for _ in range(message_count):
            await client.post("/", data=b"any")
        await client.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_client_benchmark())


def test_one_hundred_json_post_requests(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark 100 JSON POST requests that check the content-type."""
    message_count = 100

    async def handler(request: web.Request) -> web.Response:
        _ = request.content_type
        _ = request.charset
        return web.Response()

    app = web.Application()
    app.router.add_route("POST", "/", handler)

    async def run_client_benchmark() -> None:
        client = await aiohttp_client(app)
        for _ in range(message_count):
            await client.post("/", json={"key": "value"})
        await client.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_client_benchmark())
