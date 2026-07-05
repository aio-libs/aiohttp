"""
Tests for aiohttp’s public HTTP/2 client API.

Divided into:
- Outgoing frame correctness (what aiohttp writes to the transport).
- Incoming response parsing (what aiohttp returns when frames are fed).

Both rely on a mocked transport that simulates ALPN negotiation of "h2"
and a custom connector that plugs in your Http2Protocol.
"""

import asyncio
import struct
from typing import List, Tuple
from unittest.mock import MagicMock, patch

import pytest
import aiohttp
from aiohttp.connector import TCPConnector
from test_http2 import (
    Http2Protocol,
    build_headers_frame,
    build_data_frame,
    build_goaway,
)
from aiohttp.http2.settings import FrameType, FlagHeaders, FlagData


# ----------------------------------------------------------------------
# Mock transport – records writes and lies about ALPN
# ----------------------------------------------------------------------
class MockH2Transport(asyncio.Transport):
    def __init__(self, extra_info=None):
        super().__init__()
        self.written = bytearray()
        self._closing = False
        self._extra = extra_info or {}

    def write(self, data):
        self.written.extend(data)

    def close(self):
        self._closing = True

    def is_closing(self):
        return self._closing

    def get_extra_info(self, name, default=None):
        if name == "ssl_object":
            return self._extra.get("ssl_object", MagicMock())
        return self._extra.get(name, default)


# ----------------------------------------------------------------------
# Custom connector – always returns Http2Protocol for h2 connections
# ----------------------------------------------------------------------
class H2TestConnector(TCPConnector):
    def _get_protocol(self, loop):
        # Return the class; aiohttp will instantiate it
        return Http2Protocol

    async def close(self):
        self._closed = True


# ----------------------------------------------------------------------
# Fixture: session + mock transport + captured protocol
# ----------------------------------------------------------------------
@pytest.fixture
async def h2_client():
    """Create a ClientSession that uses our Http2Protocol over a mock transport."""
    loop = asyncio.get_running_loop()

    # Mock SSL object that tells aiohttp we’ve negotiated h2
    mock_ssl = MagicMock()
    mock_ssl.selected_alpn_protocol.return_value = "h2"
    transport = MockH2Transport(extra_info={"ssl_object": mock_ssl})

    protocol_instance = None

    async def fake_create_connection(protocol_factory, *args, **kwargs):
        nonlocal protocol_instance
        protocol_instance = protocol_factory()  # Http2Protocol()
        protocol_instance.connection_made(transport)
        transport._protocol = protocol_instance
        return transport, protocol_instance

    connector = H2TestConnector()
    connector._wrap_create_connection = fake_create_connection
    async with aiohttp.ClientSession(connector=connector) as session:
        yield session, transport, protocol_instance


CEASE = build_goaway(0, 1)
URL = "https://127.3.3.3"


class TestIncomingResponses:
    @pytest.mark.asyncio
    async def test_get_200_response(self, h2_client):
        session, transport, _ = h2_client
        task = asyncio.create_task(session.get(URL))
        await asyncio.sleep(0.01)  # request sent

        # Feed a minimal 200 response
        hframe = build_headers_frame(1, [(":status", "200")], end_stream=True)
        proto = transport._protocol
        proto.data_received(hframe)

        resp = await task
        assert resp.status == 200
        assert await resp.read() == b""

    @pytest.mark.asyncio
    async def test_response_with_body(self, h2_client):
        session, transport, _ = h2_client
        task = asyncio.create_task(session.get(URL))
        await asyncio.sleep(0.01)

        # Send HEADERS (no END_STREAM) then DATA with body
        hframe = build_headers_frame(1, [(":status", "200")], end_stream=False)
        dframe = build_data_frame(1, b"Hello, h2!", end_stream=True)
        proto = transport._protocol
        proto.data_received(hframe)
        proto.data_received(dframe)

        resp = await task
        assert resp.status == 200
        assert await resp.text() == "Hello, h2!"

    @pytest.mark.asyncio
    async def test_json_response(self, h2_client):
        session, transport, _ = h2_client
        task = asyncio.create_task(session.get(URL))
        await asyncio.sleep(0.01)

        headers = [(":status", "200"), ("content-type", "application/json")]
        body = b'{"key":"value"}'
        proto = transport._protocol
        proto.data_received(build_headers_frame(1, headers, end_stream=False))
        proto.data_received(build_data_frame(1, body, end_stream=True))

        resp = await task
        assert await resp.json() == {"key": "value"}

    @pytest.mark.asyncio
    async def test_response_cookies(self, h2_client):
        session, transport, _ = h2_client
        task = asyncio.create_task(session.get(URL))
        await asyncio.sleep(0.01)

        headers = [(":status", "200"), ("set-cookie", "session=abc123; Path=/")]
        proto = transport._protocol
        proto.data_received(build_headers_frame(1, headers, end_stream=True))

        resp = await task
        assert "session" in resp.cookies
        assert resp.cookies["session"].value == "abc123"

    @pytest.mark.asyncio
    async def test_concurrent_requests_mux(self, h2_client):
        session, transport, _ = h2_client
        t1 = asyncio.create_task(session.get(URL))
        t2 = asyncio.create_task(session.get(URL))
        await asyncio.sleep(0.01)

        # Stream 1 gets response, stream 3 gets response
        proto = transport._protocol
        proto.data_received(
            build_headers_frame(1, [(":status", "200")], end_stream=True)
        )
        proto.data_received(
            build_headers_frame(3, [(":status", "201")], end_stream=True)
        )

        r1, r2 = await asyncio.gather(t1, t2)
        assert r1.status == 200
        assert r2.status == 201

    @pytest.mark.asyncio
    async def test_redirect_headers(self, h2_client):
        session, transport, _ = h2_client
        task = asyncio.create_task(session.get(URL))
        await asyncio.sleep(0.01)

        headers = [(":status", "302"), ("location", "/new")]
        proto = transport._protocol
        proto.data_received(build_headers_frame(1, headers, end_stream=True))

        await asyncio.sleep(0.01)

        headers = [(":status", "200")]
        proto.data_received(build_headers_frame(3, headers, end_stream=True))

        resp = await task
        first = resp._history[0]
        assert first.status == 302
        assert first.headers.get("location") == "/new"

        assert resp.status == 200

    @pytest.mark.asyncio
    async def test_error_response_raises(self, h2_client):
        session, transport, _ = h2_client
        task = asyncio.create_task(session.get(URL))
        await asyncio.sleep(0.01)

        proto = transport._protocol
        proto.data_received(
            build_headers_frame(1, [(":status", "404")], end_stream=True)
        )
        resp = await task
        with pytest.raises(aiohttp.ClientResponseError):
            resp.raise_for_status()
