"""Test that multipart reader handles empty parts at the end correctly."""

import asyncio

import pytest

from aiohttp import web
from aiohttp.multipart import MultipartReader
from aiohttp.test_utils import AioHTTPTestCase


class TestMultipartEmptyFinal(AioHTTPTestCase):
    async def get_application(self):
        app = web.Application()
        app.router.add_post("/graphql", self.multipart_handler)
        return app

    async def multipart_handler(self, request):
        response = web.StreamResponse()
        response.headers["Content-Type"] = "multipart/mixed; boundary=graphql"
        await response.prepare(request)

        # preamble
        await response.write(
            b"Content-Type: application/json\r\n"
            b"Content-Length: 2\r\n"
            b"\r\n"
            b"{}\r\n"
        )

        # valid part
        await response.write(
            b"--graphql\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 15\r\n"
            b"\r\n"
            b'{"data": "foo"}\r\n'
        )

        # empty part which triggers the bug - technically valid
        await response.write(b"--graphql\r\n")

        await response.write(b"--graphql--")
        await response.write_eof()
        return response

    @pytest.mark.xfail(reason="Empty multipart parts not yet supported")
    async def test_multipart_with_empty_final_part(self):
        """Test that multipart reader can handle empty parts before final boundary."""
        async with self.client.post("/graphql") as resp:
            reader = MultipartReader.from_response(resp)

            parts = []
            while True:
                part = await reader.next()
                if part is None:
                    break
                content = await part.read()
                parts.append(content.decode("utf-8"))

            assert len(parts) == 2
            assert "{}" in parts[0]
            assert '{"data": "foo"}' in parts[1]
