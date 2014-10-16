import unittest
from unittest import mock
from aiohttp.web import Request, StreamResponse
from aiohttp.protocol import Request as RequestImpl


class TestStreamResponse(unittest.TestCase):

    def make_request(self, method, path, headers=()):
        self.app = mock.Mock()
        self.transport = mock.Mock()
        message = RequestImpl(self.transport, method, path)
        message.headers.extend(headers)
        self.payload = mock.Mock()
        self.protocol = mock.Mock()
        req = Request(self.app, message, self.payload, self.protocol)
        return req

    def test_ctor(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        self.assertEqual(req, resp._request)
        self.assertIsNone(req._response)
        self.assertEqual(200, resp.status_code)
        self.assertTrue(resp.keep_alive)
