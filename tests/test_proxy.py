import asyncio
import gc
import socket
import ssl
import sys
import unittest
from unittest import mock

import pytest
from yarl import URL

import aiohttp
from aiohttp.client_reqrep import ClientRequest, ClientResponse
from aiohttp.helpers import TimerNoop
from aiohttp.test_utils import make_mocked_coro

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="Proxy tests are unstable on Windows"
)


class TestProxy(unittest.TestCase):
    response_mock_attrs = {
        "status": 200,
    }
    mocked_response = mock.Mock(**response_mock_attrs)
    clientrequest_mock_attrs = {
        "return_value.send.return_value.start": make_mocked_coro(mocked_response),
    }

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        # just in case if we have transport close callbacks
        self.loop.stop()
        self.loop.run_forever()
        self.loop.close()
        gc.collect()

    @mock.patch("aiohttp.connector.ClientRequest")
    def test_connect(self, ClientRequestMock) -> None:
        req = ClientRequest(
            "GET",
            URL("http://www.python.org"),
            proxy=URL("http://proxy.example.com"),
            loop=self.loop,
        )
        self.assertEqual(str(req.proxy), "http://proxy.example.com")

        # mock all the things!
        async def make_conn():
            return aiohttp.TCPConnector()

        connector = self.loop.run_until_complete(make_conn())
        connector._resolve_host = make_mocked_coro([mock.MagicMock()])

        proto = mock.Mock(
            **{
                "transport.get_extra_info.return_value": False,
            }
        )
        self.loop.create_connection = make_mocked_coro((proto.transport, proto))
        conn = self.loop.run_until_complete(
            connector.connect(req, None, aiohttp.ClientTimeout())
        )
        self.assertEqual(req.url, URL("http://www.python.org"))
        self.assertIs(conn._protocol, proto)
        self.assertIs(conn.transport, proto.transport)

        ClientRequestMock.assert_called_with(
            "GET",
            URL("http://proxy.example.com"),
            auth=None,
            headers={"Host": "www.python.org"},
            loop=self.loop,
            ssl=None,
        )

        conn.close()

    @mock.patch("aiohttp.connector.ClientRequest")
    def test_proxy_headers(self, ClientRequestMock) -> None:
        req = ClientRequest(
            "GET",
            URL("http://www.python.org"),
            proxy=URL("http://proxy.example.com"),
            proxy_headers={"Foo": "Bar"},
            loop=self.loop,
        )
        self.assertEqual(str(req.proxy), "http://proxy.example.com")

        # mock all the things!
        async def make_conn():
            return aiohttp.TCPConnector()

        connector = self.loop.run_until_complete(make_conn())
        connector._resolve_host = make_mocked_coro([mock.MagicMock()])

        proto = mock.Mock(
            **{
                "transport.get_extra_info.return_value": False,
            }
        )
        self.loop.create_connection = make_mocked_coro((proto.transport, proto))
        conn = self.loop.run_until_complete(
            connector.connect(req, None, aiohttp.ClientTimeout())
        )
        self.assertEqual(req.url, URL("http://www.python.org"))
        self.assertIs(conn._protocol, proto)
        self.assertIs(conn.transport, proto.transport)

        ClientRequestMock.assert_called_with(
            "GET",
            URL("http://proxy.example.com"),
            auth=None,
            headers={"Host": "www.python.org", "Foo": "Bar"},
            loop=self.loop,
            ssl=None,
        )

        conn.close()

    def test_proxy_auth(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            ClientRequest(
                "GET",
                URL("http://python.org"),
                proxy=URL("http://proxy.example.com"),
                proxy_auth=("user", "pass"),
                loop=mock.Mock(),
            )
        self.assertEqual(
            ctx.exception.args[0],
            "proxy_auth must be None or BasicAuth() tuple",
        )

    def test_proxy_dns_error(self) -> None:
        async def make_conn():
            return aiohttp.TCPConnector()

        connector = self.loop.run_until_complete(make_conn())
        connector._resolve_host = make_mocked_coro(
            raise_exception=OSError("dont take it serious")
        )

        req = ClientRequest(
            "GET",
            URL("http://www.python.org"),
            proxy=URL("http://proxy.example.com"),
            loop=self.loop,
        )
        expected_headers = dict(req.headers)
        with self.assertRaises(aiohttp.ClientConnectorError):
            self.loop.run_until_complete(
                connector.connect(req, None, aiohttp.ClientTimeout())
            )
        self.assertEqual(req.url.path, "/")
        self.assertEqual(dict(req.headers), expected_headers)

    def test_proxy_connection_error(self) -> None:
        async def make_conn():
            return aiohttp.TCPConnector()

        connector = self.loop.run_until_complete(make_conn())
        connector._resolve_host = make_mocked_coro(
            [
                {
                    "hostname": "www.python.org",
                    "host": "127.0.0.1",
                    "port": 80,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": socket.AI_NUMERICHOST,
                }
            ]
        )
        connector._loop.create_connection = make_mocked_coro(
            raise_exception=OSError("dont take it serious")
        )

        req = ClientRequest(
            "GET",
            URL("http://www.python.org"),
            proxy=URL("http://proxy.example.com"),
            loop=self.loop,
        )
        with self.assertRaises(aiohttp.ClientProxyConnectionError):
            self.loop.run_until_complete(
                connector.connect(req, None, aiohttp.ClientTimeout())
            )

    @mock.patch("aiohttp.connector.ClientRequest")
    def test_proxy_server_hostname_default(self, ClientRequestMock) -> None:
        proxy_req = ClientRequest(
            "GET", URL("http://proxy.example.com"), loop=self.loop
        )
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse(
            "get",
            URL("http://proxy.example.com"),
            request_info=mock.Mock(),
            writer=mock.Mock(),
            continue100=None,
            timer=TimerNoop(),
            traces=[],
            loop=self.loop,
            session=mock.Mock(),
        )
        proxy_req.send = make_mocked_coro(proxy_resp)
        proxy_resp.start = make_mocked_coro(mock.Mock(status=200))

        async def make_conn():
            return aiohttp.TCPConnector()

        connector = self.loop.run_until_complete(make_conn())
        connector._resolve_host = make_mocked_coro(
            [
                {
                    "hostname": "hostname",
                    "host": "127.0.0.1",
                    "port": 80,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": 0,
                }
            ]
        )

        tr, proto = mock.Mock(), mock.Mock()
        self.loop.create_connection = make_mocked_coro((tr, proto))
        self.loop.start_tls = make_mocked_coro(mock.Mock())

        req = ClientRequest(
            "GET",
            URL("https://www.python.org"),
            proxy=URL("http://proxy.example.com"),
            loop=self.loop,
        )
        self.loop.run_until_complete(
            connector._create_connection(req, None, aiohttp.ClientTimeout())
        )

        self.assertEqual(
            self.loop.start_tls.call_args.kwargs["server_hostname"], "www.python.org"
        )

        self.loop.run_until_complete(proxy_req.close())
        proxy_resp.close()
        self.loop.run_until_complete(req.close())

    @mock.patch("aiohttp.connector.ClientRequest")
    def test_proxy_server_hostname_override(self, ClientRequestMock) -> None:
        proxy_req = ClientRequest(
            "GET",
            URL("http://proxy.example.com"),
            loop=self.loop,
        )
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse(
            "get",
            URL("http://proxy.example.com"),
            request_info=mock.Mock(),
            writer=mock.Mock(),
            continue100=None,
            timer=TimerNoop(),
            traces=[],
            loop=self.loop,
            session=mock.Mock(),
        )
        proxy_req.send = make_mocked_coro(proxy_resp)
        proxy_resp.start = make_mocked_coro(mock.Mock(status=200))

        async def make_conn():
            return aiohttp.TCPConnector()

        connector = self.loop.run_until_complete(make_conn())
        connector._resolve_host = make_mocked_coro(
            [
                {
                    "hostname": "hostname",
                    "host": "127.0.0.1",
                    "port": 80,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": 0,
                }
            ]
        )

        tr, proto = mock.Mock(), mock.Mock()
        self.loop.create_connection = make_mocked_coro((tr, proto))
        self.loop.start_tls = make_mocked_coro(mock.Mock())

        req = ClientRequest(
            "GET",
            URL("https://www.python.org"),
            proxy=URL("http://proxy.example.com"),
            server_hostname="server-hostname.example.com",
            loop=self.loop,
        )
        self.loop.run_until_complete(
            connector._create_connection(req, None, aiohttp.ClientTimeout())
        )

        self.assertEqual(
            self.loop.start_tls.call_args.kwargs["server_hostname"],
            "server-hostname.example.com",
        )

        self.loop.run_until_complete(proxy_req.close())
        proxy_resp.close()
        self.loop.run_until_complete(req.close())

    @mock.patch("aiohttp.connector.ClientRequest")
    def test_https_connect(self, ClientRequestMock) -> None:
        proxy_req = ClientRequest(
            "GET", URL("http://proxy.example.com"), loop=self.loop
        )
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse(
            "get",
            URL("http://proxy.example.com"),
            request_info=mock.Mock(),
            writer=mock.Mock(),
            continue100=None,
            timer=TimerNoop(),
            traces=[],
            loop=self.loop,
            session=mock.Mock(),
        )
        proxy_req.send = make_mocked_coro(proxy_resp)
        proxy_resp.start = make_mocked_coro(mock.Mock(status=200))

        async def make_conn():
            return aiohttp.TCPConnector()

        connector = self.loop.run_until_complete(make_conn())
        connector._resolve_host = make_mocked_coro(
            [
                {
                    "hostname": "hostname",
                    "host": "127.0.0.1",
                    "port": 80,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": 0,
                }
            ]
        )

        tr, proto = mock.Mock(), mock.Mock()
        self.loop.create_connection = make_mocked_coro((tr, proto))
        self.loop.start_tls = make_mocked_coro(mock.Mock())

        req = ClientRequest(
            "GET",
            URL("https://www.python.org"),
            proxy=URL("http://proxy.example.com"),
            loop=self.loop,
        )
        self.loop.run_until_complete(
            connector._create_connection(req, None, aiohttp.ClientTimeout())
        )

        self.assertEqual(req.url.path, "/")
        self.assertEqual(proxy_req.method, "CONNECT")
        self.assertEqual(proxy_req.url, URL("https://www.python.org"))

        self.loop.run_until_complete(proxy_req.close())
        proxy_resp.close()
        self.loop.run_until_complete(req.close())

    @mock.patch("aiohttp.connector.ClientRequest")
    def test_https_connect_certificate_error(self, ClientRequestMock) -> None:
        proxy_req = ClientRequest(
            "GET", URL("http://proxy.example.com"), loop=self.loop
        )
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse(
            "get",
            URL("http://proxy.example.com"),
            request_info=mock.Mock(),
            writer=mock.Mock(),
            continue100=None,
            timer=TimerNoop(),
            traces=[],
            loop=self.loop,
            session=mock.Mock(),
        )
        proxy_req.send = make_mocked_coro(proxy_resp)
        proxy_resp.start = make_mocked_coro(mock.Mock(status=200))

        async def make_conn():
            return aiohttp.TCPConnector()

        connector = self.loop.run_until_complete(make_conn())
        connector._resolve_host = make_mocked_coro(
            [
                {
                    "hostname": "hostname",
                    "host": "127.0.0.1",
                    "port": 80,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": 0,
                }
            ]
        )

        # Called on connection to http://proxy.example.com
        self.loop.create_connection = make_mocked_coro((mock.Mock(), mock.Mock()))
        # Called on connection to https://www.python.org
        self.loop.start_tls = make_mocked_coro(raise_exception=ssl.CertificateError)

        req = ClientRequest(
            "GET",
            URL("https://www.python.org"),
            proxy=URL("http://proxy.example.com"),
            loop=self.loop,
        )
        with self.assertRaises(aiohttp.ClientConnectorCertificateError):
            self.loop.run_until_complete(
                connector._create_connection(req, None, aiohttp.ClientTimeout())
            )

    @mock.patch("aiohttp.connector.ClientRequest")
    def test_https_connect_ssl_error(self, ClientRequestMock) -> None:
        proxy_req = ClientRequest(
            "GET", URL("http://proxy.example.com"), loop=self.loop
        )
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse(
            "get",
            URL("http://proxy.example.com"),
            request_info=mock.Mock(),
            writer=mock.Mock(),
            continue100=None,
            timer=TimerNoop(),
            traces=[],
            loop=self.loop,
            session=mock.Mock(),
        )
        proxy_req.send = make_mocked_coro(proxy_resp)
        proxy_resp.start = make_mocked_coro(mock.Mock(status=200))

        async def make_conn():
            return aiohttp.TCPConnector()

        connector = self.loop.run_until_complete(make_conn())
        connector._resolve_host = make_mocked_coro(
            [
                {
                    "hostname": "hostname",
                    "host": "127.0.0.1",
                    "port": 80,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": 0,
                }
            ]
        )

        # Called on connection to http://proxy.example.com
        self.loop.create_connection = make_mocked_coro(
            (mock.Mock(), mock.Mock()),
        )
        # Called on connection to https://www.python.org
        self.loop.start_tls = make_mocked_coro(raise_exception=ssl.SSLError)

        req = ClientRequest(
            "GET",
            URL("https://www.python.org"),
            proxy=URL("http://proxy.example.com"),
            loop=self.loop,
        )
        with self.assertRaises(aiohttp.ClientConnectorSSLError):
            self.loop.run_until_complete(
                connector._create_connection(req, None, aiohttp.ClientTimeout())
            )

    @mock.patch("aiohttp.connector.ClientRequest")
    def test_https_connect_http_proxy_error(self, ClientRequestMock) -> None:
        proxy_req = ClientRequest(
            "GET", URL("http://proxy.example.com"), loop=self.loop
        )
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse(
            "get",
            URL("http://proxy.example.com"),
            request_info=mock.Mock(),
            writer=mock.Mock(),
            continue100=None,
            timer=TimerNoop(),
            traces=[],
            loop=self.loop,
            session=mock.Mock(),
        )
        proxy_req.send = make_mocked_coro(proxy_resp)
        proxy_resp.start = make_mocked_coro(mock.Mock(status=400, reason="bad request"))

        async def make_conn():
            return aiohttp.TCPConnector()

        connector = self.loop.run_until_complete(make_conn())
        connector._resolve_host = make_mocked_coro(
            [
                {
                    "hostname": "hostname",
                    "host": "127.0.0.1",
                    "port": 80,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": 0,
                }
            ]
        )

        tr, proto = mock.Mock(), mock.Mock()
        tr.get_extra_info.return_value = None
        self.loop.create_connection = make_mocked_coro((tr, proto))

        req = ClientRequest(
            "GET",
            URL("https://www.python.org"),
            proxy=URL("http://proxy.example.com"),
            loop=self.loop,
        )
        with self.assertRaisesRegex(
            aiohttp.ClientHttpProxyError, "400, message='bad request'"
        ):
            self.loop.run_until_complete(
                connector._create_connection(req, None, aiohttp.ClientTimeout())
            )

        self.loop.run_until_complete(proxy_req.close())
        proxy_resp.close()
        self.loop.run_until_complete(req.close())

    @mock.patch("aiohttp.connector.ClientRequest")
    def test_https_connect_resp_start_error(self, ClientRequestMock) -> None:
        proxy_req = ClientRequest(
            "GET", URL("http://proxy.example.com"), loop=self.loop
        )
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse(
            "get",
            URL("http://proxy.example.com"),
            request_info=mock.Mock(),
            writer=mock.Mock(),
            continue100=None,
            timer=TimerNoop(),
            traces=[],
            loop=self.loop,
            session=mock.Mock(),
        )
        proxy_req.send = make_mocked_coro(proxy_resp)
        proxy_resp.start = make_mocked_coro(raise_exception=OSError("error message"))

        async def make_conn():
            return aiohttp.TCPConnector()

        connector = self.loop.run_until_complete(make_conn())
        connector._resolve_host = make_mocked_coro(
            [
                {
                    "hostname": "hostname",
                    "host": "127.0.0.1",
                    "port": 80,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": 0,
                }
            ]
        )

        tr, proto = mock.Mock(), mock.Mock()
        tr.get_extra_info.return_value = None
        self.loop.create_connection = make_mocked_coro((tr, proto))

        req = ClientRequest(
            "GET",
            URL("https://www.python.org"),
            proxy=URL("http://proxy.example.com"),
            loop=self.loop,
        )
        with self.assertRaisesRegex(OSError, "error message"):
            self.loop.run_until_complete(
                connector._create_connection(req, None, aiohttp.ClientTimeout())
            )

    @mock.patch("aiohttp.connector.ClientRequest")
    def test_request_port(self, ClientRequestMock) -> None:
        proxy_req = ClientRequest(
            "GET", URL("http://proxy.example.com"), loop=self.loop
        )
        ClientRequestMock.return_value = proxy_req

        async def make_conn():
            return aiohttp.TCPConnector()

        connector = self.loop.run_until_complete(make_conn())
        connector._resolve_host = make_mocked_coro(
            [
                {
                    "hostname": "hostname",
                    "host": "127.0.0.1",
                    "port": 80,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": 0,
                }
            ]
        )

        tr, proto = mock.Mock(), mock.Mock()
        tr.get_extra_info.return_value = None
        self.loop.create_connection = make_mocked_coro((tr, proto))

        req = ClientRequest(
            "GET",
            URL("http://localhost:1234/path"),
            proxy=URL("http://proxy.example.com"),
            loop=self.loop,
        )
        self.loop.run_until_complete(
            connector._create_connection(req, None, aiohttp.ClientTimeout())
        )
        self.assertEqual(req.url, URL("http://localhost:1234/path"))

    def test_proxy_auth_property(self) -> None:
        req = aiohttp.ClientRequest(
            "GET",
            URL("http://localhost:1234/path"),
            proxy=URL("http://proxy.example.com"),
            proxy_auth=aiohttp.helpers.BasicAuth("user", "pass"),
            loop=self.loop,
        )
        self.assertEqual(("user", "pass", "latin1"), req.proxy_auth)

    def test_proxy_auth_property_default(self) -> None:
        req = aiohttp.ClientRequest(
            "GET",
            URL("http://localhost:1234/path"),
            proxy=URL("http://proxy.example.com"),
            loop=self.loop,
        )
        self.assertIsNone(req.proxy_auth)

    @mock.patch("aiohttp.connector.ClientRequest")
    def test_https_connect_pass_ssl_context(self, ClientRequestMock) -> None:
        proxy_req = ClientRequest(
            "GET", URL("http://proxy.example.com"), loop=self.loop
        )
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse(
            "get",
            URL("http://proxy.example.com"),
            request_info=mock.Mock(),
            writer=mock.Mock(),
            continue100=None,
            timer=TimerNoop(),
            traces=[],
            loop=self.loop,
            session=mock.Mock(),
        )
        proxy_req.send = make_mocked_coro(proxy_resp)
        proxy_resp.start = make_mocked_coro(mock.Mock(status=200))

        async def make_conn():
            return aiohttp.TCPConnector()

        connector = self.loop.run_until_complete(make_conn())
        connector._resolve_host = make_mocked_coro(
            [
                {
                    "hostname": "hostname",
                    "host": "127.0.0.1",
                    "port": 80,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": 0,
                }
            ]
        )

        tr, proto = mock.Mock(), mock.Mock()
        self.loop.create_connection = make_mocked_coro((tr, proto))
        self.loop.start_tls = make_mocked_coro(mock.Mock())

        req = ClientRequest(
            "GET",
            URL("https://www.python.org"),
            proxy=URL("http://proxy.example.com"),
            loop=self.loop,
        )
        self.loop.run_until_complete(
            connector._create_connection(req, None, aiohttp.ClientTimeout())
        )

        self.loop.start_tls.assert_called_with(
            mock.ANY,
            mock.ANY,
            connector._make_ssl_context(True),
            server_hostname="www.python.org",
            ssl_handshake_timeout=mock.ANY,
        )

        self.assertEqual(req.url.path, "/")
        self.assertEqual(proxy_req.method, "CONNECT")
        self.assertEqual(proxy_req.url, URL("https://www.python.org"))

        self.loop.run_until_complete(proxy_req.close())
        proxy_resp.close()
        self.loop.run_until_complete(req.close())

    @mock.patch("aiohttp.connector.ClientRequest")
    def test_https_auth(self, ClientRequestMock) -> None:
        proxy_req = ClientRequest(
            "GET",
            URL("http://proxy.example.com"),
            auth=aiohttp.helpers.BasicAuth("user", "pass"),
            loop=self.loop,
        )
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse(
            "get",
            URL("http://proxy.example.com"),
            request_info=mock.Mock(),
            writer=mock.Mock(),
            continue100=None,
            timer=TimerNoop(),
            traces=[],
            loop=self.loop,
            session=mock.Mock(),
        )
        proxy_req.send = make_mocked_coro(proxy_resp)
        proxy_resp.start = make_mocked_coro(mock.Mock(status=200))

        async def make_conn():
            return aiohttp.TCPConnector()

        connector = self.loop.run_until_complete(make_conn())
        connector._resolve_host = make_mocked_coro(
            [
                {
                    "hostname": "hostname",
                    "host": "127.0.0.1",
                    "port": 80,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": 0,
                }
            ]
        )

        tr, proto = mock.Mock(), mock.Mock()
        self.loop.create_connection = make_mocked_coro((tr, proto))
        self.loop.start_tls = make_mocked_coro(mock.Mock())

        self.assertIn("AUTHORIZATION", proxy_req.headers)
        self.assertNotIn("PROXY-AUTHORIZATION", proxy_req.headers)

        req = ClientRequest(
            "GET",
            URL("https://www.python.org"),
            proxy=URL("http://proxy.example.com"),
            loop=self.loop,
        )
        self.assertNotIn("AUTHORIZATION", req.headers)
        self.assertNotIn("PROXY-AUTHORIZATION", req.headers)
        self.loop.run_until_complete(
            connector._create_connection(req, None, aiohttp.ClientTimeout())
        )

        self.assertEqual(req.url.path, "/")
        self.assertNotIn("AUTHORIZATION", req.headers)
        self.assertNotIn("PROXY-AUTHORIZATION", req.headers)
        self.assertNotIn("AUTHORIZATION", proxy_req.headers)
        self.assertIn("PROXY-AUTHORIZATION", proxy_req.headers)

        connector._resolve_host.assert_called_with(
            "proxy.example.com", 80, traces=mock.ANY
        )

        self.loop.run_until_complete(proxy_req.close())
        proxy_resp.close()
        self.loop.run_until_complete(req.close())
