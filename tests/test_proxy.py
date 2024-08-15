import asyncio
import gc
import socket
import ssl
import sys
import unittest
from unittest import mock

from yarl import URL

import aiohttp
from aiohttp.client_reqrep import ClientRequest, ClientResponse
from aiohttp.helpers import TimerNoop
from aiohttp.test_utils import make_mocked_coro


class TestProxy(unittest.TestCase):
    response_mock_attrs = {
        "status": 200,
    }
    mocked_response = mock.Mock(**response_mock_attrs)
    clientrequest_mock_attrs = {
        "return_value.send.return_value.start": make_mocked_coro(mocked_response),
    }

    def setUp(self) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self) -> None:
        # just in case if we have transport close callbacks
        self.loop.stop()
        self.loop.run_forever()
        self.loop.close()
        gc.collect()

    @mock.patch("aiohttp.connector.ClientRequest")
    @mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        autospec=True,
        spec_set=True,
    )
    def test_connect(
        self, start_connection: mock.Mock, ClientRequestMock: mock.Mock
    ) -> None:
        req = ClientRequest(
            "GET",
            URL("http://www.python.org"),
            proxy=URL("http://proxy.example.com"),
            loop=self.loop,
        )
        self.assertEqual(str(req.proxy), "http://proxy.example.com")

        # mock all the things!
        async def make_conn() -> aiohttp.TCPConnector:
            return aiohttp.TCPConnector()

        connector = self.loop.run_until_complete(make_conn())
        r = {
            "hostname": "hostname",
            "host": "127.0.0.1",
            "port": 80,
            "family": socket.AF_INET,
            "proto": 0,
            "flags": 0,
        }
        with mock.patch.object(
            connector, "_resolve_host", autospec=True, return_value=[r]
        ):
            proto = mock.Mock(
                **{
                    "transport.get_extra_info.return_value": False,
                }
            )
            with mock.patch.object(
                self.loop,
                "create_connection",
                autospec=True,
                return_value=(proto.transport, proto),
            ):
                conn = self.loop.run_until_complete(
                    connector.connect(req, [], aiohttp.ClientTimeout())
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
                    ssl=True,
                )

                conn.close()

    @mock.patch("aiohttp.connector.ClientRequest")
    @mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        autospec=True,
        spec_set=True,
    )
    def test_proxy_headers(
        self, start_connection: mock.Mock, ClientRequestMock: mock.Mock
    ) -> None:
        req = ClientRequest(
            "GET",
            URL("http://www.python.org"),
            proxy=URL("http://proxy.example.com"),
            proxy_headers={"Foo": "Bar"},
            loop=self.loop,
        )
        self.assertEqual(str(req.proxy), "http://proxy.example.com")

        # mock all the things!
        async def make_conn() -> aiohttp.TCPConnector:
            return aiohttp.TCPConnector()

        connector = self.loop.run_until_complete(make_conn())
        r = {
            "hostname": "hostname",
            "host": "127.0.0.1",
            "port": 80,
            "family": socket.AF_INET,
            "proto": 0,
            "flags": 0,
        }
        with mock.patch.object(
            connector, "_resolve_host", autospec=True, return_value=[r]
        ):
            proto = mock.Mock(
                **{
                    "transport.get_extra_info.return_value": False,
                }
            )
            with mock.patch.object(
                self.loop,
                "create_connection",
                autospec=True,
                return_value=(proto.transport, proto),
            ):
                conn = self.loop.run_until_complete(
                    connector.connect(req, [], aiohttp.ClientTimeout())
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
                    ssl=True,
                )

                conn.close()

    @mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        autospec=True,
        spec_set=True,
    )
    def test_proxy_auth(self, start_connection: mock.Mock) -> None:
        with self.assertRaises(ValueError) as ctx:
            ClientRequest(
                "GET",
                URL("http://python.org"),
                proxy=URL("http://proxy.example.com"),
                proxy_auth=("user", "pass"),  # type: ignore[arg-type]
                loop=mock.Mock(),
            )
        self.assertEqual(
            ctx.exception.args[0],
            "proxy_auth must be None or BasicAuth() tuple",
        )

    @mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        autospec=True,
        spec_set=True,
    )
    def test_proxy_dns_error(self, start_connection: mock.Mock) -> None:
        async def make_conn() -> aiohttp.TCPConnector:
            return aiohttp.TCPConnector()

        connector = self.loop.run_until_complete(make_conn())
        with mock.patch.object(
            connector,
            "_resolve_host",
            autospec=True,
            side_effect=OSError("dont take it serious"),
        ):
            req = ClientRequest(
                "GET",
                URL("http://www.python.org"),
                proxy=URL("http://proxy.example.com"),
                loop=self.loop,
            )
            expected_headers = dict(req.headers)
            with self.assertRaises(aiohttp.ClientConnectorError):
                self.loop.run_until_complete(
                    connector.connect(req, [], aiohttp.ClientTimeout())
                )
            self.assertEqual(req.url.path, "/")
            self.assertEqual(dict(req.headers), expected_headers)

    @mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        autospec=True,
        spec_set=True,
    )
    def test_proxy_connection_error(self, start_connection: mock.Mock) -> None:
        async def make_conn() -> aiohttp.TCPConnector:
            return aiohttp.TCPConnector()

        connector = self.loop.run_until_complete(make_conn())
        r = {
            "hostname": "www.python.org",
            "host": "127.0.0.1",
            "port": 80,
            "family": socket.AF_INET,
            "proto": 0,
            "flags": socket.AI_NUMERICHOST,
        }
        with mock.patch.object(
            connector, "_resolve_host", autospec=True, return_value=[r]
        ):
            with mock.patch.object(
                connector._loop,
                "create_connection",
                autospec=True,
                side_effect=OSError("dont take it serious"),
            ):
                req = ClientRequest(
                    "GET",
                    URL("http://www.python.org"),
                    proxy=URL("http://proxy.example.com"),
                    loop=self.loop,
                )
                with self.assertRaises(aiohttp.ClientProxyConnectionError):
                    self.loop.run_until_complete(
                        connector.connect(req, [], aiohttp.ClientTimeout())
                    )

    @mock.patch("aiohttp.connector.ClientRequest")
    @mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        autospec=True,
        spec_set=True,
    )
    def test_proxy_server_hostname_default(
        self, start_connection: mock.Mock, ClientRequestMock: mock.Mock
    ) -> None:
        proxy_req = ClientRequest(
            "GET", URL("http://proxy.example.com"), loop=self.loop
        )
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse(
            "get",
            URL("http://proxy.example.com"),
            request_info=mock.Mock(),
            writer=None,  # type: ignore[arg-type]
            continue100=None,
            timer=TimerNoop(),
            traces=[],
            loop=self.loop,
            session=mock.Mock(),
        )
        with mock.patch.object(
            proxy_req, "send", autospec=True, return_value=proxy_resp
        ):
            with mock.patch.object(proxy_resp, "start", autospec=True) as m:
                m.return_value.status = 200

                async def make_conn() -> aiohttp.TCPConnector:
                    return aiohttp.TCPConnector()

                connector = self.loop.run_until_complete(make_conn())
                r = {
                    "hostname": "hostname",
                    "host": "127.0.0.1",
                    "port": 80,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": 0,
                }
                with mock.patch.object(
                    connector, "_resolve_host", autospec=True, return_value=[r]
                ):
                    tr, proto = mock.Mock(), mock.Mock()
                    with mock.patch.object(
                        self.loop,
                        "create_connection",
                        autospec=True,
                        return_value=(tr, proto),
                    ):
                        with mock.patch.object(
                            self.loop,
                            "start_tls",
                            autospec=True,
                            return_value=mock.Mock(),
                        ) as tls_m:
                            req = ClientRequest(
                                "GET",
                                URL("https://www.python.org"),
                                proxy=URL("http://proxy.example.com"),
                                loop=self.loop,
                            )
                            self.loop.run_until_complete(
                                connector._create_connection(
                                    req, [], aiohttp.ClientTimeout()
                                )
                            )

                            self.assertEqual(
                                tls_m.call_args.kwargs["server_hostname"],
                                "www.python.org",
                            )

                            self.loop.run_until_complete(proxy_req.close())
                            proxy_resp.close()
                            self.loop.run_until_complete(req.close())

    @mock.patch("aiohttp.connector.ClientRequest")
    @mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        autospec=True,
        spec_set=True,
    )
    def test_proxy_server_hostname_override(
        self, start_connection: mock.Mock, ClientRequestMock: mock.Mock
    ) -> None:
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
            writer=None,  # type: ignore[arg-type]
            continue100=None,
            timer=TimerNoop(),
            traces=[],
            loop=self.loop,
            session=mock.Mock(),
        )
        with mock.patch.object(
            proxy_req, "send", autospec=True, return_value=proxy_resp
        ):
            with mock.patch.object(proxy_resp, "start", autospec=True) as m:
                m.return_value.status = 200

                async def make_conn() -> aiohttp.TCPConnector:
                    return aiohttp.TCPConnector()

                connector = self.loop.run_until_complete(make_conn())
                r = {
                    "hostname": "hostname",
                    "host": "127.0.0.1",
                    "port": 80,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": 0,
                }
                with mock.patch.object(
                    connector, "_resolve_host", autospec=True, return_value=[r]
                ):
                    tr, proto = mock.Mock(), mock.Mock()
                    with mock.patch.object(
                        self.loop,
                        "create_connection",
                        autospec=True,
                        return_value=(tr, proto),
                    ):
                        with mock.patch.object(
                            self.loop,
                            "start_tls",
                            autospec=True,
                            return_value=mock.Mock(),
                        ) as tls_m:
                            req = ClientRequest(
                                "GET",
                                URL("https://www.python.org"),
                                proxy=URL("http://proxy.example.com"),
                                server_hostname="server-hostname.example.com",
                                loop=self.loop,
                            )
                            self.loop.run_until_complete(
                                connector._create_connection(
                                    req, [], aiohttp.ClientTimeout()
                                )
                            )

                            self.assertEqual(
                                tls_m.call_args.kwargs["server_hostname"],
                                "server-hostname.example.com",
                            )

                            self.loop.run_until_complete(proxy_req.close())
                            proxy_resp.close()
                            self.loop.run_until_complete(req.close())

    @mock.patch("aiohttp.connector.ClientRequest")
    @mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        autospec=True,
        spec_set=True,
    )
    def test_https_connect(
        self, start_connection: mock.Mock, ClientRequestMock: mock.Mock
    ) -> None:
        proxy_req = ClientRequest(
            "GET", URL("http://proxy.example.com"), loop=self.loop
        )
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse(
            "get",
            URL("http://proxy.example.com"),
            request_info=mock.Mock(),
            writer=None,  # type: ignore[arg-type]
            continue100=None,
            timer=TimerNoop(),
            traces=[],
            loop=self.loop,
            session=mock.Mock(),
        )
        with mock.patch.object(
            proxy_req, "send", autospec=True, return_value=proxy_resp
        ):
            with mock.patch.object(proxy_resp, "start", autospec=True) as m:
                m.return_value.status = 200

                async def make_conn() -> aiohttp.TCPConnector:
                    return aiohttp.TCPConnector()

                connector = self.loop.run_until_complete(make_conn())
                r = {
                    "hostname": "hostname",
                    "host": "127.0.0.1",
                    "port": 80,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": 0,
                }
                with mock.patch.object(
                    connector, "_resolve_host", autospec=True, return_value=[r]
                ):
                    tr, proto = mock.Mock(), mock.Mock()
                    with mock.patch.object(
                        self.loop,
                        "create_connection",
                        autospec=True,
                        return_value=(tr, proto),
                    ):
                        with mock.patch.object(
                            self.loop,
                            "start_tls",
                            autospec=True,
                            return_value=mock.Mock(),
                        ):
                            req = ClientRequest(
                                "GET",
                                URL("https://www.python.org"),
                                proxy=URL("http://proxy.example.com"),
                                loop=self.loop,
                            )
                            self.loop.run_until_complete(
                                connector._create_connection(
                                    req, [], aiohttp.ClientTimeout()
                                )
                            )

                            self.assertEqual(req.url.path, "/")
                            self.assertEqual(proxy_req.method, "CONNECT")
                            self.assertEqual(
                                proxy_req.url, URL("https://www.python.org")
                            )

                            self.loop.run_until_complete(proxy_req.close())
                            proxy_resp.close()
                            self.loop.run_until_complete(req.close())

    @mock.patch("aiohttp.connector.ClientRequest")
    @mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        autospec=True,
        spec_set=True,
    )
    def test_https_connect_certificate_error(
        self, start_connection: mock.Mock, ClientRequestMock: mock.Mock
    ) -> None:
        proxy_req = ClientRequest(
            "GET", URL("http://proxy.example.com"), loop=self.loop
        )
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse(
            "get",
            URL("http://proxy.example.com"),
            request_info=mock.Mock(),
            writer=None,  # type: ignore[arg-type]
            continue100=None,
            timer=TimerNoop(),
            traces=[],
            loop=self.loop,
            session=mock.Mock(),
        )
        with mock.patch.object(
            proxy_req, "send", autospec=True, return_value=proxy_resp
        ):
            with mock.patch.object(proxy_resp, "start", autospec=True) as m:
                m.return_value.status = 200

                async def make_conn() -> aiohttp.TCPConnector:
                    return aiohttp.TCPConnector()

                connector = self.loop.run_until_complete(make_conn())
                r = {
                    "hostname": "hostname",
                    "host": "127.0.0.1",
                    "port": 80,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": 0,
                }
                with mock.patch.object(
                    connector, "_resolve_host", autospec=True, return_value=[r]
                ):
                    tr, proto = mock.Mock(), mock.Mock()
                    # Called on connection to http://proxy.example.com
                    with mock.patch.object(
                        self.loop,
                        "create_connection",
                        autospec=True,
                        return_value=(tr, proto),
                    ):
                        # Called on connection to https://www.python.org
                        with mock.patch.object(
                            self.loop,
                            "start_tls",
                            autospec=True,
                            side_effect=ssl.CertificateError,
                        ):
                            req = ClientRequest(
                                "GET",
                                URL("https://www.python.org"),
                                proxy=URL("http://proxy.example.com"),
                                loop=self.loop,
                            )
                            with self.assertRaises(
                                aiohttp.ClientConnectorCertificateError
                            ):
                                self.loop.run_until_complete(
                                    connector._create_connection(
                                        req, [], aiohttp.ClientTimeout()
                                    )
                                )

    @mock.patch("aiohttp.connector.ClientRequest")
    @mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        autospec=True,
        spec_set=True,
    )
    def test_https_connect_ssl_error(
        self, start_connection: mock.Mock, ClientRequestMock: mock.Mock
    ) -> None:
        proxy_req = ClientRequest(
            "GET", URL("http://proxy.example.com"), loop=self.loop
        )
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse(
            "get",
            URL("http://proxy.example.com"),
            request_info=mock.Mock(),
            writer=None,  # type: ignore[arg-type]
            continue100=None,
            timer=TimerNoop(),
            traces=[],
            loop=self.loop,
            session=mock.Mock(),
        )
        with mock.patch.object(
            proxy_req, "send", autospec=True, return_value=proxy_resp
        ):
            with mock.patch.object(proxy_resp, "start", autospec=True) as m:
                m.return_value.status = 200

                async def make_conn() -> aiohttp.TCPConnector:
                    return aiohttp.TCPConnector()

                connector = self.loop.run_until_complete(make_conn())
                r = {
                    "hostname": "hostname",
                    "host": "127.0.0.1",
                    "port": 80,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": 0,
                }
                with mock.patch.object(
                    connector, "_resolve_host", autospec=True, return_value=[r]
                ):
                    tr, proto = mock.Mock(), mock.Mock()
                    # Called on connection to http://proxy.example.com
                    with mock.patch.object(
                        self.loop,
                        "create_connection",
                        autospec=True,
                        return_value=(tr, proto),
                    ):
                        # Called on connection to https://www.python.org
                        with mock.patch.object(
                            self.loop,
                            "start_tls",
                            autospec=True,
                            side_effect=ssl.SSLError,
                        ):
                            req = ClientRequest(
                                "GET",
                                URL("https://www.python.org"),
                                proxy=URL("http://proxy.example.com"),
                                loop=self.loop,
                            )
                            with self.assertRaises(aiohttp.ClientConnectorSSLError):
                                self.loop.run_until_complete(
                                    connector._create_connection(
                                        req, [], aiohttp.ClientTimeout()
                                    )
                                )

    @mock.patch("aiohttp.connector.ClientRequest")
    @mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        autospec=True,
        spec_set=True,
    )
    def test_https_connect_http_proxy_error(
        self, start_connection: mock.Mock, ClientRequestMock: mock.Mock
    ) -> None:
        proxy_req = ClientRequest(
            "GET", URL("http://proxy.example.com"), loop=self.loop
        )
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse(
            "get",
            URL("http://proxy.example.com"),
            request_info=mock.Mock(),
            writer=None,  # type: ignore[arg-type]
            continue100=None,
            timer=TimerNoop(),
            traces=[],
            loop=self.loop,
            session=mock.Mock(),
        )
        with mock.patch.object(
            proxy_req, "send", autospec=True, return_value=proxy_resp
        ):
            with mock.patch.object(proxy_resp, "start", autospec=True) as m:
                m.return_value.status = 400
                m.return_value.reason = "bad request"

                async def make_conn() -> aiohttp.TCPConnector:
                    return aiohttp.TCPConnector()

                connector = self.loop.run_until_complete(make_conn())
                r = {
                    "hostname": "hostname",
                    "host": "127.0.0.1",
                    "port": 80,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": 0,
                }
                with mock.patch.object(
                    connector, "_resolve_host", autospec=True, return_value=[r]
                ):
                    tr, proto = mock.Mock(), mock.Mock()
                    tr.get_extra_info.return_value = None
                    # Called on connection to http://proxy.example.com
                    with mock.patch.object(
                        self.loop,
                        "create_connection",
                        autospec=True,
                        return_value=(tr, proto),
                    ):
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
                                connector._create_connection(
                                    req, [], aiohttp.ClientTimeout()
                                )
                            )

                        self.loop.run_until_complete(proxy_req.close())
                        proxy_resp.close()
                        self.loop.run_until_complete(req.close())

    @mock.patch("aiohttp.connector.ClientRequest")
    @mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        autospec=True,
        spec_set=True,
    )
    def test_https_connect_resp_start_error(
        self, start_connection: mock.Mock, ClientRequestMock: mock.Mock
    ) -> None:
        proxy_req = ClientRequest(
            "GET", URL("http://proxy.example.com"), loop=self.loop
        )
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse(
            "get",
            URL("http://proxy.example.com"),
            request_info=mock.Mock(),
            writer=None,  # type: ignore[arg-type]
            continue100=None,
            timer=TimerNoop(),
            traces=[],
            loop=self.loop,
            session=mock.Mock(),
        )
        with mock.patch.object(
            proxy_req, "send", autospec=True, return_value=proxy_resp
        ):
            with mock.patch.object(
                proxy_resp, "start", autospec=True, side_effect=OSError("error message")
            ):

                async def make_conn() -> aiohttp.TCPConnector:
                    return aiohttp.TCPConnector()

                connector = self.loop.run_until_complete(make_conn())
                r = {
                    "hostname": "hostname",
                    "host": "127.0.0.1",
                    "port": 80,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": 0,
                }
                with mock.patch.object(
                    connector, "_resolve_host", autospec=True, return_value=[r]
                ):
                    tr, proto = mock.Mock(), mock.Mock()
                    tr.get_extra_info.return_value = None
                    # Called on connection to http://proxy.example.com
                    with mock.patch.object(
                        self.loop,
                        "create_connection",
                        autospec=True,
                        return_value=(tr, proto),
                    ):
                        req = ClientRequest(
                            "GET",
                            URL("https://www.python.org"),
                            proxy=URL("http://proxy.example.com"),
                            loop=self.loop,
                        )
                        with self.assertRaisesRegex(OSError, "error message"):
                            self.loop.run_until_complete(
                                connector._create_connection(
                                    req, [], aiohttp.ClientTimeout()
                                )
                            )

    @mock.patch("aiohttp.connector.ClientRequest")
    @mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        autospec=True,
        spec_set=True,
    )
    def test_request_port(
        self, start_connection: mock.Mock, ClientRequestMock: mock.Mock
    ) -> None:
        proxy_req = ClientRequest(
            "GET", URL("http://proxy.example.com"), loop=self.loop
        )
        ClientRequestMock.return_value = proxy_req

        async def make_conn() -> aiohttp.TCPConnector:
            return aiohttp.TCPConnector()

        connector = self.loop.run_until_complete(make_conn())
        r = {
            "hostname": "hostname",
            "host": "127.0.0.1",
            "port": 80,
            "family": socket.AF_INET,
            "proto": 0,
            "flags": 0,
        }
        with mock.patch.object(
            connector, "_resolve_host", autospec=True, return_value=[r]
        ):
            tr, proto = mock.Mock(), mock.Mock()
            tr.get_extra_info.return_value = None
            # Called on connection to http://proxy.example.com
            with mock.patch.object(
                self.loop, "create_connection", autospec=True, return_value=(tr, proto)
            ):
                req = ClientRequest(
                    "GET",
                    URL("http://localhost:1234/path"),
                    proxy=URL("http://proxy.example.com"),
                    loop=self.loop,
                )
                self.loop.run_until_complete(
                    connector._create_connection(req, [], aiohttp.ClientTimeout())
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
    @mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        autospec=True,
        spec_set=True,
    )
    def test_https_connect_pass_ssl_context(
        self, start_connection: mock.Mock, ClientRequestMock: mock.Mock
    ) -> None:
        proxy_req = ClientRequest(
            "GET", URL("http://proxy.example.com"), loop=self.loop
        )
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse(
            "get",
            URL("http://proxy.example.com"),
            request_info=mock.Mock(),
            writer=None,  # type: ignore[arg-type]
            continue100=None,
            timer=TimerNoop(),
            traces=[],
            loop=self.loop,
            session=mock.Mock(),
        )
        with mock.patch.object(
            proxy_req, "send", autospec=True, return_value=proxy_resp
        ):
            with mock.patch.object(proxy_resp, "start", autospec=True) as m:
                m.return_value.status = 200

                async def make_conn() -> aiohttp.TCPConnector:
                    return aiohttp.TCPConnector()

                connector = self.loop.run_until_complete(make_conn())
                r = {
                    "hostname": "hostname",
                    "host": "127.0.0.1",
                    "port": 80,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": 0,
                }
                with mock.patch.object(
                    connector, "_resolve_host", autospec=True, return_value=[r]
                ):
                    tr, proto = mock.Mock(), mock.Mock()
                    with mock.patch.object(
                        self.loop,
                        "create_connection",
                        autospec=True,
                        return_value=(tr, proto),
                    ):
                        with mock.patch.object(
                            self.loop,
                            "start_tls",
                            autospec=True,
                            return_value=mock.Mock(),
                        ) as tls_m:
                            req = ClientRequest(
                                "GET",
                                URL("https://www.python.org"),
                                proxy=URL("http://proxy.example.com"),
                                loop=self.loop,
                            )
                            self.loop.run_until_complete(
                                connector._create_connection(
                                    req, [], aiohttp.ClientTimeout()
                                )
                            )

                            tls_m.assert_called_with(
                                mock.ANY,
                                mock.ANY,
                                self.loop.run_until_complete(
                                    connector._make_or_get_ssl_context(True)
                                ),
                                server_hostname="www.python.org",
                                ssl_handshake_timeout=mock.ANY,
                            )

                            self.assertEqual(req.url.path, "/")
                            self.assertEqual(proxy_req.method, "CONNECT")
                            self.assertEqual(
                                proxy_req.url, URL("https://www.python.org")
                            )

                            self.loop.run_until_complete(proxy_req.close())
                            proxy_resp.close()
                            self.loop.run_until_complete(req.close())

    @mock.patch("aiohttp.connector.ClientRequest")
    @mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        autospec=True,
        spec_set=True,
    )
    def test_https_auth(
        self, start_connection: mock.Mock, ClientRequestMock: mock.Mock
    ) -> None:
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
            writer=None,  # type: ignore[arg-type]
            continue100=None,
            timer=TimerNoop(),
            traces=[],
            loop=self.loop,
            session=mock.Mock(),
        )
        with mock.patch.object(
            proxy_req, "send", autospec=True, return_value=proxy_resp
        ):
            with mock.patch.object(proxy_resp, "start", autospec=True) as m:
                m.return_value.status = 200

                async def make_conn() -> aiohttp.TCPConnector:
                    return aiohttp.TCPConnector()

                connector = self.loop.run_until_complete(make_conn())
                r = {
                    "hostname": "hostname",
                    "host": "127.0.0.1",
                    "port": 80,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": 0,
                }
                with mock.patch.object(
                    connector, "_resolve_host", autospec=True, return_value=[r]
                ) as host_m:
                    tr, proto = mock.Mock(), mock.Mock()
                    with mock.patch.object(
                        self.loop,
                        "create_connection",
                        autospec=True,
                        return_value=(tr, proto),
                    ):
                        with mock.patch.object(
                            self.loop,
                            "start_tls",
                            autospec=True,
                            return_value=mock.Mock(),
                        ):
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
                                connector._create_connection(
                                    req, [], aiohttp.ClientTimeout()
                                )
                            )

                            self.assertEqual(req.url.path, "/")
                            self.assertNotIn("AUTHORIZATION", req.headers)
                            self.assertNotIn("PROXY-AUTHORIZATION", req.headers)
                            self.assertNotIn("AUTHORIZATION", proxy_req.headers)
                            self.assertIn("PROXY-AUTHORIZATION", proxy_req.headers)

                            host_m.assert_called_with(
                                "proxy.example.com", 80, traces=mock.ANY
                            )

                            self.loop.run_until_complete(proxy_req.close())
                            proxy_resp.close()
                            self.loop.run_until_complete(req.close())
