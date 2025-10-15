import asyncio
import socket
import ssl
import sys
from typing import Callable
from unittest import mock

import pytest
from multidict import CIMultiDict
from yarl import URL

import aiohttp
from aiohttp.client_reqrep import (
    ClientRequest,
    ClientRequestArgs,
    ClientRequestBase,
    ClientResponse,
    Fingerprint,
)
from aiohttp.connector import _SSL_CONTEXT_VERIFIED
from aiohttp.helpers import TimerNoop
from aiohttp.http import HttpVersion

if sys.version_info >= (3, 11):
    from typing import Unpack

    _RequestMaker = Callable[[str, URL, Unpack[ClientRequestArgs]], ClientRequest]
else:
    from typing import Any

    _RequestMaker = Any


@mock.patch("aiohttp.connector.ClientRequestBase")
@mock.patch(
    "aiohttp.connector.aiohappyeyeballs.start_connection",
    autospec=True,
    spec_set=True,
)
async def test_connect(  # type: ignore[misc]
    start_connection: mock.Mock,
    ClientRequestMock: mock.Mock,
    make_client_request: _RequestMaker,
) -> None:
    event_loop = asyncio.get_running_loop()
    req = make_client_request(
        "GET",
        URL("http://www.python.org"),
        proxy=URL("http://proxy.example.com"),
        loop=event_loop,
        ssl=True,
        headers=CIMultiDict({}),
    )
    assert str(req.proxy) == "http://proxy.example.com"

    connector = aiohttp.TCPConnector()
    r = {
        "hostname": "hostname",
        "host": "127.0.0.1",
        "port": 80,
        "family": socket.AF_INET,
        "proto": 0,
        "flags": 0,
    }
    with mock.patch.object(connector, "_resolve_host", autospec=True, return_value=[r]):
        proto = mock.Mock(
            **{
                "transport.get_extra_info.return_value": False,
            }
        )
        with mock.patch.object(
            event_loop,
            "create_connection",
            autospec=True,
            return_value=(proto.transport, proto),
        ):
            conn = await connector.connect(req, [], aiohttp.ClientTimeout())
            assert req.url == URL("http://www.python.org")
            assert conn._protocol is proto
            assert conn.transport is proto.transport

            ClientRequestMock.assert_called_with(
                "GET",
                URL("http://proxy.example.com"),
                auth=None,
                headers={"Host": "www.python.org"},
                loop=event_loop,
                ssl=True,
            )

            conn.close()
    await connector.close()


@mock.patch("aiohttp.connector.ClientRequestBase")
@mock.patch(
    "aiohttp.connector.aiohappyeyeballs.start_connection",
    autospec=True,
    spec_set=True,
)
async def test_proxy_headers(  # type: ignore[misc]
    start_connection: mock.Mock,
    ClientRequestMock: mock.Mock,
    make_client_request: _RequestMaker,
) -> None:
    event_loop = asyncio.get_running_loop()
    req = make_client_request(
        "GET",
        URL("http://www.python.org"),
        proxy=URL("http://proxy.example.com"),
        proxy_headers=CIMultiDict({"Foo": "Bar"}),
        loop=event_loop,
        ssl=True,
        headers=CIMultiDict({}),
    )
    assert str(req.proxy) == "http://proxy.example.com"

    connector = aiohttp.TCPConnector()
    r = {
        "hostname": "hostname",
        "host": "127.0.0.1",
        "port": 80,
        "family": socket.AF_INET,
        "proto": 0,
        "flags": 0,
    }
    with mock.patch.object(connector, "_resolve_host", autospec=True, return_value=[r]):
        proto = mock.Mock(
            **{
                "transport.get_extra_info.return_value": False,
            }
        )
        with mock.patch.object(
            event_loop,
            "create_connection",
            autospec=True,
            return_value=(proto.transport, proto),
        ):
            conn = await connector.connect(req, [], aiohttp.ClientTimeout())
            assert req.url == URL("http://www.python.org")
            assert conn._protocol is proto
            assert conn.transport is proto.transport

            ClientRequestMock.assert_called_with(
                "GET",
                URL("http://proxy.example.com"),
                auth=None,
                headers={"Host": "www.python.org", "Foo": "Bar"},
                loop=event_loop,
                ssl=True,
            )

            conn.close()
    await connector.close()


@mock.patch(
    "aiohttp.connector.aiohappyeyeballs.start_connection",
    autospec=True,
    spec_set=True,
)
async def test_proxy_auth(  # type: ignore[misc]
    start_connection: mock.Mock,
    make_client_request: _RequestMaker,
) -> None:
    msg = r"proxy_auth must be None or BasicAuth\(\) tuple"
    with pytest.raises(ValueError, match=msg):
        make_client_request(
            "GET",
            URL("http://python.org"),
            proxy=URL("http://proxy.example.com"),
            proxy_auth=("user", "pass"),  # type: ignore[arg-type]
            loop=mock.Mock(),
        )


@mock.patch(
    "aiohttp.connector.aiohappyeyeballs.start_connection",
    autospec=True,
    spec_set=True,
)
async def test_proxy_dns_error(  # type: ignore[misc]
    start_connection: mock.Mock,
    make_client_request: _RequestMaker,
) -> None:
    connector = aiohttp.TCPConnector()
    with mock.patch.object(
        connector,
        "_resolve_host",
        autospec=True,
        side_effect=OSError("dont take it serious"),
    ):
        req = make_client_request(
            "GET",
            URL("http://www.python.org"),
            proxy=URL("http://proxy.example.com"),
            loop=asyncio.get_running_loop(),
        )
        expected_headers = dict(req.headers)
        with pytest.raises(aiohttp.ClientConnectorError):
            await connector.connect(req, [], aiohttp.ClientTimeout())
        assert req.url.path == "/"
        assert dict(req.headers) == expected_headers
    await connector.close()


@mock.patch(
    "aiohttp.connector.aiohappyeyeballs.start_connection",
    autospec=True,
    spec_set=True,
    return_value=mock.create_autospec(socket.socket, spec_set=True, instance=True),
)
async def test_proxy_connection_error(  # type: ignore[misc]
    start_connection: mock.Mock,
    make_client_request: _RequestMaker,
) -> None:
    connector = aiohttp.TCPConnector()
    r = {
        "hostname": "www.python.org",
        "host": "127.0.0.1",
        "port": 80,
        "family": socket.AF_INET,
        "proto": 0,
        "flags": socket.AI_NUMERICHOST,
    }
    with mock.patch.object(connector, "_resolve_host", autospec=True, return_value=[r]):
        with mock.patch.object(
            connector._loop,
            "create_connection",
            autospec=True,
            side_effect=OSError("dont take it serious"),
        ):
            req = make_client_request(
                "GET",
                URL("http://www.python.org"),
                proxy=URL("http://proxy.example.com"),
            )
            with pytest.raises(aiohttp.ClientProxyConnectionError):
                await connector.connect(req, [], aiohttp.ClientTimeout())
    await connector.close()


@mock.patch("aiohttp.connector.ClientRequestBase")
@mock.patch(
    "aiohttp.connector.aiohappyeyeballs.start_connection",
    autospec=True,
    spec_set=True,
)
async def test_proxy_server_hostname_default(  # type: ignore[misc]
    start_connection: mock.Mock,
    ClientRequestMock: mock.Mock,
    make_client_request: _RequestMaker,
) -> None:
    event_loop = asyncio.get_running_loop()
    proxy_req = ClientRequestBase(
        "GET",
        URL("http://proxy.example.com"),
        auth=None,
        loop=event_loop,
        ssl=True,
        headers=CIMultiDict({}),
    )
    ClientRequestMock.return_value = proxy_req

    proxy_resp = ClientResponse(
        "get",
        URL("http://proxy.example.com"),
        request_info=mock.Mock(),
        writer=None,
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=event_loop,
        session=mock.Mock(),
    )
    with mock.patch.object(proxy_req, "_send", autospec=True, return_value=proxy_resp):
        with mock.patch.object(proxy_resp, "start", autospec=True) as m:
            m.return_value.status = 200

            connector = aiohttp.TCPConnector()
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
                    event_loop,
                    "create_connection",
                    autospec=True,
                    return_value=(tr, proto),
                ):
                    with mock.patch.object(
                        event_loop,
                        "start_tls",
                        autospec=True,
                        return_value=mock.Mock(),
                    ) as tls_m:
                        req = make_client_request(
                            "GET",
                            URL("https://www.python.org"),
                            proxy=URL("http://proxy.example.com"),
                            loop=event_loop,
                        )
                        await connector._create_connection(
                            req, [], aiohttp.ClientTimeout()
                        )

                        assert (
                            tls_m.call_args.kwargs["server_hostname"]
                            == "www.python.org"
                        )

                        proxy_resp.close()
                        await req._close()
            await connector.close()


@mock.patch("aiohttp.connector.ClientRequestBase")
@mock.patch(
    "aiohttp.connector.aiohappyeyeballs.start_connection",
    autospec=True,
    spec_set=True,
)
async def test_proxy_server_hostname_override(  # type: ignore[misc]
    start_connection: mock.Mock,
    ClientRequestMock: mock.Mock,
    make_client_request: _RequestMaker,
) -> None:
    event_loop = asyncio.get_running_loop()
    proxy_req = ClientRequestBase(
        "GET",
        URL("http://proxy.example.com"),
        auth=None,
        loop=event_loop,
        ssl=True,
        headers=CIMultiDict({}),
    )
    ClientRequestMock.return_value = proxy_req

    proxy_resp = ClientResponse(
        "get",
        URL("http://proxy.example.com"),
        request_info=mock.Mock(),
        writer=None,
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=event_loop,
        session=mock.Mock(),
    )
    with mock.patch.object(proxy_req, "_send", autospec=True, return_value=proxy_resp):
        with mock.patch.object(proxy_resp, "start", autospec=True) as m:
            m.return_value.status = 200

            connector = aiohttp.TCPConnector()
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
                    event_loop,
                    "create_connection",
                    autospec=True,
                    return_value=(tr, proto),
                ):
                    with mock.patch.object(
                        event_loop,
                        "start_tls",
                        autospec=True,
                        return_value=mock.Mock(),
                    ) as tls_m:
                        req = make_client_request(
                            "GET",
                            URL("https://www.python.org"),
                            proxy=URL("http://proxy.example.com"),
                            server_hostname="server-hostname.example.com",
                        )
                        await connector._create_connection(
                            req, [], aiohttp.ClientTimeout()
                        )

                        assert (
                            tls_m.call_args.kwargs["server_hostname"]
                            == "server-hostname.example.com"
                        )

                        proxy_resp.close()
                        await req._close()
            await connector.close()


@mock.patch("aiohttp.connector.ClientRequestBase")
@mock.patch(
    "aiohttp.connector.aiohappyeyeballs.start_connection",
    autospec=True,
    spec_set=True,
)
@pytest.mark.usefixtures("enable_cleanup_closed")
@pytest.mark.parametrize("cleanup", (True, False))
async def test_https_connect_fingerprint_mismatch(  # type: ignore[misc]
    start_connection: mock.Mock,
    ClientRequestMock: mock.Mock,
    cleanup: bool,
    make_client_request: _RequestMaker,
) -> None:
    event_loop = asyncio.get_running_loop()
    proxy_req = ClientRequestBase(
        "GET",
        URL("http://proxy.example.com"),
        auth=None,
        loop=event_loop,
        ssl=True,
        headers=CIMultiDict({}),
    )
    ClientRequestMock.return_value = proxy_req

    class TransportMock(asyncio.Transport):
        def close(self) -> None:
            pass

    proxy_resp = ClientResponse(
        "get",
        URL("http://proxy.example.com"),
        request_info=mock.Mock(),
        writer=mock.Mock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=event_loop,
        session=mock.Mock(),
    )
    fingerprint_mock = mock.Mock(spec=Fingerprint, auto_spec=True)
    fingerprint_mock.check.side_effect = aiohttp.ServerFingerprintMismatch(
        b"exp", b"got", "example.com", 8080
    )
    with (
        mock.patch.object(
            proxy_req,
            "_send",
            autospec=True,
            spec_set=True,
            return_value=proxy_resp,
        ),
        mock.patch.object(
            proxy_resp,
            "start",
            autospec=True,
            spec_set=True,
            return_value=mock.Mock(status=200),
        ),
    ):
        connector = aiohttp.TCPConnector(enable_cleanup_closed=cleanup)
        host = [
            {
                "hostname": "hostname",
                "host": "127.0.0.1",
                "port": 80,
                "family": socket.AF_INET,
                "proto": 0,
                "flags": 0,
            }
        ]
        with (
            mock.patch.object(
                connector,
                "_resolve_host",
                autospec=True,
                spec_set=True,
                return_value=host,
            ),
            mock.patch.object(
                connector,
                "_get_fingerprint",
                autospec=True,
                spec_set=True,
                return_value=fingerprint_mock,
            ),
            mock.patch.object(  # Called on connection to http://proxy.example.com
                event_loop,
                "create_connection",
                autospec=True,
                spec_set=True,
                return_value=(mock.Mock(), mock.Mock()),
            ),
            mock.patch.object(  # Called on connection to https://www.python.org
                event_loop,
                "start_tls",
                autospec=True,
                spec_set=True,
                return_value=TransportMock(),
            ),
        ):
            req = make_client_request(
                "GET",
                URL("https://www.python.org"),
                proxy=URL("http://proxy.example.com"),
                loop=event_loop,
            )
            with pytest.raises(aiohttp.ServerFingerprintMismatch):
                await connector._create_connection(req, [], aiohttp.ClientTimeout())


@mock.patch("aiohttp.connector.ClientRequestBase")
@mock.patch(
    "aiohttp.connector.aiohappyeyeballs.start_connection",
    autospec=True,
    spec_set=True,
)
async def test_https_connect(  # type: ignore[misc]
    start_connection: mock.Mock,
    ClientRequestMock: mock.Mock,
    make_client_request: _RequestMaker,
) -> None:
    event_loop = asyncio.get_running_loop()
    proxy_req = ClientRequestBase(
        "GET",
        URL("http://proxy.example.com"),
        auth=None,
        loop=event_loop,
        ssl=True,
        headers=CIMultiDict({}),
    )
    ClientRequestMock.return_value = proxy_req

    proxy_resp = ClientResponse(
        "get",
        URL("http://proxy.example.com"),
        request_info=mock.Mock(),
        writer=None,
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=event_loop,
        session=mock.Mock(),
    )
    with mock.patch.object(proxy_req, "_send", autospec=True, return_value=proxy_resp):
        with mock.patch.object(proxy_resp, "start", autospec=True) as m:
            m.return_value.status = 200

            connector = aiohttp.TCPConnector()
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
                    event_loop,
                    "create_connection",
                    autospec=True,
                    return_value=(tr, proto),
                ):
                    with mock.patch.object(
                        event_loop,
                        "start_tls",
                        autospec=True,
                        return_value=mock.Mock(),
                    ):
                        req = make_client_request(
                            "GET",
                            URL("https://www.python.org"),
                            proxy=URL("http://proxy.example.com"),
                            loop=event_loop,
                        )
                        await connector._create_connection(
                            req, [], aiohttp.ClientTimeout()
                        )

                        assert req.url.path == "/"
                        assert proxy_req.method == "CONNECT"
                        assert proxy_req.url == URL("https://www.python.org")

                        proxy_resp.close()
                        await req._close()
            await connector.close()


@mock.patch("aiohttp.connector.ClientRequestBase")
@mock.patch(
    "aiohttp.connector.aiohappyeyeballs.start_connection",
    autospec=True,
    spec_set=True,
)
async def test_https_connect_certificate_error(  # type: ignore[misc]
    start_connection: mock.Mock,
    ClientRequestMock: mock.Mock,
    make_client_request: _RequestMaker,
) -> None:
    event_loop = asyncio.get_running_loop()
    proxy_req = ClientRequestBase(
        "GET",
        URL("http://proxy.example.com"),
        auth=None,
        loop=event_loop,
        ssl=True,
        headers=CIMultiDict({}),
    )
    ClientRequestMock.return_value = proxy_req

    proxy_resp = ClientResponse(
        "get",
        URL("http://proxy.example.com"),
        request_info=mock.Mock(),
        writer=None,
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=event_loop,
        session=mock.Mock(),
    )
    with mock.patch.object(proxy_req, "_send", autospec=True, return_value=proxy_resp):
        with mock.patch.object(proxy_resp, "start", autospec=True) as m:
            m.return_value.status = 200

            connector = aiohttp.TCPConnector()
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
                    event_loop,
                    "create_connection",
                    autospec=True,
                    return_value=(tr, proto),
                ):
                    # Called on connection to https://www.python.org
                    with mock.patch.object(
                        event_loop,
                        "start_tls",
                        autospec=True,
                        side_effect=ssl.CertificateError,
                    ):
                        req = make_client_request(
                            "GET",
                            URL("https://www.python.org"),
                            proxy=URL("http://proxy.example.com"),
                            loop=event_loop,
                        )
                        with pytest.raises(aiohttp.ClientConnectorCertificateError):
                            await connector._create_connection(
                                req, [], aiohttp.ClientTimeout()
                            )
            await connector.close()


@mock.patch("aiohttp.connector.ClientRequestBase")
@mock.patch(
    "aiohttp.connector.aiohappyeyeballs.start_connection",
    autospec=True,
    spec_set=True,
)
async def test_https_connect_ssl_error(  # type: ignore[misc]
    start_connection: mock.Mock,
    ClientRequestMock: mock.Mock,
    make_client_request: _RequestMaker,
) -> None:
    event_loop = asyncio.get_running_loop()
    proxy_req = ClientRequestBase(
        "GET",
        URL("http://proxy.example.com"),
        auth=None,
        loop=event_loop,
        ssl=True,
        headers=CIMultiDict({}),
    )
    ClientRequestMock.return_value = proxy_req

    proxy_resp = ClientResponse(
        "get",
        URL("http://proxy.example.com"),
        request_info=mock.Mock(),
        writer=None,
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=event_loop,
        session=mock.Mock(),
    )
    with mock.patch.object(proxy_req, "_send", autospec=True, return_value=proxy_resp):
        with mock.patch.object(proxy_resp, "start", autospec=True) as m:
            m.return_value.status = 200

            connector = aiohttp.TCPConnector()
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
                    event_loop,
                    "create_connection",
                    autospec=True,
                    return_value=(tr, proto),
                ):
                    # Called on connection to https://www.python.org
                    with mock.patch.object(
                        event_loop,
                        "start_tls",
                        autospec=True,
                        side_effect=ssl.SSLError,
                    ):
                        req = make_client_request(
                            "GET",
                            URL("https://www.python.org"),
                            proxy=URL("http://proxy.example.com"),
                            loop=event_loop,
                        )
                        with pytest.raises(aiohttp.ClientConnectorSSLError):
                            await connector._create_connection(
                                req, [], aiohttp.ClientTimeout()
                            )
            await connector.close()


@mock.patch("aiohttp.connector.ClientRequestBase")
@mock.patch(
    "aiohttp.connector.aiohappyeyeballs.start_connection",
    autospec=True,
    spec_set=True,
)
async def test_https_connect_http_proxy_error(  # type: ignore[misc]
    start_connection: mock.Mock,
    ClientRequestMock: mock.Mock,
    make_client_request: _RequestMaker,
) -> None:
    event_loop = asyncio.get_running_loop()
    proxy_req = ClientRequestBase(
        "GET",
        URL("http://proxy.example.com"),
        auth=None,
        loop=event_loop,
        ssl=True,
        headers=CIMultiDict({}),
    )
    ClientRequestMock.return_value = proxy_req

    proxy_resp = ClientResponse(
        "get",
        URL("http://proxy.example.com"),
        request_info=mock.Mock(),
        writer=None,
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=event_loop,
        session=mock.Mock(),
    )
    with mock.patch.object(proxy_req, "_send", autospec=True, return_value=proxy_resp):
        with mock.patch.object(proxy_resp, "start", autospec=True) as m:
            m.return_value.status = 400
            m.return_value.reason = "bad request"

            connector = aiohttp.TCPConnector()
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
                    event_loop,
                    "create_connection",
                    autospec=True,
                    return_value=(tr, proto),
                ):
                    req = make_client_request(
                        "GET",
                        URL("https://www.python.org"),
                        proxy=URL("http://proxy.example.com"),
                        loop=event_loop,
                    )
                    with pytest.raises(
                        aiohttp.ClientHttpProxyError, match="400, message='bad request'"
                    ):
                        await connector._create_connection(
                            req, [], aiohttp.ClientTimeout()
                        )

                    proxy_resp.close()
                    await req._close()
            await connector.close()


@mock.patch("aiohttp.connector.ClientRequestBase")
@mock.patch(
    "aiohttp.connector.aiohappyeyeballs.start_connection",
    autospec=True,
    spec_set=True,
)
async def test_https_connect_resp_start_error(  # type: ignore[misc]
    start_connection: mock.Mock,
    ClientRequestMock: mock.Mock,
    make_client_request: _RequestMaker,
) -> None:
    event_loop = asyncio.get_running_loop()
    proxy_req = ClientRequestBase(
        "GET",
        URL("http://proxy.example.com"),
        auth=None,
        loop=event_loop,
        ssl=True,
        headers=CIMultiDict({}),
    )
    ClientRequestMock.return_value = proxy_req

    proxy_resp = ClientResponse(
        "get",
        URL("http://proxy.example.com"),
        request_info=mock.Mock(),
        writer=None,
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=event_loop,
        session=mock.Mock(),
    )
    with mock.patch.object(proxy_req, "_send", autospec=True, return_value=proxy_resp):
        with mock.patch.object(
            proxy_resp, "start", autospec=True, side_effect=OSError("error message")
        ):
            connector = aiohttp.TCPConnector()
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
                    event_loop,
                    "create_connection",
                    autospec=True,
                    return_value=(tr, proto),
                ):
                    req = make_client_request(
                        "GET",
                        URL("https://www.python.org"),
                        proxy=URL("http://proxy.example.com"),
                        loop=event_loop,
                    )
                    with pytest.raises(OSError, match="error message"):
                        await connector._create_connection(
                            req, [], aiohttp.ClientTimeout()
                        )
            await connector.close()


@mock.patch("aiohttp.connector.ClientRequest")
@mock.patch(
    "aiohttp.connector.aiohappyeyeballs.start_connection",
    autospec=True,
    spec_set=True,
)
async def test_request_port(  # type: ignore[misc]
    start_connection: mock.Mock,
    ClientRequestMock: mock.Mock,
    make_client_request: _RequestMaker,
) -> None:
    event_loop = asyncio.get_running_loop()
    proxy_req = make_client_request(
        "GET", URL("http://proxy.example.com"), loop=event_loop
    )
    ClientRequestMock.return_value = proxy_req

    connector = aiohttp.TCPConnector()
    r = {
        "hostname": "hostname",
        "host": "127.0.0.1",
        "port": 80,
        "family": socket.AF_INET,
        "proto": 0,
        "flags": 0,
    }
    with mock.patch.object(connector, "_resolve_host", autospec=True, return_value=[r]):
        tr, proto = mock.Mock(), mock.Mock()
        tr.get_extra_info.return_value = None
        # Called on connection to http://proxy.example.com
        with mock.patch.object(
            event_loop, "create_connection", autospec=True, return_value=(tr, proto)
        ):
            req = make_client_request(
                "GET",
                URL("http://localhost:1234/path"),
                proxy=URL("http://proxy.example.com"),
                loop=event_loop,
            )
            await connector._create_connection(req, [], aiohttp.ClientTimeout())
            assert req.url == URL("http://localhost:1234/path")
    await connector.close()


async def test_proxy_auth_property(
    event_loop: asyncio.AbstractEventLoop, make_client_request: _RequestMaker
) -> None:
    req = make_client_request(
        "GET",
        URL("http://localhost:1234/path"),
        proxy=URL("http://proxy.example.com"),
        proxy_auth=aiohttp.helpers.BasicAuth("user", "pass"),
        loop=event_loop,
    )
    assert ("user", "pass", "latin1") == req.proxy_auth


async def test_proxy_auth_property_default(
    event_loop: asyncio.AbstractEventLoop,
    make_client_request: _RequestMaker,
) -> None:
    req = make_client_request(
        "GET",
        URL("http://localhost:1234/path"),
        proxy=URL("http://proxy.example.com"),
        loop=event_loop,
    )
    assert req.proxy_auth is None


@mock.patch("aiohttp.connector.ClientRequestBase")
@mock.patch(
    "aiohttp.connector.aiohappyeyeballs.start_connection",
    autospec=True,
    spec_set=True,
)
async def test_https_connect_pass_ssl_context(  # type: ignore[misc]
    start_connection: mock.Mock,
    ClientRequestMock: mock.Mock,
    make_client_request: _RequestMaker,
) -> None:
    event_loop = asyncio.get_running_loop()
    proxy_req = ClientRequestBase(
        "GET",
        URL("http://proxy.example.com"),
        auth=None,
        loop=event_loop,
        ssl=True,
        headers=CIMultiDict({}),
    )
    ClientRequestMock.return_value = proxy_req

    proxy_resp = ClientResponse(
        "get",
        URL("http://proxy.example.com"),
        request_info=mock.Mock(),
        writer=None,
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=event_loop,
        session=mock.Mock(),
    )
    with mock.patch.object(proxy_req, "_send", autospec=True, return_value=proxy_resp):
        with mock.patch.object(proxy_resp, "start", autospec=True) as m:
            m.return_value.status = 200

            connector = aiohttp.TCPConnector()
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
                    event_loop,
                    "create_connection",
                    autospec=True,
                    return_value=(tr, proto),
                ):
                    with mock.patch.object(
                        event_loop,
                        "start_tls",
                        autospec=True,
                        return_value=mock.Mock(),
                    ) as tls_m:
                        req = make_client_request(
                            "GET",
                            URL("https://www.python.org"),
                            proxy=URL("http://proxy.example.com"),
                            loop=event_loop,
                        )
                        await connector._create_connection(
                            req, [], aiohttp.ClientTimeout()
                        )

                        # ssl_shutdown_timeout=0 is not passed to start_tls
                        tls_m.assert_called_with(
                            mock.ANY,
                            mock.ANY,
                            _SSL_CONTEXT_VERIFIED,
                            server_hostname="www.python.org",
                            ssl_handshake_timeout=mock.ANY,
                        )

                        assert req.url.path == "/"
                        assert proxy_req.method == "CONNECT"
                        assert proxy_req.url == URL("https://www.python.org")

                        proxy_resp.close()
                        await req._close()
            await connector.close()


@mock.patch("aiohttp.connector.ClientRequestBase")
@mock.patch(
    "aiohttp.connector.aiohappyeyeballs.start_connection",
    autospec=True,
    spec_set=True,
)
async def test_https_auth(  # type: ignore[misc]
    start_connection: mock.Mock,
    ClientRequestMock: mock.Mock,
    make_client_request: _RequestMaker,
) -> None:
    event_loop = asyncio.get_running_loop()
    proxy_req = ClientRequestBase(
        "GET",
        URL("http://proxy.example.com"),
        auth=aiohttp.helpers.BasicAuth("user", "pass"),
        loop=event_loop,
        ssl=True,
        headers=CIMultiDict({}),
    )
    ClientRequestMock.return_value = proxy_req

    proxy_resp = ClientResponse(
        "get",
        URL("http://proxy.example.com"),
        request_info=mock.Mock(),
        writer=None,
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=event_loop,
        session=mock.Mock(),
    )
    with mock.patch.object(proxy_req, "_send", autospec=True, return_value=proxy_resp):
        with mock.patch.object(proxy_resp, "start", autospec=True) as m:
            m.return_value.status = 200

            connector = aiohttp.TCPConnector()
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
                    event_loop,
                    "create_connection",
                    autospec=True,
                    return_value=(tr, proto),
                ):
                    with mock.patch.object(
                        event_loop,
                        "start_tls",
                        autospec=True,
                        return_value=mock.Mock(),
                    ):
                        assert "AUTHORIZATION" in proxy_req.headers
                        assert "PROXY-AUTHORIZATION" not in proxy_req.headers

                        req = make_client_request(
                            "GET",
                            URL("https://www.python.org"),
                            proxy=URL("http://proxy.example.com"),
                            loop=event_loop,
                        )
                        assert "AUTHORIZATION" not in req.headers
                        assert "PROXY-AUTHORIZATION" not in req.headers
                        await connector._create_connection(
                            req, [], aiohttp.ClientTimeout()
                        )

                        assert req.url.path == "/"
                        assert "AUTHORIZATION" not in req.headers
                        assert "PROXY-AUTHORIZATION" not in req.headers
                        assert "AUTHORIZATION" not in proxy_req.headers
                        assert "PROXY-AUTHORIZATION" in proxy_req.headers

                        host_m.assert_called_with(
                            "proxy.example.com", 80, traces=mock.ANY
                        )

                        proxy_resp.close()
                        await req._close()
            await connector.close()
