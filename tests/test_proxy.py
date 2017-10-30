import asyncio
import gc
import hashlib
import socket
import ssl
import unittest
from unittest import mock

from yarl import URL

import aiohttp
from aiohttp.client_reqrep import ClientRequest, ClientResponse
from aiohttp.test_utils import make_mocked_coro


class TestProxy(unittest.TestCase):
    fingerprint = hashlib.sha256(b"foo").digest()
    response_mock_attrs = {
        'status': 200,
    }
    mocked_response = mock.Mock(**response_mock_attrs)
    clientrequest_mock_attrs = {
        'return_value._hashfunc.return_value.digest.return_value': fingerprint,
        'return_value.fingerprint': fingerprint,
        'return_value.send.return_value.start':
            make_mocked_coro(mocked_response),
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

    @mock.patch('aiohttp.connector.ClientRequest')
    def test_connect(self, ClientRequestMock):
        req = ClientRequest(
            'GET', URL('http://www.python.org'),
            proxy=URL('http://proxy.example.com'),
            loop=self.loop
        )
        self.assertEqual(str(req.proxy), 'http://proxy.example.com')

        # mock all the things!
        connector = aiohttp.TCPConnector(loop=self.loop)
        connector._resolve_host = make_mocked_coro([mock.MagicMock()])

        proto = mock.Mock(**{
            'transport.get_extra_info.return_value': False,
        })
        self.loop.create_connection = make_mocked_coro(
            (proto.transport, proto))
        conn = self.loop.run_until_complete(connector.connect(req))
        self.assertEqual(req.url, URL('http://www.python.org'))
        self.assertIs(conn._protocol, proto)
        self.assertIs(conn.transport, proto.transport)

        ClientRequestMock.assert_called_with(
            'GET', URL('http://proxy.example.com'),
            auth=None,
            fingerprint=None,
            headers={'Host': 'www.python.org'},
            loop=self.loop,
            ssl_context=None,
            verify_ssl=None)

    @mock.patch('aiohttp.connector.ClientRequest')
    def test_proxy_headers(self, ClientRequestMock):
        req = ClientRequest(
            'GET', URL('http://www.python.org'),
            proxy=URL('http://proxy.example.com'),
            proxy_headers={'Foo': 'Bar'},
            loop=self.loop)
        self.assertEqual(str(req.proxy), 'http://proxy.example.com')

        # mock all the things!
        connector = aiohttp.TCPConnector(loop=self.loop)
        connector._resolve_host = make_mocked_coro([mock.MagicMock()])

        proto = mock.Mock(**{
            'transport.get_extra_info.return_value': False,
        })
        self.loop.create_connection = make_mocked_coro(
            (proto.transport, proto))
        conn = self.loop.run_until_complete(connector.connect(req))
        self.assertEqual(req.url, URL('http://www.python.org'))
        self.assertIs(conn._protocol, proto)
        self.assertIs(conn.transport, proto.transport)

        ClientRequestMock.assert_called_with(
            'GET', URL('http://proxy.example.com'),
            auth=None,
            fingerprint=None,
            headers={'Host': 'www.python.org', 'Foo': 'Bar'},
            loop=self.loop,
            ssl_context=None,
            verify_ssl=None)

    @mock.patch('aiohttp.connector.ClientRequest', **clientrequest_mock_attrs)
    def test_connect_req_verify_ssl_true(self, ClientRequestMock):
        req = ClientRequest(
            'GET', URL('https://www.python.org'),
            proxy=URL('http://proxy.example.com'),
            loop=self.loop,
            verify_ssl=True,
        )

        proto = mock.Mock()
        connector = aiohttp.TCPConnector(loop=self.loop)
        connector._create_proxy_connection = mock.MagicMock(
            side_effect=connector._create_proxy_connection)
        connector._create_direct_connection = mock.MagicMock(
            side_effect=connector._create_direct_connection)
        connector._resolve_host = make_mocked_coro([mock.MagicMock()])

        self.loop.create_connection = make_mocked_coro(
            (proto.transport, proto))
        self.loop.run_until_complete(connector.connect(req))

        connector._create_proxy_connection.assert_called_with(req)
        ((proxy_req,), _) = connector._create_direct_connection.call_args
        proxy_req.send.assert_called_with(mock.ANY)

    @mock.patch('aiohttp.connector.ClientRequest', **clientrequest_mock_attrs)
    def test_connect_req_verify_ssl_false(self, ClientRequestMock):
        req = ClientRequest(
            'GET', URL('https://www.python.org'),
            proxy=URL('http://proxy.example.com'),
            loop=self.loop,
            verify_ssl=False,
        )

        proto = mock.Mock()
        connector = aiohttp.TCPConnector(loop=self.loop)
        connector._create_proxy_connection = mock.MagicMock(
            side_effect=connector._create_proxy_connection)
        connector._create_direct_connection = mock.MagicMock(
            side_effect=connector._create_direct_connection)
        connector._resolve_host = make_mocked_coro([mock.MagicMock()])

        self.loop.create_connection = make_mocked_coro(
            (proto.transport, proto))
        self.loop.run_until_complete(connector.connect(req))

        connector._create_proxy_connection.assert_called_with(req)
        ((proxy_req,), _) = connector._create_direct_connection.call_args
        proxy_req.send.assert_called_with(mock.ANY)

    @mock.patch('aiohttp.connector.ClientRequest', **clientrequest_mock_attrs)
    def test_connect_req_fingerprint_ssl_context(self, ClientRequestMock):
        ssl_context = mock.Mock()
        attrs = {
            'return_value.ssl_context': ssl_context,
        }
        ClientRequestMock.configure_mock(**attrs)
        req = ClientRequest(
            'GET', URL('https://www.python.org'),
            proxy=URL('http://proxy.example.com'),
            loop=self.loop,
            verify_ssl=True,
            fingerprint=self.fingerprint,
            ssl_context=ssl_context,
        )

        proto = mock.Mock()
        connector = aiohttp.TCPConnector(loop=self.loop)
        connector._create_proxy_connection = mock.MagicMock(
            side_effect=connector._create_proxy_connection)
        connector._create_direct_connection = mock.MagicMock(
            side_effect=connector._create_direct_connection)
        connector._resolve_host = make_mocked_coro([mock.MagicMock()])

        transport_attrs = {
            'get_extra_info.return_value.getpeercert.return_value': b"foo"
        }
        transport = mock.Mock(**transport_attrs)
        self.loop.create_connection = make_mocked_coro(
            (transport, proto))
        self.loop.run_until_complete(connector.connect(req))

        connector._create_proxy_connection.assert_called_with(req)
        ((proxy_req,), _) = connector._create_direct_connection.call_args
        self.assertTrue(proxy_req.verify_ssl)
        self.assertEqual(proxy_req.fingerprint, req.fingerprint)
        self.assertIs(proxy_req.ssl_context, req.ssl_context)

    def test_proxy_auth(self):
        with self.assertRaises(ValueError) as ctx:
            ClientRequest(
                'GET', URL('http://python.org'),
                proxy=URL('http://proxy.example.com'),
                proxy_auth=('user', 'pass'),
                loop=mock.Mock())
        self.assertEqual(
            ctx.exception.args[0],
            "proxy_auth must be None or BasicAuth() tuple",
        )

    @mock.patch('aiohttp.client_reqrep.PayloadWriter')
    def _test_connect_request_with_unicode_host(self, Request_mock):
        loop = mock.Mock()
        request = ClientRequest("CONNECT", URL("http://éé.com/"),
                                loop=loop)

        request.response_class = mock.Mock()
        request.write_bytes = mock.Mock()
        request.write_bytes.return_value = asyncio.Future(loop=loop)
        request.write_bytes.return_value.set_result(None)
        request.send(mock.Mock())

        Request_mock.assert_called_with(mock.ANY, mock.ANY, "xn--9caa.com:80",
                                        mock.ANY, loop=loop)

    def test_proxy_dns_error(self):
        connector = aiohttp.TCPConnector(loop=self.loop)
        connector._resolve_host = make_mocked_coro(
            raise_exception=OSError('dont take it serious'))

        req = ClientRequest(
            'GET', URL('http://www.python.org'),
            proxy=URL('http://proxy.example.com'),
            loop=self.loop,
        )
        expected_headers = dict(req.headers)
        with self.assertRaises(aiohttp.ClientConnectorError):
            self.loop.run_until_complete(connector.connect(req))
        self.assertEqual(req.url.path, '/')
        self.assertEqual(dict(req.headers), expected_headers)

    def test_proxy_connection_error(self):
        connector = aiohttp.TCPConnector(loop=self.loop)
        connector._resolve_host = make_mocked_coro([{
            'hostname': 'www.python.org',
            'host': '127.0.0.1', 'port': 80,
            'family': socket.AF_INET, 'proto': 0,
            'flags': socket.AI_NUMERICHOST}])
        connector._loop.create_connection = make_mocked_coro(
            raise_exception=OSError('dont take it serious'))

        req = ClientRequest(
            'GET', URL('http://www.python.org'),
            proxy=URL('http://proxy.example.com'),
            loop=self.loop,
        )
        with self.assertRaises(aiohttp.ClientProxyConnectionError):
            self.loop.run_until_complete(connector.connect(req))

    @mock.patch('aiohttp.connector.ClientRequest')
    def test_auth(self, ClientRequestMock):
        proxy_req = ClientRequest(
            'GET', URL('http://proxy.example.com'),
            auth=aiohttp.helpers.BasicAuth('user', 'pass'),
            loop=self.loop
        )
        ClientRequestMock.return_value = proxy_req
        self.assertIn('AUTHORIZATION', proxy_req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', proxy_req.headers)

        connector = aiohttp.TCPConnector(loop=self.loop)
        connector._resolve_host = make_mocked_coro([mock.MagicMock()])

        tr, proto = mock.Mock(), mock.Mock()
        self.loop.create_connection = make_mocked_coro((tr, proto))

        req = ClientRequest(
            'GET', URL('http://www.python.org'),
            proxy=URL('http://proxy.example.com'),
            proxy_auth=aiohttp.helpers.BasicAuth('user', 'pass'),
            loop=self.loop,
        )
        self.assertNotIn('AUTHORIZATION', req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', req.headers)
        conn = self.loop.run_until_complete(connector.connect(req))

        self.assertEqual(req.url, URL('http://www.python.org'))
        self.assertNotIn('AUTHORIZATION', req.headers)
        self.assertIn('PROXY-AUTHORIZATION', req.headers)
        self.assertNotIn('AUTHORIZATION', proxy_req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', proxy_req.headers)

        ClientRequestMock.assert_called_with(
            'GET', URL('http://proxy.example.com'),
            auth=aiohttp.helpers.BasicAuth('user', 'pass'),
            loop=mock.ANY, headers=mock.ANY, fingerprint=None,
            ssl_context=None, verify_ssl=None)
        conn.close()

    def test_auth_utf8(self):
        proxy_req = ClientRequest(
            'GET', URL('http://proxy.example.com'),
            auth=aiohttp.helpers.BasicAuth('юзер', 'пасс', 'utf-8'),
            loop=self.loop)
        self.assertIn('AUTHORIZATION', proxy_req.headers)

    @mock.patch('aiohttp.connector.ClientRequest')
    def test_auth_from_url(self, ClientRequestMock):
        proxy_req = ClientRequest('GET',
                                  URL('http://user:pass@proxy.example.com'),
                                  loop=self.loop)
        ClientRequestMock.return_value = proxy_req
        self.assertIn('AUTHORIZATION', proxy_req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', proxy_req.headers)

        connector = aiohttp.TCPConnector(loop=self.loop)
        connector._resolve_host = make_mocked_coro([mock.MagicMock()])

        tr, proto = mock.Mock(), mock.Mock()
        self.loop.create_connection = make_mocked_coro((tr, proto))

        req = ClientRequest(
            'GET', URL('http://www.python.org'),
            proxy=URL('http://user:pass@proxy.example.com'),
            loop=self.loop,
        )
        self.assertNotIn('AUTHORIZATION', req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', req.headers)
        conn = self.loop.run_until_complete(connector.connect(req))

        self.assertEqual(req.url, URL('http://www.python.org'))
        self.assertNotIn('AUTHORIZATION', req.headers)
        self.assertIn('PROXY-AUTHORIZATION', req.headers)
        self.assertNotIn('AUTHORIZATION', proxy_req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', proxy_req.headers)

        ClientRequestMock.assert_called_with(
            'GET', URL('http://user:pass@proxy.example.com'),
            auth=None, loop=mock.ANY, headers=mock.ANY, fingerprint=None,
            ssl_context=None, verify_ssl=None)
        conn.close()

    @mock.patch('aiohttp.connector.ClientRequest')
    def test_https_connect(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', URL('http://proxy.example.com'),
                                  loop=self.loop)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', URL('http://proxy.example.com'))
        proxy_resp._loop = self.loop
        proxy_req.send = send_mock = mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = make_mocked_coro(mock.Mock(status=200))

        connector = aiohttp.TCPConnector(loop=self.loop)
        connector._resolve_host = make_mocked_coro(
            [{'hostname': 'hostname', 'host': '127.0.0.1', 'port': 80,
              'family': socket.AF_INET, 'proto': 0, 'flags': 0}])

        tr, proto = mock.Mock(), mock.Mock()
        self.loop.create_connection = make_mocked_coro((tr, proto))

        req = ClientRequest(
            'GET', URL('https://www.python.org'),
            proxy=URL('http://proxy.example.com'),
            loop=self.loop,
        )
        self.loop.run_until_complete(connector._create_connection(req))

        self.assertEqual(req.url.path, '/')
        self.assertEqual(proxy_req.method, 'CONNECT')
        self.assertEqual(proxy_req.url, URL('https://www.python.org'))
        tr.close.assert_called_once_with()
        tr.get_extra_info.assert_called_with('socket', default=None)

        self.loop.run_until_complete(proxy_req.close())
        proxy_resp.close()
        self.loop.run_until_complete(req.close())

    @mock.patch('aiohttp.connector.ClientRequest')
    def test_https_connect_certificate_error(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', URL('http://proxy.example.com'),
                                  loop=self.loop)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', URL('http://proxy.example.com'))
        proxy_resp._loop = self.loop
        proxy_req.send = send_mock = mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = make_mocked_coro(mock.Mock(status=200))

        connector = aiohttp.TCPConnector(loop=self.loop)
        connector._resolve_host = make_mocked_coro(
            [{'hostname': 'hostname', 'host': '127.0.0.1', 'port': 80,
              'family': socket.AF_INET, 'proto': 0, 'flags': 0}])

        seq = 0

        @asyncio.coroutine
        def create_connection(*args, **kwargs):
            nonlocal seq
            seq += 1

            # connection to http://proxy.example.com
            if seq == 1:
                return mock.Mock(), mock.Mock()
            # connection to https://www.python.org
            elif seq == 2:
                raise ssl.CertificateError
            else:
                assert False

        self.loop.create_connection = create_connection

        req = ClientRequest(
            'GET', URL('https://www.python.org'),
            proxy=URL('http://proxy.example.com'),
            loop=self.loop,
        )
        with self.assertRaises(aiohttp.ClientConnectorCertificateError):
            self.loop.run_until_complete(connector._create_connection(req))

    @mock.patch('aiohttp.connector.ClientRequest')
    def test_https_connect_ssl_error(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', URL('http://proxy.example.com'),
                                  loop=self.loop)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', URL('http://proxy.example.com'))
        proxy_resp._loop = self.loop
        proxy_req.send = send_mock = mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = make_mocked_coro(mock.Mock(status=200))

        connector = aiohttp.TCPConnector(loop=self.loop)
        connector._resolve_host = make_mocked_coro(
            [{'hostname': 'hostname', 'host': '127.0.0.1', 'port': 80,
              'family': socket.AF_INET, 'proto': 0, 'flags': 0}])

        seq = 0

        @asyncio.coroutine
        def create_connection(*args, **kwargs):
            nonlocal seq
            seq += 1

            # connection to http://proxy.example.com
            if seq == 1:
                return mock.Mock(), mock.Mock()
            # connection to https://www.python.org
            elif seq == 2:
                raise ssl.SSLError
            else:
                assert False

        self.loop.create_connection = create_connection

        req = ClientRequest(
            'GET', URL('https://www.python.org'),
            proxy=URL('http://proxy.example.com'),
            loop=self.loop,
        )
        with self.assertRaises(aiohttp.ClientConnectorSSLError):
            self.loop.run_until_complete(connector._create_connection(req))

    @mock.patch('aiohttp.connector.ClientRequest')
    def test_https_connect_runtime_error(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', URL('http://proxy.example.com'),
                                  loop=self.loop)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', URL('http://proxy.example.com'))
        proxy_resp._loop = self.loop
        proxy_req.send = send_mock = mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = make_mocked_coro(mock.Mock(status=200))

        connector = aiohttp.TCPConnector(loop=self.loop)
        connector._resolve_host = make_mocked_coro(
            [{'hostname': 'hostname', 'host': '127.0.0.1', 'port': 80,
              'family': socket.AF_INET, 'proto': 0, 'flags': 0}])

        tr, proto = mock.Mock(), mock.Mock()
        tr.get_extra_info.return_value = None
        self.loop.create_connection = make_mocked_coro((tr, proto))

        req = ClientRequest(
            'GET', URL('https://www.python.org'),
            proxy=URL('http://proxy.example.com'),
            loop=self.loop,
        )
        with self.assertRaisesRegex(
                RuntimeError, "Transport does not expose socket instance"):
            self.loop.run_until_complete(connector._create_connection(req))

        self.loop.run_until_complete(proxy_req.close())
        proxy_resp.close()
        self.loop.run_until_complete(req.close())

    @mock.patch('aiohttp.connector.ClientRequest')
    def test_https_connect_http_proxy_error(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', URL('http://proxy.example.com'),
                                  loop=self.loop)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', URL('http://proxy.example.com'))
        proxy_resp._loop = self.loop
        proxy_req.send = send_mock = mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = make_mocked_coro(
            mock.Mock(status=400, reason='bad request'))

        connector = aiohttp.TCPConnector(loop=self.loop)
        connector._resolve_host = make_mocked_coro(
            [{'hostname': 'hostname', 'host': '127.0.0.1', 'port': 80,
              'family': socket.AF_INET, 'proto': 0, 'flags': 0}])

        tr, proto = mock.Mock(), mock.Mock()
        tr.get_extra_info.return_value = None
        self.loop.create_connection = make_mocked_coro((tr, proto))

        req = ClientRequest(
            'GET', URL('https://www.python.org'),
            proxy=URL('http://proxy.example.com'),
            loop=self.loop,
        )
        with self.assertRaisesRegex(
                aiohttp.ClientHttpProxyError, "400, message='bad request'"):
            self.loop.run_until_complete(connector._create_connection(req))

        self.loop.run_until_complete(proxy_req.close())
        proxy_resp.close()
        self.loop.run_until_complete(req.close())

    @mock.patch('aiohttp.connector.ClientRequest')
    def test_https_connect_resp_start_error(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', URL('http://proxy.example.com'),
                                  loop=self.loop)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', URL('http://proxy.example.com'))
        proxy_resp._loop = self.loop
        proxy_req.send = send_mock = mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = make_mocked_coro(
            raise_exception=OSError("error message"))

        connector = aiohttp.TCPConnector(loop=self.loop)
        connector._resolve_host = make_mocked_coro(
            [{'hostname': 'hostname', 'host': '127.0.0.1', 'port': 80,
              'family': socket.AF_INET, 'proto': 0, 'flags': 0}])

        tr, proto = mock.Mock(), mock.Mock()
        tr.get_extra_info.return_value = None
        self.loop.create_connection = make_mocked_coro((tr, proto))

        req = ClientRequest(
            'GET', URL('https://www.python.org'),
            proxy=URL('http://proxy.example.com'),
            loop=self.loop,
        )
        with self.assertRaisesRegex(OSError, "error message"):
            self.loop.run_until_complete(connector._create_connection(req))

    @mock.patch('aiohttp.connector.ClientRequest')
    def test_request_port(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', URL('http://proxy.example.com'),
                                  loop=self.loop)
        ClientRequestMock.return_value = proxy_req

        connector = aiohttp.TCPConnector(loop=self.loop)
        connector._resolve_host = make_mocked_coro(
            [{'hostname': 'hostname', 'host': '127.0.0.1', 'port': 80,
              'family': socket.AF_INET, 'proto': 0, 'flags': 0}])

        tr, proto = mock.Mock(), mock.Mock()
        tr.get_extra_info.return_value = None
        self.loop.create_connection = make_mocked_coro((tr, proto))

        req = ClientRequest(
            'GET', URL('http://localhost:1234/path'),
            proxy=URL('http://proxy.example.com'),
            loop=self.loop,
        )
        self.loop.run_until_complete(connector._create_connection(req))
        self.assertEqual(req.url, URL('http://localhost:1234/path'))

    def test_proxy_auth_property(self):
        req = aiohttp.ClientRequest(
            'GET', URL('http://localhost:1234/path'),
            proxy=URL('http://proxy.example.com'),
            proxy_auth=aiohttp.helpers.BasicAuth('user', 'pass'),
            loop=self.loop)
        self.assertEqual(('user', 'pass', 'latin1'), req.proxy_auth)

    def test_proxy_auth_property_default(self):
        req = aiohttp.ClientRequest(
            'GET', URL('http://localhost:1234/path'),
            proxy=URL('http://proxy.example.com'),
            loop=self.loop)
        self.assertIsNone(req.proxy_auth)

    @mock.patch('aiohttp.connector.ClientRequest')
    def test_https_connect_pass_ssl_context(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', URL('http://proxy.example.com'),
                                  loop=self.loop)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', URL('http://proxy.example.com'))
        proxy_resp._loop = self.loop
        proxy_req.send = send_mock = mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = make_mocked_coro(mock.Mock(status=200))

        connector = aiohttp.TCPConnector(loop=self.loop)
        connector._resolve_host = make_mocked_coro(
            [{'hostname': 'hostname', 'host': '127.0.0.1', 'port': 80,
              'family': socket.AF_INET, 'proto': 0, 'flags': 0}])

        tr, proto = mock.Mock(), mock.Mock()
        self.loop.create_connection = make_mocked_coro((tr, proto))

        req = ClientRequest(
            'GET', URL('https://www.python.org'),
            proxy=URL('http://proxy.example.com'),
            loop=self.loop,
        )
        self.loop.run_until_complete(connector._create_connection(req))

        self.loop.create_connection.assert_called_with(
            mock.ANY,
            ssl=connector.ssl_context,
            sock=mock.ANY,
            server_hostname='www.python.org')

        self.assertEqual(req.url.path, '/')
        self.assertEqual(proxy_req.method, 'CONNECT')
        self.assertEqual(proxy_req.url, URL('https://www.python.org'))
        tr.close.assert_called_once_with()
        tr.get_extra_info.assert_called_with('socket', default=None)

        self.loop.run_until_complete(proxy_req.close())
        proxy_resp.close()
        self.loop.run_until_complete(req.close())

    @mock.patch('aiohttp.connector.ClientRequest')
    def test_https_auth(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', URL('http://proxy.example.com'),
                                  auth=aiohttp.helpers.BasicAuth('user',
                                                                 'pass'),
                                  loop=self.loop)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', URL('http://proxy.example.com'))
        proxy_resp._loop = self.loop
        proxy_req.send = send_mock = mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = make_mocked_coro(mock.Mock(status=200))

        connector = aiohttp.TCPConnector(loop=self.loop)
        connector._resolve_host = make_mocked_coro(
            [{'hostname': 'hostname', 'host': '127.0.0.1', 'port': 80,
              'family': socket.AF_INET, 'proto': 0, 'flags': 0}])

        tr, proto = mock.Mock(), mock.Mock()
        self.loop.create_connection = make_mocked_coro((tr, proto))

        self.assertIn('AUTHORIZATION', proxy_req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', proxy_req.headers)

        req = ClientRequest(
            'GET', URL('https://www.python.org'),
            proxy=URL('http://proxy.example.com'),
            loop=self.loop
        )
        self.assertNotIn('AUTHORIZATION', req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', req.headers)
        self.loop.run_until_complete(connector._create_connection(req))

        self.assertEqual(req.url.path, '/')
        self.assertNotIn('AUTHORIZATION', req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', req.headers)
        self.assertNotIn('AUTHORIZATION', proxy_req.headers)
        self.assertIn('PROXY-AUTHORIZATION', proxy_req.headers)

        connector._resolve_host.assert_called_with('proxy.example.com', 80)

        self.loop.run_until_complete(proxy_req.close())
        proxy_resp.close()
        self.loop.run_until_complete(req.close())
