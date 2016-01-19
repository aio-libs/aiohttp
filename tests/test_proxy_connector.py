import unittest
import asyncio
import gc
import aiohttp
from aiohttp.client_reqrep import ClientRequest, ClientResponse
from unittest import mock


class TestProxyConnector(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        # just in case if we have transport close callbacks
        self.loop.stop()
        self.loop.run_forever()
        self.loop.close()
        gc.collect()

    def _fake_coroutine(self, mock, return_value):

        def coro(*args, **kw):
            if isinstance(return_value, Exception):
                raise return_value
            return return_value
            yield  # pragma: no cover
        mock.side_effect = coro

    def test_ctor(self):
        with self.assertRaises(AssertionError):
            aiohttp.ProxyConnector('https://localhost:8118', loop=self.loop)

    def test_ctor2(self):
        connector = aiohttp.ProxyConnector('http://localhost:8118',
                                           loop=self.loop)

        self.assertEqual('http://localhost:8118', connector.proxy)
        self.assertTrue(connector.force_close)

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_connect(self, ClientRequestMock):
        req = ClientRequest('GET', 'http://www.python.org', loop=self.loop)
        self.assertEqual(req.path, '/')

        loop_mock = unittest.mock.Mock()
        connector = aiohttp.ProxyConnector('http://proxy.example.com',
                                           loop=loop_mock)
        self.assertIs(loop_mock, connector._loop)

        resolve_host = unittest.mock.Mock()
        self._fake_coroutine(resolve_host, [unittest.mock.MagicMock()])
        connector._resolve_host = resolve_host

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))
        conn = self.loop.run_until_complete(connector.connect(req))
        self.assertEqual(req.path, 'http://www.python.org/')
        self.assertIs(conn._transport, tr)
        self.assertIs(conn._protocol, proto)

        # resolve_host.assert_called_once_with('proxy.example.com', 80)
        tr.get_extra_info.assert_called_once_with('sslcontext')

        ClientRequestMock.assert_called_with(
            'GET', 'http://proxy.example.com',
            auth=None,
            headers={'HOST': 'www.python.org'},
            loop=loop_mock)
        conn.close()

    def test_proxy_auth(self):
        with self.assertRaises(AssertionError) as ctx:
            aiohttp.ProxyConnector('http://proxy.example.com',
                                   proxy_auth=('user', 'pass'),
                                   loop=unittest.mock.Mock())
        self.assertEqual(ctx.exception.args[0],
                         ("proxy_auth must be None or BasicAuth() tuple",
                          ('user', 'pass')))

    def test_proxy_connection_error(self):
        connector = aiohttp.ProxyConnector('http://proxy.example.com',
                                           loop=self.loop)
        connector._resolve_host = resolve_mock = unittest.mock.Mock()
        self._fake_coroutine(resolve_mock, OSError('dont take it serious'))

        req = ClientRequest('GET', 'http://www.python.org', loop=self.loop)
        expected_headers = dict(req.headers)
        with self.assertRaises(aiohttp.ProxyConnectionError):
            self.loop.run_until_complete(connector.connect(req))
        self.assertEqual(req.path, '/')
        self.assertEqual(dict(req.headers), expected_headers)

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_auth(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', 'http://proxy.example.com',
                                  auth=aiohttp.helpers.BasicAuth('user',
                                                                 'pass'),
                                  loop=self.loop)
        ClientRequestMock.return_value = proxy_req
        self.assertIn('AUTHORIZATION', proxy_req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', proxy_req.headers)

        loop_mock = unittest.mock.Mock()
        connector = aiohttp.ProxyConnector(
            'http://proxy.example.com', loop=loop_mock,
            proxy_auth=aiohttp.helpers.BasicAuth('user', 'pass'))
        connector._resolve_host = resolve_mock = unittest.mock.Mock()
        self._fake_coroutine(resolve_mock, [unittest.mock.MagicMock()])

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        req = ClientRequest('GET', 'http://www.python.org', loop=self.loop)
        self.assertNotIn('AUTHORIZATION', req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', req.headers)
        conn = self.loop.run_until_complete(connector.connect(req))

        self.assertEqual(req.path, 'http://www.python.org/')
        self.assertNotIn('AUTHORIZATION', req.headers)
        self.assertIn('PROXY-AUTHORIZATION', req.headers)
        self.assertNotIn('AUTHORIZATION', proxy_req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', proxy_req.headers)

        ClientRequestMock.assert_called_with(
            'GET', 'http://proxy.example.com',
            auth=aiohttp.helpers.BasicAuth('user', 'pass'),
            loop=unittest.mock.ANY, headers=unittest.mock.ANY)
        conn.close()

    def test_auth_utf8(self):
        proxy_req = ClientRequest(
            'GET', 'http://proxy.example.com',
            auth=aiohttp.helpers.BasicAuth('юзер', 'пасс', 'utf-8'),
            loop=self.loop)
        self.assertIn('AUTHORIZATION', proxy_req.headers)

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_auth_from_url(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', 'http://user:pass@proxy.example.com',
                                  loop=self.loop)
        ClientRequestMock.return_value = proxy_req
        self.assertIn('AUTHORIZATION', proxy_req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', proxy_req.headers)

        loop_mock = unittest.mock.Mock()
        connector = aiohttp.ProxyConnector(
            'http://user:pass@proxy.example.com', loop=loop_mock)
        connector._resolve_host = resolve_mock = unittest.mock.Mock()
        self._fake_coroutine(resolve_mock, [unittest.mock.MagicMock()])

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        req = ClientRequest('GET', 'http://www.python.org', loop=self.loop)
        self.assertNotIn('AUTHORIZATION', req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', req.headers)
        conn = self.loop.run_until_complete(connector.connect(req))

        self.assertEqual(req.path, 'http://www.python.org/')
        self.assertNotIn('AUTHORIZATION', req.headers)
        self.assertIn('PROXY-AUTHORIZATION', req.headers)
        self.assertNotIn('AUTHORIZATION', proxy_req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', proxy_req.headers)

        ClientRequestMock.assert_called_with(
            'GET', 'http://user:pass@proxy.example.com',
            auth=None, loop=unittest.mock.ANY, headers=unittest.mock.ANY)
        conn.close()

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_auth__not_modifying_request(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', 'http://user:pass@proxy.example.com',
                                  loop=self.loop)
        ClientRequestMock.return_value = proxy_req
        proxy_req_headers = dict(proxy_req.headers)

        loop_mock = unittest.mock.Mock()
        connector = aiohttp.ProxyConnector(
            'http://user:pass@proxy.example.com', loop=loop_mock)
        connector._resolve_host = resolve_mock = unittest.mock.Mock()
        self._fake_coroutine(resolve_mock, OSError('nothing personal'))

        req = ClientRequest('GET', 'http://www.python.org', loop=self.loop)
        req_headers = dict(req.headers)
        with self.assertRaises(aiohttp.ProxyConnectionError):
            self.loop.run_until_complete(connector.connect(req))
        self.assertEqual(req.headers, req_headers)
        self.assertEqual(req.path, '/')
        self.assertEqual(proxy_req.headers, proxy_req_headers)

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_https_connect(self, ClientRequestMock):
        loop_mock = unittest.mock.Mock()
        proxy_req = ClientRequest('GET', 'http://proxy.example.com',
                                  loop=loop_mock)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', 'http://proxy.example.com')
        proxy_resp._loop = loop_mock
        proxy_req.send = send_mock = unittest.mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = start_mock = unittest.mock.Mock()
        self._fake_coroutine(start_mock, unittest.mock.Mock(status=200))

        connector = aiohttp.ProxyConnector(
            'http://proxy.example.com', loop=loop_mock)

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        req = ClientRequest('GET', 'https://www.python.org', loop=self.loop)
        self.loop.run_until_complete(connector._create_connection(req))

        self.assertEqual(req.path, '/')
        self.assertEqual(proxy_req.method, 'CONNECT')
        self.assertEqual(proxy_req.path, 'www.python.org:443')
        tr.pause_reading.assert_called_once_with()
        tr.get_extra_info.assert_called_with('socket', default=None)

        self.loop.run_until_complete(proxy_req.close())
        proxy_resp.close()
        self.loop.run_until_complete(req.close())

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_https_connect_runtime_error(self, ClientRequestMock):
        loop_mock = unittest.mock.Mock()
        proxy_req = ClientRequest('GET', 'http://proxy.example.com',
                                  loop=loop_mock)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', 'http://proxy.example.com')
        proxy_resp._loop = loop_mock
        proxy_req.send = send_mock = unittest.mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = start_mock = unittest.mock.Mock()
        self._fake_coroutine(start_mock, unittest.mock.Mock(status=200))

        connector = aiohttp.ProxyConnector(
            'http://proxy.example.com', loop=loop_mock)

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        tr.get_extra_info.return_value = None
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        req = ClientRequest('GET', 'https://www.python.org', loop=self.loop)
        with self.assertRaisesRegex(
                RuntimeError, "Transport does not expose socket instance"):
            self.loop.run_until_complete(connector._create_connection(req))

        self.loop.run_until_complete(proxy_req.close())
        proxy_resp.close()
        self.loop.run_until_complete(req.close())

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_https_connect_http_proxy_error(self, ClientRequestMock):
        loop_mock = unittest.mock.Mock()
        proxy_req = ClientRequest('GET', 'http://proxy.example.com',
                                  loop=loop_mock)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', 'http://proxy.example.com')
        proxy_resp._loop = loop_mock
        proxy_req.send = send_mock = unittest.mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = start_mock = unittest.mock.Mock()
        self._fake_coroutine(
            start_mock, unittest.mock.Mock(status=400, reason='bad request'))

        connector = aiohttp.ProxyConnector(
            'http://proxy.example.com', loop=loop_mock)

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        tr.get_extra_info.return_value = None
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        req = ClientRequest('GET', 'https://www.python.org', loop=self.loop)
        with self.assertRaisesRegex(
                aiohttp.HttpProxyError, "400, message='bad request'"):
            self.loop.run_until_complete(connector._create_connection(req))

        self.loop.run_until_complete(proxy_req.close())
        proxy_resp.close()
        self.loop.run_until_complete(req.close())

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_https_connect_resp_start_error(self, ClientRequestMock):
        loop_mock = unittest.mock.Mock()
        proxy_req = ClientRequest('GET', 'http://proxy.example.com',
                                  loop=loop_mock)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', 'http://proxy.example.com')
        proxy_resp._loop = loop_mock
        proxy_req.send = send_mock = unittest.mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = start_mock = unittest.mock.Mock()
        self._fake_coroutine(start_mock, OSError("error message"))

        connector = aiohttp.ProxyConnector(
            'http://proxy.example.com', loop=loop_mock)

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        tr.get_extra_info.return_value = None
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        req = ClientRequest('GET', 'https://www.python.org', loop=self.loop)
        with self.assertRaisesRegex(OSError, "error message"):
            self.loop.run_until_complete(connector._create_connection(req))

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_request_port(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', 'http://proxy.example.com',
                                  loop=self.loop)
        ClientRequestMock.return_value = proxy_req

        loop_mock = unittest.mock.Mock()
        connector = aiohttp.ProxyConnector('http://proxy.example.com',
                                           loop=loop_mock)

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        tr.get_extra_info.return_value = None
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        req = ClientRequest('GET', 'http://localhost:1234/path',
                            loop=self.loop)
        self.loop.run_until_complete(connector._create_connection(req))
        self.assertEqual(req.path, 'http://localhost:1234/path')

    def test_proxy_auth_property(self):
        connector = aiohttp.ProxyConnector(
            'http://proxy.example.com',
            proxy_auth=aiohttp.helpers.BasicAuth('user', 'pass'),
            loop=self.loop)
        self.assertEqual(('user', 'pass', 'latin1'), connector.proxy_auth)
        connector.close()

    def test_proxy_auth_property_default(self):
        connector = aiohttp.ProxyConnector('http://proxy.example.com',
                                           loop=self.loop)
        self.assertIsNone(connector.proxy_auth)
        connector.close()

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_https_connect_pass_ssl_context(self, ClientRequestMock):
        loop_mock = unittest.mock.Mock()
        proxy_req = ClientRequest('GET', 'http://proxy.example.com',
                                  loop=loop_mock)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', 'http://proxy.example.com')
        proxy_resp._loop = loop_mock
        proxy_req.send = send_mock = unittest.mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = start_mock = unittest.mock.Mock()
        self._fake_coroutine(start_mock, unittest.mock.Mock(status=200))

        connector = aiohttp.ProxyConnector(
            'http://proxy.example.com', loop=loop_mock)

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        req = ClientRequest('GET', 'https://www.python.org', loop=self.loop)
        self.loop.run_until_complete(connector._create_connection(req))

        loop_mock.create_connection.assert_called_with(
            mock.ANY,
            ssl=connector.ssl_context,
            sock=mock.ANY,
            server_hostname='www.python.org')

        self.assertEqual(req.path, '/')
        self.assertEqual(proxy_req.method, 'CONNECT')
        self.assertEqual(proxy_req.path, 'www.python.org:443')
        tr.pause_reading.assert_called_once_with()
        tr.get_extra_info.assert_called_with('socket', default=None)

        self.loop.run_until_complete(proxy_req.close())
        proxy_resp.close()
        self.loop.run_until_complete(req.close())

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_https_auth(self, ClientRequestMock):
        loop_mock = unittest.mock.Mock()
        proxy_req = ClientRequest('GET', 'http://proxy.example.com',
                                  auth=aiohttp.helpers.BasicAuth('user',
                                                                 'pass'),
                                  loop=loop_mock)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', 'http://proxy.example.com')
        proxy_resp._loop = loop_mock
        proxy_req.send = send_mock = unittest.mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = start_mock = unittest.mock.Mock()
        self._fake_coroutine(start_mock, unittest.mock.Mock(status=200))

        connector = aiohttp.ProxyConnector(
            'http://proxy.example.com', loop=loop_mock)

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        self.assertIn('AUTHORIZATION', proxy_req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', proxy_req.headers)

        req = ClientRequest('GET', 'https://www.python.org', loop=self.loop)
        self.assertNotIn('AUTHORIZATION', req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', req.headers)
        self.loop.run_until_complete(connector._create_connection(req))

        self.assertEqual(req.path, '/')
        self.assertNotIn('AUTHORIZATION', req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', req.headers)
        self.assertNotIn('AUTHORIZATION', proxy_req.headers)
        self.assertIn('PROXY-AUTHORIZATION', proxy_req.headers)

        self.loop.run_until_complete(proxy_req.close())
        proxy_resp.close()
        self.loop.run_until_complete(req.close())
