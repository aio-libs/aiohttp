# -*- coding: utf-8 -*-
"""Tests for aiohttp/client.py"""

import asyncio
import gc
import unittest
from unittest import mock

import aiohttp
from aiohttp import helpers
from aiohttp.client_reqrep import ClientResponse


class TestClientResponse(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

        self.connection = mock.Mock()
        self.stream = aiohttp.StreamParser(loop=self.loop)
        self.response = ClientResponse('get', 'http://def-cl-resp.org')
        self.response._post_init(self.loop)
        self.response._setup_connection(self.connection)

    def tearDown(self):
        self.response.close()
        self.loop.close()
        gc.collect()

    def test_del(self):
        response = ClientResponse('get', 'http://del-cl-resp.org')
        response._post_init(self.loop)

        connection = mock.Mock()
        response._setup_connection(connection)
        self.loop.set_exception_handler(lambda loop, ctx: None)

        with self.assertWarns(ResourceWarning):
            del response
            gc.collect()

        connection.close.assert_called_with()

    def test_close(self):
        self.response._connection = self.connection
        self.response.close()
        self.assertIsNone(self.response.connection)
        self.response.close()
        self.response.close()

    def test_wait_for_100_1(self):
        response = ClientResponse(
            'get', 'http://python.org', continue100=object())
        response._post_init(self.loop)
        self.assertTrue(response.waiting_for_continue())
        response.close()

    def test_wait_for_100_2(self):
        response = ClientResponse(
            'get', 'http://python.org')
        response._post_init(self.loop)
        self.assertFalse(response.waiting_for_continue())
        response.close()

    def test_repr(self):
        self.response.status = 200
        self.response.reason = 'Ok'
        self.assertIn(
            '<ClientResponse(http://def-cl-resp.org) [200 Ok]>',
            repr(self.response))

    def test_repr_non_ascii_url(self):
        response = ClientResponse('get', 'http://fake-host.org/\u03bb')
        self.assertIn(
            "<ClientResponse(http://fake-host.org/\\u03bb) [None None]>",
            repr(response))

    def test_repr_non_ascii_reason(self):
        response = ClientResponse('get', 'http://fake-host.org/path')
        response.reason = '\u03bb'
        self.assertIn(
            "<ClientResponse(http://fake-host.org/path) [None \\u03bb]>",
            repr(response))

    def test_read_and_release_connection(self):
        def side_effect(*args, **kwargs):
            fut = helpers.create_future(self.loop)
            fut.set_result(b'payload')
            return fut
        content = self.response.content = mock.Mock()
        content.read.side_effect = side_effect

        res = self.loop.run_until_complete(self.response.read())
        self.assertEqual(res, b'payload')
        self.assertIsNone(self.response._connection)

    def test_read_and_release_connection_with_error(self):
        content = self.response.content = mock.Mock()
        content.read.return_value = helpers.create_future(self.loop)
        content.read.return_value.set_exception(ValueError)

        self.assertRaises(
            ValueError,
            self.loop.run_until_complete, self.response.read())
        self.assertTrue(self.response._closed)

    def test_release(self):
        fut = helpers.create_future(self.loop)
        fut.set_result(b'')
        content = self.response.content = mock.Mock()
        content.readany.return_value = fut

        self.loop.run_until_complete(self.response.release())
        self.assertIsNone(self.response._connection)

    def test_text(self):
        def side_effect(*args, **kwargs):
            fut = helpers.create_future(self.loop)
            fut.set_result('{"тест": "пройден"}'.encode('cp1251'))
            return fut
        self.response.headers = {
            'Content-Type': 'application/json;charset=cp1251'}
        content = self.response.content = mock.Mock()
        content.read.side_effect = side_effect

        res = self.loop.run_until_complete(self.response.text())
        self.assertEqual(res, '{"тест": "пройден"}')
        self.assertIsNone(self.response._connection)

    def test_text_custom_encoding(self):
        def side_effect(*args, **kwargs):
            fut = helpers.create_future(self.loop)
            fut.set_result('{"тест": "пройден"}'.encode('cp1251'))
            return fut
        self.response.headers = {
            'Content-Type': 'application/json'}
        content = self.response.content = mock.Mock()
        content.read.side_effect = side_effect
        self.response._get_encoding = mock.Mock()

        res = self.loop.run_until_complete(
            self.response.text(encoding='cp1251'))
        self.assertEqual(res, '{"тест": "пройден"}')
        self.assertIsNone(self.response._connection)
        self.assertFalse(self.response._get_encoding.called)

    def test_text_detect_encoding(self):
        def side_effect(*args, **kwargs):
            fut = helpers.create_future(self.loop)
            fut.set_result('{"тест": "пройден"}'.encode('cp1251'))
            return fut
        self.response.headers = {'Content-Type': 'application/json'}
        content = self.response.content = mock.Mock()
        content.read.side_effect = side_effect

        self.loop.run_until_complete(self.response.read())
        res = self.loop.run_until_complete(self.response.text())
        self.assertEqual(res, '{"тест": "пройден"}')
        self.assertIsNone(self.response._connection)

    def test_text_after_read(self):
        def side_effect(*args, **kwargs):
            fut = helpers.create_future(self.loop)
            fut.set_result('{"тест": "пройден"}'.encode('cp1251'))
            return fut
        self.response.headers = {
            'Content-Type': 'application/json;charset=cp1251'}
        content = self.response.content = mock.Mock()
        content.read.side_effect = side_effect

        res = self.loop.run_until_complete(self.response.text())
        self.assertEqual(res, '{"тест": "пройден"}')
        self.assertIsNone(self.response._connection)

    def test_json(self):
        def side_effect(*args, **kwargs):
            fut = helpers.create_future(self.loop)
            fut.set_result('{"тест": "пройден"}'.encode('cp1251'))
            return fut
        self.response.headers = {
            'Content-Type': 'application/json;charset=cp1251'}
        content = self.response.content = mock.Mock()
        content.read.side_effect = side_effect

        res = self.loop.run_until_complete(self.response.json())
        self.assertEqual(res, {'тест': 'пройден'})
        self.assertIsNone(self.response._connection)

    def test_json_custom_loader(self):
        self.response.headers = {
            'Content-Type': 'application/json;charset=cp1251'}
        self.response._content = b'data'

        def custom(content):
            return content + '-custom'

        res = self.loop.run_until_complete(self.response.json(loads=custom))
        self.assertEqual(res, 'data-custom')

    @mock.patch('aiohttp.client_reqrep.client_logger')
    def test_json_no_content(self, m_log):
        self.response.headers = {
            'Content-Type': 'data/octet-stream'}
        self.response._content = b''

        res = self.loop.run_until_complete(self.response.json())
        self.assertIsNone(res)
        m_log.warning.assert_called_with(
            'Attempt to decode JSON with unexpected mimetype: %s',
            'data/octet-stream')

    def test_json_override_encoding(self):
        def side_effect(*args, **kwargs):
            fut = helpers.create_future(self.loop)
            fut.set_result('{"тест": "пройден"}'.encode('cp1251'))
            return fut
        self.response.headers = {
            'Content-Type': 'application/json;charset=utf8'}
        content = self.response.content = mock.Mock()
        content.read.side_effect = side_effect
        self.response._get_encoding = mock.Mock()

        res = self.loop.run_until_complete(
            self.response.json(encoding='cp1251'))
        self.assertEqual(res, {'тест': 'пройден'})
        self.assertIsNone(self.response._connection)
        self.assertFalse(self.response._get_encoding.called)

    def test_json_detect_encoding(self):
        def side_effect(*args, **kwargs):
            fut = helpers.create_future(self.loop)
            fut.set_result('{"тест": "пройден"}'.encode('cp1251'))
            return fut
        self.response.headers = {'Content-Type': 'application/json'}
        content = self.response.content = mock.Mock()
        content.read.side_effect = side_effect

        res = self.loop.run_until_complete(self.response.json())
        self.assertEqual(res, {'тест': 'пройден'})
        self.assertIsNone(self.response._connection)

    def test_override_flow_control(self):
        class MyResponse(ClientResponse):
            flow_control_class = aiohttp.StreamReader
        response = MyResponse('get', 'http://my-cl-resp.org')
        response._post_init(self.loop)
        response._setup_connection(self.connection)
        self.assertIsInstance(response.content, aiohttp.StreamReader)
        response.close()

    @mock.patch('aiohttp.client_reqrep.chardet')
    def test_get_encoding_unknown(self, m_chardet):
        m_chardet.detect.return_value = {'encoding': None}

        self.response.headers = {'Content-Type': 'application/json'}
        self.assertEqual(self.response._get_encoding(), 'utf-8')

    def test_raise_for_status_2xx(self):
        self.response.status = 200
        self.response.reason = 'OK'
        self.response.raise_for_status()  # should not raise

    def test_raise_for_status_4xx(self):
        self.response.status = 409
        self.response.reason = 'CONFLICT'
        with self.assertRaises(aiohttp.HttpProcessingError) as cm:
            self.response.raise_for_status()
        self.assertEqual(str(cm.exception.code), '409')
        self.assertEqual(str(cm.exception.message), "CONFLICT")
