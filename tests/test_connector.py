"""Tests of http client with custom Connector"""

import gc
import asyncio
import unittest

import aiohttp
from aiohttp import client
from aiohttp import test_utils

from tests.test_client_functional import Functional


class UnixSocketConnector(aiohttp.DefaultConnector):

    def __init__(self, path):
        self.path = path

    def create_connection(self, protocol_factory, host, port, *,
                          loop=None, **kwargs):
        if loop is None:
            loop = asyncio.get_event_loop()
        conn = yield from loop.create_unix_connection(
            protocol_factory, self.path, **kwargs)
        return conn


class HttpClientConnectorTests(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        # just in case if we have transport close callbacks
        test_utils.run_briefly(self.loop)

        self.loop.close()
        gc.collect()

    def test_default_connector(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            r = self.loop.run_until_complete(
                client.request('get', httpd.url('method', 'get'),
                               connector=aiohttp.DefaultConnector(),
                               loop=self.loop))
            content = self.loop.run_until_complete(r.content.read())
            content = content.decode()
            self.assertEqual(r.status, 200)
            r.close()

    def test_unix_connector(self):
        path = '/tmp/aiohttp_unix.sock'

        with test_utils.run_server(
                self.loop, listen_addr=path, router=Functional) as httpd:
            r = self.loop.run_until_complete(
                client.request('get', httpd.url('method', 'get'),
                               connector=UnixSocketConnector(path),
                               loop=self.loop))
            content = self.loop.run_until_complete(r.content.read())
            content = content.decode()
            self.assertEqual(r.status, 200)
            r.close()
