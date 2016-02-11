import asyncio
import socket
import ipaddress
import aiodns
import unittest
from aiohttp.resolver import AsyncResolver, DefaultResolver


class BaseResolverTestCase(unittest.TestCase):

    __test__ = False

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def test_positive_lookup(self):
        @asyncio.coroutine
        def go():
            real = yield from self.resolver.resolve('www.python.org')
            ipaddress.ip_address(real[0]['host'])
        self.loop.run_until_complete(go())

    def test_multiple_replies(self):
        @asyncio.coroutine
        def go():
            real = yield from self.resolver.resolve('www.google.com')
            ips = [ipaddress.ip_address(x['host']) for x in real]
            self.assertGreater(len(ips), 3)
        self.loop.run_until_complete(go())


class TestAsyncResolver(BaseResolverTestCase):

    __test__ = True

    def setUp(self):
        super(TestAsyncResolver, self).setUp()
        self.resolver = AsyncResolver(loop=self.loop)

    def test_negative_lookup(self):
        @asyncio.coroutine
        def go():
            with self.assertRaises(aiodns.error.DNSError):
                yield from self.resolver.resolve('doesnotexist.bla')
        self.loop.run_until_complete(go())


class TestExecutorResolver(BaseResolverTestCase):

    __test__ = True

    def setUp(self):
        super(TestExecutorResolver, self).setUp()
        self.resolver = DefaultResolver(loop=self.loop)

    def test_negative_lookup(self):
        @asyncio.coroutine
        def go():
            with self.assertRaises(socket.gaierror):
                yield from self.resolver.resolve('doesnotexist.bla')
        self.loop.run_until_complete(go())
