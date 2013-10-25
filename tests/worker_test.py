"""Tests for aiohttp/worker.py"""
import asyncio
import unittest
import unittest.mock

from aiohttp import worker
from aiohttp.wsgi import WSGIServerHttpProtocol


class TestWorker(worker.AsyncGunicornWorker):

    def __init__(self):
        pass


class WorkerTests(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.worker = TestWorker()

    def tearDown(self):
        self.loop.close()

    @unittest.mock.patch('aiohttp.worker.asyncio')
    def test_init_process(self, m_asyncio):
        try:
            self.worker.init_process()
        except AttributeError:
            pass

        self.assertTrue(m_asyncio.get_event_loop.return_value.close.called)
        self.assertTrue(m_asyncio.new_event_loop.called)
        self.assertTrue(m_asyncio.set_event_loop.called)

    @unittest.mock.patch('aiohttp.worker.asyncio')
    def test_run(self, m_asyncio):
        self.worker.loop = unittest.mock.Mock()
        self.worker.run()

        self.assertTrue(m_asyncio.async.called)
        self.assertTrue(self.worker.loop.run_until_complete.called)
        self.assertTrue(self.worker.loop.close.called)

    def test_factory(self):
        self.worker.wsgi = unittest.mock.Mock()
        self.worker.loop = unittest.mock.Mock()
        self.worker.log = unittest.mock.Mock()
        self.worker.cfg = unittest.mock.Mock()

        f = self.worker.factory()
        self.assertIsInstance(f, WSGIServerHttpProtocol)

    @unittest.mock.patch('aiohttp.worker.asyncio')
    def test__run(self, m_asyncio):
        self.worker.ppid = 1
        self.worker.alive = True
        self.worker.servers = []
        self.worker.sockets = [unittest.mock.Mock()]
        self.worker.log = unittest.mock.Mock()
        self.worker.loop = unittest.mock.Mock()
        self.worker.notify = unittest.mock.Mock()

        self.loop.run_until_complete(self.worker._run())

        m_asyncio.async.return_value.add_done_callback.call_args[0][0](
            self.worker.sockets[0])

        self.assertTrue(self.worker.log.info.called)
        self.assertTrue(self.worker.notify.called)

    @unittest.mock.patch('aiohttp.worker.os')
    @unittest.mock.patch('aiohttp.worker.asyncio.sleep')
    def test__run_exc(self, m_sleep, m_os):
        m_os.getpid.return_value = 1
        m_os.getppid.return_value = 1

        self.worker.servers = [unittest.mock.Mock()]
        self.worker.ppid = 1
        self.worker.alive = True
        self.worker.sockets = []
        self.worker.log = unittest.mock.Mock()
        self.worker.loop = unittest.mock.Mock()
        self.worker.notify = unittest.mock.Mock()

        slp = asyncio.Future(loop=self.loop)
        slp.set_exception(KeyboardInterrupt)
        m_sleep.return_value = slp

        self.loop.run_until_complete(self.worker._run())
        self.assertTrue(m_sleep.called)
        self.assertTrue(self.worker.servers[0].close.called)
