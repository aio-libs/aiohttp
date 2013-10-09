"""Tests for asynchttp/worker.py"""
import inspect
import tulip
import unittest
import unittest.mock
import urllib.parse

import asynchttp
from asynchttp import worker
from asynchttp.wsgi import WSGIServerHttpProtocol


class TestWorker(worker.AsyncGunicornWorker):

    def __init__(self):
        pass


class WorkerTests(unittest.TestCase):

    def setUp(self):
        self.loop = tulip.new_event_loop()
        tulip.set_event_loop(None)
        self.worker = TestWorker()

    def tearDown(self):
        self.loop.close()

    @unittest.mock.patch('asynchttp.worker.tulip')
    def test_init_process(self, m_tulip):
        try:
            self.worker.init_process()
        except AttributeError:
            pass

        self.assertTrue(m_tulip.get_event_loop.return_value.close.called)
        self.assertTrue(m_tulip.new_event_loop.called)
        self.assertTrue(m_tulip.set_event_loop.called)

    @unittest.mock.patch('asynchttp.worker.tulip')
    def test_run(self, m_tulip):
        self.worker.loop = unittest.mock.Mock()
        self.worker.run()

        self.assertTrue(m_tulip.async.called)
        self.assertTrue(self.worker.loop.run_until_complete.called)
        self.assertTrue(self.worker.loop.close.called)

    def test_factory(self):
        self.worker.wsgi = unittest.mock.Mock()
        self.worker.loop = unittest.mock.Mock()
        f = self.worker.factory()

        self.assertIsInstance(f, WSGIServerHttpProtocol)

    @unittest.mock.patch('asynchttp.worker.tulip')
    def test__run(self, m_tulip):
        self.worker.ppid = 1
        self.worker.alive = True
        self.worker.sockets = [unittest.mock.Mock()]
        self.worker.log = unittest.mock.Mock()
        self.worker.loop = unittest.mock.Mock()
        self.worker.notify = unittest.mock.Mock()

        self.loop.run_until_complete(self.worker._run())

        self.assertTrue(self.worker.log.info.called)
        self.assertTrue(self.worker.notify.called)

    @unittest.mock.patch('asynchttp.worker.os')
    @unittest.mock.patch('asynchttp.worker.tulip.sleep')
    def test__run_exc(self, m_sleep, m_os):
        m_os.getpid.return_value = 1
        m_os.getppid.return_value = 1

        self.worker.ppid = 1
        self.worker.alive = True
        self.worker.sockets = []
        self.worker.log = unittest.mock.Mock()
        self.worker.loop = unittest.mock.Mock()
        self.worker.notify = unittest.mock.Mock()

        slp = tulip.Future(loop=self.loop)
        slp.set_exception(KeyboardInterrupt)
        m_sleep.return_value = slp

        self.loop.run_until_complete(self.worker._run())
        self.assertTrue(m_sleep.called)
