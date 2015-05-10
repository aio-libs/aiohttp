"""Tests for aiohttp/worker.py"""
import asyncio
import unittest
import unittest.mock

try:
    from aiohttp import worker
except ImportError as error:  # pragma: no cover
    raise unittest.SkipTest('gunicorn required') from error


class MyWorker(worker.GunicornWebWorker):

    def __init__(self):
        self.servers = []
        self.exit_code = 0
        self.cfg = unittest.mock.Mock()
        self.cfg.graceful_timeout = 100


class TestWorker(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.worker = MyWorker()

    def tearDown(self):
        self.loop.close()

    @unittest.mock.patch('aiohttp.worker.asyncio')
    def test_init_process(self, m_asyncio):
        try:
            self.worker.init_process()
        except TypeError:
            pass

        self.assertTrue(m_asyncio.get_event_loop.return_value.close.called)
        self.assertTrue(m_asyncio.new_event_loop.called)
        self.assertTrue(m_asyncio.set_event_loop.called)

    @unittest.mock.patch('aiohttp.worker.asyncio')
    def test_run(self, m_asyncio):
        self.worker.loop = unittest.mock.Mock()
        with self.assertRaises(SystemExit):
            self.worker.run()

        self.assertTrue(m_asyncio.async.called)
        self.assertTrue(self.worker.loop.run_until_complete.called)
        self.assertTrue(self.worker.loop.close.called)

    def test_handle_quit(self):
        self.worker.handle_quit(object(), object())
        self.assertEqual(self.worker.alive, False)
        self.assertEqual(self.worker.exit_code, 0)

    def test_handle_abort(self):
        self.worker.handle_abort(object(), object())
        self.assertEqual(self.worker.alive, False)
        self.assertEqual(self.worker.exit_code, 1)

    def test_init_signal(self):
        self.worker.loop = unittest.mock.Mock()
        self.worker.init_signal()
        self.assertTrue(self.worker.loop.add_signal_handler.called)

    def test_make_handler(self):
        self.worker.wsgi = unittest.mock.Mock()
        self.worker.loop = unittest.mock.Mock()
        self.worker.log = unittest.mock.Mock()
        self.worker.cfg = unittest.mock.Mock()

        f = self.worker.make_handler(
            self.worker.wsgi, 'localhost', 8080)
        self.assertIs(f, self.worker.wsgi.make_handler.return_value)

    @unittest.mock.patch('aiohttp.worker.asyncio')
    def test__run(self, m_asyncio):
        self.worker.ppid = 1
        self.worker.alive = True
        self.worker.servers = {}
        sock = unittest.mock.Mock()
        sock.cfg_addr = ('localhost', 8080)
        self.worker.sockets = [sock]
        self.worker.wsgi = unittest.mock.Mock()
        self.worker.close = unittest.mock.Mock()
        self.worker.close.return_value = asyncio.Future(loop=self.loop)
        self.worker.close.return_value.set_result(())
        self.worker.log = unittest.mock.Mock()
        self.worker.notify = unittest.mock.Mock()
        loop = self.worker.loop = unittest.mock.Mock()
        loop.create_server.return_value = asyncio.Future(loop=self.loop)
        loop.create_server.return_value.set_result(sock)

        self.loop.run_until_complete(self.worker._run())

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

        self.worker.close = unittest.mock.Mock()
        self.worker.close.return_value = asyncio.Future(loop=self.loop)
        self.worker.close.return_value.set_result(1)

        self.loop.run_until_complete(self.worker._run())
        self.assertTrue(m_sleep.called)
        self.assertTrue(self.worker.close.called)

    def test_close(self):
        srv = unittest.mock.Mock()
        handler = unittest.mock.Mock()
        self.worker.servers = {srv: handler}
        self.worker.log = unittest.mock.Mock()
        self.worker.loop = self.loop
        app = self.worker.wsgi = unittest.mock.Mock()
        app.finish.return_value = asyncio.Future(loop=self.loop)
        app.finish.return_value.set_result(1)
        handler.connections = [object()]
        handler.finish_connections.return_value = asyncio.Future(
            loop=self.loop)
        handler.finish_connections.return_value.set_result(1)

        self.loop.run_until_complete(self.worker.close())
        app.finish.assert_called_with()
        handler.finish_connections.assert_called_with(timeout=95.0)
        srv.close.assert_called_with()
        self.assertIsNone(self.worker.servers)

        self.loop.run_until_complete(self.worker.close())
