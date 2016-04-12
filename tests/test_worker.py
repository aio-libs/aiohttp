"""Tests for aiohttp/worker.py"""
import asyncio
import pytest
from unittest import mock


base_worker = pytest.importorskip('aiohttp.worker')


class MyWorker(base_worker.GunicornWebWorker):

    def __init__(self):
        self.servers = []
        self.exit_code = 0
        self.cfg = mock.Mock()
        self.cfg.graceful_timeout = 100


@pytest.fixture
def worker():
    return MyWorker()


def test_init_process(worker):
    with mock.patch('aiohttp.worker.asyncio') as m_asyncio:
        try:
            worker.init_process()
        except TypeError:
            pass

        assert m_asyncio.get_event_loop.return_value.close.called
        assert m_asyncio.new_event_loop.called
        assert m_asyncio.set_event_loop.called


def test_run(worker, loop):
    worker.loop = loop
    worker._run = mock.Mock(
        wraps=asyncio.coroutine(lambda: None))
    with pytest.raises(SystemExit):
        worker.run()

    assert worker._run.called
    is_closed = getattr(loop, 'is_closed')
    if is_closed is not None:
        closed = is_closed()
    else:
        closed = loop._closed
    assert closed


def test_handle_quit(worker):
    worker.handle_quit(object(), object())
    assert not worker.alive
    assert worker.exit_code == 0


def test_handle_abort(worker):
    worker.handle_abort(object(), object())
    assert not worker.alive
    assert worker.exit_code == 1


def test_init_signal(worker):
    worker.loop = mock.Mock()
    worker.init_signal()
    assert worker.loop.add_signal_handler.called


def test_make_handler(worker):
    worker.wsgi = mock.Mock()
    worker.loop = mock.Mock()
    worker.log = mock.Mock()
    worker.cfg = mock.Mock()

    f = worker.make_handler(worker.wsgi)
    assert f is worker.wsgi.make_handler.return_value


def test__run_ok(worker, loop):
    worker.ppid = 1
    worker.alive = True
    worker.servers = {}
    sock = mock.Mock()
    sock.cfg_addr = ('localhost', 8080)
    worker.sockets = [sock]
    worker.wsgi = mock.Mock()
    worker.close = mock.Mock()
    worker.close.return_value = asyncio.Future(loop=loop)
    worker.close.return_value.set_result(())
    worker.log = mock.Mock()
    worker.notify = mock.Mock()
    worker.loop = loop
    ret = asyncio.Future(loop=loop)
    loop.create_server = mock.Mock(
        wraps=asyncio.coroutine(lambda *a, **kw: ret))
    ret.set_result(sock)
    worker.wsgi.make_handler.return_value.num_connections = 1
    worker.cfg.max_requests = 100

    with mock.patch('aiohttp.worker.asyncio') as m_asyncio:
        m_asyncio.sleep = mock.Mock(
            wraps=asyncio.coroutine(lambda *a, **kw: None))
        loop.run_until_complete(worker._run())

    assert worker.notify.called
    assert worker.log.info.called


def test__run_exc(worker, loop):
    with mock.patch('aiohttp.worker.os') as m_os:
        m_os.getpid.return_value = 1
        m_os.getppid.return_value = 1

        worker.servers = [mock.Mock()]
        worker.ppid = 1
        worker.alive = True
        worker.sockets = []
        worker.log = mock.Mock()
        worker.loop = mock.Mock()
        worker.notify = mock.Mock()

        with mock.patch('aiohttp.worker.asyncio.sleep') as m_sleep:
            slp = asyncio.Future(loop=loop)
            slp.set_exception(KeyboardInterrupt)
            m_sleep.return_value = slp

            worker.close = mock.Mock()
            worker.close.return_value = asyncio.Future(loop=loop)
            worker.close.return_value.set_result(1)

            loop.run_until_complete(worker._run())

        assert m_sleep.called
        assert worker.close.called


def test_close(worker, loop):
    srv = mock.Mock()
    handler = mock.Mock()
    worker.servers = {srv: handler}
    worker.log = mock.Mock()
    worker.loop = loop
    app = worker.wsgi = mock.Mock()
    app.finish.return_value = asyncio.Future(loop=loop)
    app.finish.return_value.set_result(1)
    handler.connections = [object()]
    handler.finish_connections.return_value = asyncio.Future(
        loop=loop)
    handler.finish_connections.return_value.set_result(1)

    app.shutdown.return_value = asyncio.Future(loop=loop)
    app.shutdown.return_value.set_result(None)

    loop.run_until_complete(worker.close())
    app.shutdown.assert_called_with()
    app.finish.assert_called_with()
    handler.finish_connections.assert_called_with(timeout=95.0)
    srv.close.assert_called_with()
    assert worker.servers is None

    loop.run_until_complete(worker.close())
