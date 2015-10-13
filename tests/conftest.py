import asyncio
import pytest
import socket
import sys

from aiohttp import web


@pytest.fixture
def unused_port():
    def f():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]
    return f


@pytest.yield_fixture
def loop(request):
    try:
        old_loop = asyncio.get_event_loop()
    except (RuntimeError, AssertionError):
        old_loop = None
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(None)

    yield loop

    loop.close()
    if old_loop:
        asyncio.set_event_loop(old_loop)


@pytest.yield_fixture
def create_server(loop, unused_port):
    app = handler = srv = None

    @asyncio.coroutine
    def create(*, debug=False, ssl_ctx=None):
        nonlocal app, handler, srv
        app = web.Application(loop=loop)
        port = unused_port()
        handler = app.make_handler(debug=debug, keep_alive_on=False)
        srv = yield from loop.create_server(handler, '127.0.0.1', port,
                                            ssl=ssl_ctx)
        proto = "https" if ssl_ctx else "http"
        url = "{}://127.0.0.1:{}".format(proto, port)
        return app, url

    yield create

    @asyncio.coroutine
    def finish():
        yield from handler.finish_connections()
        yield from app.finish()
        srv.close()
        yield from srv.wait_closed()

    loop.run_until_complete(finish())


@pytest.mark.tryfirst
def pytest_pycollect_makeitem(collector, name, obj):
    if collector.funcnamefilter(name):
        if not callable(obj):
            return
        item = pytest.Function(name, parent=collector)
        if 'run_loop' in item.keywords:
            return list(collector._genfunctions(name, obj))


@pytest.mark.tryfirst
def pytest_pyfunc_call(pyfuncitem):
    """
    Run asyncio marked test functions in an event loop instead of a normal
    function call.
    """
    if 'run_loop' in pyfuncitem.keywords:
        funcargs = pyfuncitem.funcargs
        loop = funcargs['loop']
        testargs = {arg: funcargs[arg]
                    for arg in pyfuncitem._fixtureinfo.argnames}
        loop.run_until_complete(pyfuncitem.obj(**testargs))
        return True


def pytest_runtest_setup(item):
    if 'run_loop' in item.keywords and 'loop' not in item.fixturenames:
        # inject an event loop fixture for all async tests
        item.fixturenames.append('loop')


def pytest_ignore_collect(path, config):
    if 'test_py35' in str(path):
        if sys.version_info < (3, 5, 0):
            return True
