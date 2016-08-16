import asyncio
import contextlib

import pytest
from aiohttp.web import Application

from .test_utils import (TestClient, loop_context, setup_test_loop,
                         teardown_test_loop)


@contextlib.contextmanager
def _passthrough_loop_context(loop):
    if loop:
        # loop already exists, pass it straight through
        yield loop
    else:
        # this shadows loop_context's standard behavior
        loop = setup_test_loop()
        yield loop
        teardown_test_loop(loop)


def pytest_pycollect_makeitem(collector, name, obj):
    """
    Fix pytest collecting for coroutines.
    """
    if collector.funcnamefilter(name) and asyncio.iscoroutinefunction(obj):
        return list(collector._genfunctions(name, obj))


def pytest_pyfunc_call(pyfuncitem):
    """
    Run coroutines in an event loop instead of a normal function call.
    """
    if asyncio.iscoroutinefunction(pyfuncitem.function):
        existing_loop = pyfuncitem.funcargs.get('loop', None)
        with _passthrough_loop_context(existing_loop) as _loop:
            testargs = {arg: pyfuncitem.funcargs[arg]
                        for arg in pyfuncitem._fixtureinfo.argnames}

            task = _loop.create_task(pyfuncitem.obj(**testargs))
            _loop.run_until_complete(task)

        return True


@pytest.yield_fixture
def loop():
    with loop_context() as _loop:
        yield _loop


@pytest.yield_fixture
def test_client(loop):
    clients = []

    @asyncio.coroutine
    def _create_from_app_factory(app_factory, *args, **kwargs):
        if not isinstance(app_factory, Application):
            app = app_factory(loop, *args, **kwargs)
        else:
            assert not args, "args should be empty"
            assert not kwargs, "kwargs should be empty"
            app = app_factory

        assert app.loop is loop, \
            "Application is attached to other event loop"

        client = TestClient(app)
        yield from client.start_server()
        clients.append(client)
        return client

    yield _create_from_app_factory

    while clients:
        clients.pop().close()
