import asyncio
import contextlib

import pytest

from .test_utils import TestClient, loop_context, setup_test_loop, teardown_test_loop


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
        with _passthrough_loop_context(pyfuncitem.funcargs.get('loop')) as _loop:
            testargs = {arg: pyfuncitem.funcargs[arg] for arg in pyfuncitem._fixtureinfo.argnames}
            _loop.run_until_complete(_loop.create_task(pyfuncitem.obj(**testargs)))

        return True


@pytest.yield_fixture
def loop():
    with loop_context() as _loop:
        yield _loop


@pytest.yield_fixture
def test_client(loop):
    client = None

    async def _create_from_app_factory(app_factory):
        nonlocal client
        app = app_factory(loop)
        client = TestClient(app)
        await client.start_server()
        return client

    yield _create_from_app_factory

    if client:
        client.close()
