import asyncio
from unittest import mock

import pytest

from aiohttp import helpers, log, web
from aiohttp.abc import AbstractRouter


def test_app_ctor(loop):
    app = web.Application(loop=loop)
    assert loop is app.loop
    assert app.logger is log.web_logger


def test_app_call(loop):
    app = web.Application(loop=loop)
    assert app is app()


def test_app_default_loop(loop):
    asyncio.set_event_loop(loop)
    app = web.Application()
    assert loop is app.loop


@pytest.mark.parametrize('debug', [True, False])
def test_app_make_handler_debug_exc(loop, mocker, debug):
    app = web.Application(loop=loop, debug=debug)

    srv = mocker.patch('aiohttp.web.Server')

    app.make_handler()
    with pytest.warns(DeprecationWarning) as exc:
        app.make_handler(debug=debug)

    assert 'parameter is deprecated' in exc[0].message.args[0]
    assert srv.call_count == 2
    srv.assert_called_with(app._handle,
                           request_factory=app._make_request,
                           loop=loop,
                           debug=debug)

    with pytest.raises(ValueError) as exc:
        app.make_handler(debug=not debug)
    assert 'The value of `debug` parameter conflicts with the' in str(exc)


@asyncio.coroutine
def test_app_register_on_finish(loop):
    app = web.Application(loop=loop)
    cb1 = mock.Mock()
    cb2 = mock.Mock()
    app.on_cleanup.append(cb1)
    app.on_cleanup.append(cb2)
    yield from app.cleanup()
    cb1.assert_called_once_with(app)
    cb2.assert_called_once_with(app)


@asyncio.coroutine
def test_app_register_coro(loop):
    app = web.Application(loop=loop)

    fut = helpers.create_future(loop)

    @asyncio.coroutine
    def cb(app):
        yield from asyncio.sleep(0.001, loop=loop)
        fut.set_result(123)

    app.on_cleanup.append(cb)
    yield from app.cleanup()
    assert fut.done()
    assert 123 == fut.result()


@asyncio.coroutine
def test_app_register_and_finish_are_deprecated(loop):
    app = web.Application(loop=loop)
    cb1 = mock.Mock()
    cb2 = mock.Mock()
    with pytest.warns(DeprecationWarning):
        app.register_on_finish(cb1, 1, b=2)
    with pytest.warns(DeprecationWarning):
        app.register_on_finish(cb2, 2, c=3)
    with pytest.warns(DeprecationWarning):
        yield from app.finish()
    cb1.assert_called_once_with(app, 1, b=2)
    cb2.assert_called_once_with(app, 2, c=3)


def test_non_default_router(loop):
    router = mock.Mock(spec=AbstractRouter)
    app = web.Application(loop=loop, router=router)
    assert router is app.router


def test_logging(loop):
    logger = mock.Mock()
    app = web.Application(loop=loop)
    app.logger = logger
    assert app.logger is logger


@asyncio.coroutine
def test_on_shutdown(loop):
    app = web.Application(loop=loop)
    called = False

    @asyncio.coroutine
    def on_shutdown(app_param):
        nonlocal called
        assert app is app_param
        called = True

    app.on_shutdown.append(on_shutdown)

    yield from app.shutdown()
    assert called


@asyncio.coroutine
def test_on_startup(loop):
    app = web.Application(loop=loop)

    blocking_called = False
    long_running1_called = False
    long_running2_called = False
    all_long_running_called = False

    def on_startup_blocking(app_param):
        nonlocal blocking_called
        assert app is app_param
        blocking_called = True

    @asyncio.coroutine
    def long_running1(app_param):
        nonlocal long_running1_called
        assert app is app_param
        long_running1_called = True

    @asyncio.coroutine
    def long_running2(app_param):
        nonlocal long_running2_called
        assert app is app_param
        long_running2_called = True

    @asyncio.coroutine
    def on_startup_all_long_running(app_param):
        nonlocal all_long_running_called
        assert app is app_param
        all_long_running_called = True
        return (yield from asyncio.gather(long_running1(app_param),
                                          long_running2(app_param),
                                          loop=app_param.loop))

    app.on_startup.append(on_startup_blocking)
    app.on_startup.append(on_startup_all_long_running)

    yield from app.startup()
    assert blocking_called
    assert long_running1_called
    assert long_running2_called
    assert all_long_running_called


def test_app_delitem(loop):
    app = web.Application(loop=loop)
    app['key'] = 'value'
    assert len(app) == 1
    del app['key']
    assert len(app) == 0


def test_secure_proxy_ssl_header_default(loop):
    app = web.Application(loop=loop)
    assert app._secure_proxy_ssl_header is None


@asyncio.coroutine
def test_secure_proxy_ssl_header_non_default(loop):
    app = web.Application(loop=loop)
    hdr = ('X-Forwarded-Proto', 'https')
    app.make_handler(secure_proxy_ssl_header=hdr)
    assert app._secure_proxy_ssl_header is hdr
