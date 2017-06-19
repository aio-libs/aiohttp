import asyncio
from unittest import mock

import pytest

from aiohttp import helpers, log, web
from aiohttp.abc import AbstractRouter


def test_app_ctor(loop):
    with pytest.warns(ResourceWarning):
        app = web.Application(loop=loop)
    assert loop is app.loop
    assert app.logger is log.web_logger


def test_app_call():
    app = web.Application()
    assert app is app()


def test_app_default_loop():
    app = web.Application()
    assert app.loop is None


def test_set_loop(loop):
    app = web.Application()
    app._set_loop(loop)
    assert app.loop is loop


def test_set_loop_default_loop(loop):
    asyncio.set_event_loop(loop)
    app = web.Application()
    app._set_loop(None)
    assert app.loop is loop


def test_set_loop_with_different_loops(loop):
    app = web.Application()
    app._set_loop(loop)
    assert app.loop is loop

    with pytest.raises(RuntimeError):
        app._set_loop(loop=object())


def test_on_loop_available(loop):
    app = web.Application()

    cb = mock.Mock()
    with pytest.warns(DeprecationWarning):
        app.on_loop_available.append(cb)

    app._set_loop(loop)
    cb.assert_called_with(app)


@pytest.mark.parametrize('debug', [True, False])
def test_app_make_handler_debug_exc(loop, mocker, debug):
    app = web.Application(debug=debug)
    srv = mocker.patch('aiohttp.web.Server')

    app.make_handler(loop=loop)
    srv.assert_called_with(app._handle,
                           request_factory=app._make_request,
                           loop=loop,
                           debug=debug)


def test_app_make_handler_args(loop, mocker):
    app = web.Application(handler_args={'test': True})
    srv = mocker.patch('aiohttp.web.Server')

    app.make_handler(loop=loop)
    srv.assert_called_with(app._handle,
                           request_factory=app._make_request,
                           loop=loop, debug=mock.ANY, test=True)


@asyncio.coroutine
def test_app_register_on_finish():
    app = web.Application()
    cb1 = mock.Mock()
    cb2 = mock.Mock()
    app.on_cleanup.append(cb1)
    app.on_cleanup.append(cb2)
    yield from app.cleanup()
    cb1.assert_called_once_with(app)
    cb2.assert_called_once_with(app)


@asyncio.coroutine
def test_app_register_coro(loop):
    app = web.Application()
    fut = helpers.create_future(loop)

    @asyncio.coroutine
    def cb(app):
        yield from asyncio.sleep(0.001, loop=loop)
        fut.set_result(123)

    app.on_cleanup.append(cb)
    yield from app.cleanup()
    assert fut.done()
    assert 123 == fut.result()


def test_non_default_router():
    router = mock.Mock(spec=AbstractRouter)
    app = web.Application(router=router)
    assert router is app.router


def test_logging():
    logger = mock.Mock()
    app = web.Application()
    app.logger = logger
    assert app.logger is logger


@asyncio.coroutine
def test_on_shutdown():
    app = web.Application()
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
    app = web.Application()
    app._set_loop(loop)

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


def test_app_delitem():
    app = web.Application()
    app['key'] = 'value'
    assert len(app) == 1
    del app['key']
    assert len(app) == 0


def test_app_freeze():
    app = web.Application()
    subapp = mock.Mock()
    app._subapps.append(subapp)

    app.freeze()
    assert subapp.freeze.called

    app.freeze()
    assert len(subapp.freeze.call_args_list) == 1


def test_secure_proxy_ssl_header_default():
    app = web.Application()
    assert app._secure_proxy_ssl_header is None


def test_secure_proxy_ssl_header_non_default(loop):
    app = web.Application()
    hdr = ('X-Forwarded-Proto', 'https')
    app.make_handler(secure_proxy_ssl_header=hdr, loop=loop)
    assert app._secure_proxy_ssl_header is hdr


def test_secure_proxy_ssl_header_init(loop):
    hdr = ('X-Forwarded-Proto', 'https')
    with pytest.warns(DeprecationWarning):
        app = web.Application(secure_proxy_ssl_header=hdr)
    assert app._secure_proxy_ssl_header is hdr
    app.make_handler(loop=loop)
    assert app._secure_proxy_ssl_header is hdr


def test_equality():
    app1 = web.Application()
    app2 = web.Application()

    assert app1 == app1
    assert app1 != app2
