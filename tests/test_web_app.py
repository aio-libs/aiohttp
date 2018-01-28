import asyncio
from unittest import mock

import pytest

from aiohttp import log, web
from aiohttp.abc import AbstractAccessLogger, AbstractRouter
from aiohttp.helpers import PY_36
from aiohttp.test_utils import make_mocked_coro


def test_app_ctor(loop):
    with pytest.warns(DeprecationWarning):
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


@pytest.mark.parametrize('debug', [True, False])
def test_app_make_handler_debug_exc(loop, mocker, debug):
    app = web.Application(debug=debug)
    srv = mocker.patch('aiohttp.web_app.Server')

    app.make_handler(loop=loop)
    srv.assert_called_with(app._handle,
                           request_factory=app._make_request,
                           access_log_class=mock.ANY,
                           loop=loop,
                           debug=debug)


def test_app_make_handler_args(loop, mocker):
    app = web.Application(handler_args={'test': True})
    srv = mocker.patch('aiohttp.web_app.Server')

    app.make_handler(loop=loop)
    srv.assert_called_with(app._handle,
                           request_factory=app._make_request,
                           access_log_class=mock.ANY,
                           loop=loop, debug=mock.ANY, test=True)


def test_app_make_handler_access_log_class(loop, mocker):
    class Logger:
        pass

    app = web.Application()

    with pytest.raises(TypeError):
        app.make_handler(access_log_class=Logger, loop=loop)

    class Logger(AbstractAccessLogger):

        def log(self, request, response, time):
            self.logger.info('msg')

    srv = mocker.patch('aiohttp.web_app.Server')

    app.make_handler(access_log_class=Logger, loop=loop)
    srv.assert_called_with(app._handle,
                           access_log_class=Logger,
                           request_factory=app._make_request,
                           loop=loop, debug=mock.ANY)


async def test_app_register_on_finish():
    app = web.Application()
    cb1 = make_mocked_coro(None)
    cb2 = make_mocked_coro(None)
    app.on_cleanup.append(cb1)
    app.on_cleanup.append(cb2)
    app.freeze()
    await app.cleanup()
    cb1.assert_called_once_with(app)
    cb2.assert_called_once_with(app)


async def test_app_register_coro(loop):
    app = web.Application()
    fut = loop.create_future()

    async def cb(app):
        await asyncio.sleep(0.001, loop=loop)
        fut.set_result(123)

    app.on_cleanup.append(cb)
    app.freeze()
    await app.cleanup()
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


async def test_on_shutdown():
    app = web.Application()
    called = False

    async def on_shutdown(app_param):
        nonlocal called
        assert app is app_param
        called = True

    app.on_shutdown.append(on_shutdown)
    app.freeze()
    await app.shutdown()
    assert called


async def test_on_startup(loop):
    app = web.Application()
    app._set_loop(loop)

    long_running1_called = False
    long_running2_called = False
    all_long_running_called = False

    async def long_running1(app_param):
        nonlocal long_running1_called
        assert app is app_param
        long_running1_called = True

    async def long_running2(app_param):
        nonlocal long_running2_called
        assert app is app_param
        long_running2_called = True

    async def on_startup_all_long_running(app_param):
        nonlocal all_long_running_called
        assert app is app_param
        all_long_running_called = True
        return await asyncio.gather(long_running1(app_param),
                                    long_running2(app_param),
                                    loop=app_param.loop)

    app.on_startup.append(on_startup_all_long_running)
    app.freeze()

    await app.startup()
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
    subapp._middlewares = ()
    app._subapps.append(subapp)

    app.freeze()
    assert subapp.freeze.called

    app.freeze()
    assert len(subapp.freeze.call_args_list) == 1


def test_equality():
    app1 = web.Application()
    app2 = web.Application()

    assert app1 == app1
    assert app1 != app2


def test_app_run_middlewares():

    root = web.Application()
    sub = web.Application()
    root.add_subapp('/sub', sub)
    root.freeze()
    assert root._run_middlewares is False

    @web.middleware
    async def middleware(request, handler):
        return await handler(request)

    root = web.Application(middlewares=[middleware])
    sub = web.Application()
    root.add_subapp('/sub', sub)
    root.freeze()
    assert root._run_middlewares is True

    root = web.Application()
    sub = web.Application(middlewares=[middleware])
    root.add_subapp('/sub', sub)
    root.freeze()
    assert root._run_middlewares is True


def test_subapp_frozen_after_adding():
    app = web.Application()
    subapp = web.Application()

    app.add_subapp('/prefix', subapp)
    assert subapp.frozen


@pytest.mark.skipif(not PY_36,
                    reason="Python 3.6+ required")
def test_app_inheritance():
    with pytest.warns(DeprecationWarning):
        class A(web.Application):
            pass


def test_app_custom_attr():
    app = web.Application()
    with pytest.warns(DeprecationWarning):
        app.custom = None
