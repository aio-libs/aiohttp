import asyncio

import pytest

from aiohttp import web


@asyncio.coroutine
def test_middleware_modifies_response(create_app_and_client):

    @asyncio.coroutine
    def handler(request):
        return web.Response(body=b'OK')

    @asyncio.coroutine
    def middleware_factory(app, handler):

        @asyncio.coroutine
        def middleware(request):
            resp = yield from handler(request)
            assert 200 == resp.status
            resp.set_status(201)
            resp.text = resp.text + '[MIDDLEWARE]'
            return resp
        return middleware

    app, client = yield from create_app_and_client()
    app.middlewares.append(middleware_factory)
    app.router.add_route('GET', '/', handler)
    resp = yield from client.get('/')
    assert 201 == resp.status
    txt = yield from resp.text()
    assert 'OK[MIDDLEWARE]' == txt


@asyncio.coroutine
def test_middleware_handles_exception(create_app_and_client):

    @asyncio.coroutine
    def handler(request):
        raise RuntimeError('Error text')

    @asyncio.coroutine
    def middleware_factory(app, handler):

        @asyncio.coroutine
        def middleware(request):
            with pytest.raises(RuntimeError) as ctx:
                yield from handler(request)
            return web.Response(status=501,
                                text=str(ctx.value) + '[MIDDLEWARE]')

        return middleware

    app, client = yield from create_app_and_client()
    app.middlewares.append(middleware_factory)
    app.router.add_route('GET', '/', handler)
    resp = yield from client.get('/')
    assert 501 == resp.status
    txt = yield from resp.text()
    assert 'Error text[MIDDLEWARE]' == txt


@asyncio.coroutine
def test_middleware_chain(create_app_and_client):

    @asyncio.coroutine
    def handler(request):
        return web.Response(text='OK')

    def make_factory(num):

        @asyncio.coroutine
        def factory(app, handler):

            def middleware(request):
                resp = yield from handler(request)
                resp.text = resp.text + '[{}]'.format(num)
                return resp

            return middleware
        return factory

    app, client = yield from create_app_and_client()
    app.middlewares.append(make_factory(1))
    app.middlewares.append(make_factory(2))
    app.router.add_route('GET', '/', handler)
    resp = yield from client.get('/')
    assert 200 == resp.status
    txt = yield from resp.text()
    assert 'OK[2][1]' == txt
