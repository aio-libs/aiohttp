import asyncio

import pytest

from aiohttp import web


@asyncio.coroutine
def test_middleware_modifies_response(loop, test_client):

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

    app = web.Application(loop=loop)
    app.middlewares.append(middleware_factory)
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)
    resp = yield from client.get('/')
    assert 201 == resp.status
    txt = yield from resp.text()
    assert 'OK[MIDDLEWARE]' == txt


@asyncio.coroutine
def test_middleware_handles_exception(loop, test_client):

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

    app = web.Application(loop=loop)
    app.middlewares.append(middleware_factory)
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)
    resp = yield from client.get('/')
    assert 501 == resp.status
    txt = yield from resp.text()
    assert 'Error text[MIDDLEWARE]' == txt


@asyncio.coroutine
def test_middleware_chain(loop, test_client):

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

    app = web.Application(loop=loop)
    app.middlewares.append(make_factory(1))
    app.middlewares.append(make_factory(2))
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)
    resp = yield from client.get('/')
    assert 200 == resp.status
    txt = yield from resp.text()
    assert 'OK[2][1]' == txt


@pytest.fixture
def cli(loop, test_client):
    def wrapper(extra_middlewares):
        app = web.Application(loop=loop)
        app.router.add_route(
            'GET', '/resource1', lambda x: web.Response(text="OK"))
        app.router.add_route(
            'GET', '/resource2/', lambda x: web.Response(text="OK"))
        app.router.add_route(
            'GET', '/resource1/a/b', lambda x: web.Response(text="OK"))
        app.router.add_route(
            'GET', '/resource2/a/b/', lambda x: web.Response(text="OK"))
        app.middlewares.extend(extra_middlewares)
        return test_client(app, server_kwargs={'skip_url_asserts': True})
    return wrapper


class TestNormalizePathMiddleware:

    @asyncio.coroutine
    @pytest.mark.parametrize("path, status", [
        ('/resource1', 200),
        ('/resource1/', 404),
        ('/resource2', 200),
        ('/resource2/', 200)
    ])
    def test_add_trailing_when_necessary(
            self, path, status, cli):
        extra_middlewares = [
            web.normalize_path_middleware(merge_slashes=False)]
        client = yield from cli(extra_middlewares)

        resp = yield from client.get(path)
        assert resp.status == status

    @asyncio.coroutine
    @pytest.mark.parametrize("path, status", [
        ('/resource1', 200),
        ('/resource1/', 404),
        ('/resource2', 404),
        ('/resource2/', 200)
    ])
    def test_no_trailing_slash_when_disabled(
            self, path, status, cli):
        extra_middlewares = [
            web.normalize_path_middleware(
                append_slash=False, merge_slashes=False)]
        client = yield from cli(extra_middlewares)

        resp = yield from client.get(path)
        assert resp.status == status

    @asyncio.coroutine
    @pytest.mark.parametrize("path, status", [
        ('/resource1/a/b', 200),
        ('//resource1//a//b', 200),
        ('//resource1//a//b/', 404),
        ('///resource1//a//b', 200),
        ('/////resource1/a///b', 200),
        ('/////resource1/a//b/', 404)
    ])
    def test_merge_slash(self, path, status, cli):
        extra_middlewares = [
            web.normalize_path_middleware(append_slash=False)]
        client = yield from cli(extra_middlewares)

        resp = yield from client.get(path)
        assert resp.status == status

    @asyncio.coroutine
    @pytest.mark.parametrize("path, status", [
        ('/resource1/a/b', 200),
        ('/resource1/a/b/', 404),
        ('//resource2//a//b', 200),
        ('//resource2//a//b/', 200),
        ('///resource1//a//b', 200),
        ('///resource1//a//b/', 404),
        ('/////resource1/a///b', 200),
        ('/////resource1/a///b/', 404),
        ('/resource2/a/b', 200),
        ('//resource2//a//b', 200),
        ('//resource2//a//b/', 200),
        ('///resource2//a//b', 200),
        ('///resource2//a//b/', 200),
        ('/////resource2/a///b', 200),
        ('/////resource2/a///b/', 200)
    ])
    def test_append_and_merge_slash(self, path, status, cli):
        extra_middlewares = [
            web.normalize_path_middleware()]

        client = yield from cli(extra_middlewares)
        resp = yield from client.get(path)
        assert resp.status == status
