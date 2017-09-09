import asyncio

import pytest

from aiohttp import web


@asyncio.coroutine
def test_middleware_modifies_response(loop, test_client):
    @asyncio.coroutine
    def handler(request):
        return web.Response(body=b'OK')

    @asyncio.coroutine
    def middleware(request, handler):
        resp = yield from handler(request)
        assert 200 == resp.status
        resp.set_status(201)
        resp.text = resp.text + '[MIDDLEWARE]'
        return resp

    app = web.Application()
    app.middlewares.append(middleware)
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
    def middleware(request, handler):
        with pytest.raises(RuntimeError) as ctx:
            yield from handler(request)
        return web.Response(status=501,
                            text=str(ctx.value) + '[MIDDLEWARE]')

    app = web.Application()
    app.middlewares.append(middleware)
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

    def make_middleware(num):
        @asyncio.coroutine
        def middleware(request, handler):
            resp = yield from handler(request)
            resp.text = resp.text + '[{}]'.format(num)
            return resp
        return middleware

    app = web.Application()
    app.middlewares.append(make_middleware(1))
    app.middlewares.append(make_middleware(2))
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)
    resp = yield from client.get('/')
    assert 200 == resp.status
    txt = yield from resp.text()
    assert 'OK[2][1]' == txt


@pytest.fixture
def cli(loop, test_client):
    def wrapper(extra_middlewares):
        app = web.Application()
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
        ('/resource2/', 200),
        ('/resource1?p1=1&p2=2', 200),
        ('/resource1/?p1=1&p2=2', 404),
        ('/resource2?p1=1&p2=2', 200),
        ('/resource2/?p1=1&p2=2', 200)
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
        ('/resource2/', 200),
        ('/resource1?p1=1&p2=2', 200),
        ('/resource1/?p1=1&p2=2', 404),
        ('/resource2?p1=1&p2=2', 404),
        ('/resource2/?p1=1&p2=2', 200)
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
        ('/////resource1/a//b/', 404),
        ('/resource1/a/b?p=1', 200),
        ('//resource1//a//b?p=1', 200),
        ('//resource1//a//b/?p=1', 404),
        ('///resource1//a//b?p=1', 200),
        ('/////resource1/a///b?p=1', 200),
        ('/////resource1/a//b/?p=1', 404),
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
        ('/////resource2/a///b/', 200),
        ('/resource1/a/b?p=1', 200),
        ('/resource1/a/b/?p=1', 404),
        ('//resource2//a//b?p=1', 200),
        ('//resource2//a//b/?p=1', 200),
        ('///resource1//a//b?p=1', 200),
        ('///resource1//a//b/?p=1', 404),
        ('/////resource1/a///b?p=1', 200),
        ('/////resource1/a///b/?p=1', 404),
        ('/resource2/a/b?p=1', 200),
        ('//resource2//a//b?p=1', 200),
        ('//resource2//a//b/?p=1', 200),
        ('///resource2//a//b?p=1', 200),
        ('///resource2//a//b/?p=1', 200),
        ('/////resource2/a///b?p=1', 200),
        ('/////resource2/a///b/?p=1', 200)
    ])
    def test_append_and_merge_slash(self, path, status, cli):
        extra_middlewares = [
            web.normalize_path_middleware()]

        client = yield from cli(extra_middlewares)
        resp = yield from client.get(path)
        assert resp.status == status


@asyncio.coroutine
def test_old_style_middleware(loop, test_client):
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
            resp.text = resp.text + '[old style middleware]'
            return resp
        return middleware

    with pytest.warns(DeprecationWarning) as warning_checker:
        app = web.Application()
        app.middlewares.append(middleware_factory)
        app.router.add_route('GET', '/', handler)
        client = yield from test_client(app)
        resp = yield from client.get('/')
        assert 201 == resp.status
        txt = yield from resp.text()
        assert 'OK[old style middleware]' == txt

    assert len(warning_checker) == 1
    msg = str(warning_checker.list[0].message)
    assert 'old-style middleware "middleware_factory" deprecated' in msg


@asyncio.coroutine
def test_mixed_middleware(loop, test_client):
    @asyncio.coroutine
    def handler(request):
        return web.Response(body=b'OK')

    @asyncio.coroutine
    def m_old1(app, handler):
        @asyncio.coroutine
        def middleware(request):
            resp = yield from handler(request)
            resp.text += '[old style 1]'
            return resp
        return middleware

    @asyncio.coroutine
    def m_new1(request, handler):
        resp = yield from handler(request)
        resp.text += '[new style 1]'
        return resp

    @asyncio.coroutine
    def m_old2(app, handler):
        @asyncio.coroutine
        def middleware(request):
            resp = yield from handler(request)
            resp.text += '[old style 2]'
            return resp
        return middleware

    @asyncio.coroutine
    def m_new2(request, handler):
        resp = yield from handler(request)
        resp.text += '[new style 2]'
        return resp

    middlewares = m_old1, m_new1, m_old2, m_new2

    with pytest.warns(DeprecationWarning) as w:
        app = web.Application(middlewares=middlewares)
        app.router.add_route('GET', '/', handler)
        client = yield from test_client(app)
        resp = yield from client.get('/')
        assert 200 == resp.status
        txt = yield from resp.text()
        assert 'OK[new style 2][old style 2][new style 1][old style 1]' == txt

    assert len(w) == 2
    assert 'old-style middleware "m_old2" deprecated' in str(w.list[0].message)
    assert 'old-style middleware "m_old1" deprecated' in str(w.list[1].message)
