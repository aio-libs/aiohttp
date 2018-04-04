import re

import pytest

from aiohttp import web


async def test_middleware_modifies_response(loop, aiohttp_client):
    async def handler(request):
        return web.Response(body=b'OK')

    @web.middleware
    async def middleware(request, handler):
        resp = await handler(request)
        assert 200 == resp.status
        resp.set_status(201)
        resp.text = resp.text + '[MIDDLEWARE]'
        return resp

    app = web.Application()
    app.middlewares.append(middleware)
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.get('/')
    assert 201 == resp.status
    txt = await resp.text()
    assert 'OK[MIDDLEWARE]' == txt


async def test_middleware_handles_exception(loop, aiohttp_client):
    async def handler(request):
        raise RuntimeError('Error text')

    @web.middleware
    async def middleware(request, handler):
        with pytest.raises(RuntimeError) as ctx:
            await handler(request)
        return web.Response(status=501,
                            text=str(ctx.value) + '[MIDDLEWARE]')

    app = web.Application()
    app.middlewares.append(middleware)
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.get('/')
    assert 501 == resp.status
    txt = await resp.text()
    assert 'Error text[MIDDLEWARE]' == txt


async def test_middleware_chain(loop, aiohttp_client):
    async def handler(request):
        return web.Response(text='OK')

    def make_middleware(num):
        @web.middleware
        async def middleware(request, handler):
            resp = await handler(request)
            resp.text = resp.text + '[{}]'.format(num)
            return resp
        return middleware

    app = web.Application()
    app.middlewares.append(make_middleware(1))
    app.middlewares.append(make_middleware(2))
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.get('/')
    assert 200 == resp.status
    txt = await resp.text()
    assert 'OK[2][1]' == txt


@pytest.fixture
def cli(loop, aiohttp_client):
    async def handler(request):
        return web.Response(text="OK")

    def wrapper(extra_middlewares):
        app = web.Application()
        app.router.add_route(
            'GET', '/resource1', handler)
        app.router.add_route(
            'GET', '/resource2/', handler)
        app.router.add_route(
            'GET', '/resource1/a/b', handler)
        app.router.add_route(
            'GET', '/resource2/a/b/', handler)
        app.middlewares.extend(extra_middlewares)
        return aiohttp_client(app, server_kwargs={'skip_url_asserts': True})
    return wrapper


class TestNormalizePathMiddleware:

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
    async def test_add_trailing_when_necessary(
            self, path, status, cli):
        extra_middlewares = [
            web.normalize_path_middleware(merge_slashes=False)]
        client = await cli(extra_middlewares)

        resp = await client.get(path)
        assert resp.status == status

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
    async def test_no_trailing_slash_when_disabled(
            self, path, status, cli):
        extra_middlewares = [
            web.normalize_path_middleware(
                append_slash=False, merge_slashes=False)]
        client = await cli(extra_middlewares)

        resp = await client.get(path)
        assert resp.status == status

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
    async def test_merge_slash(self, path, status, cli):
        extra_middlewares = [
            web.normalize_path_middleware(append_slash=False)]
        client = await cli(extra_middlewares)

        resp = await client.get(path)
        assert resp.status == status

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
    async def test_append_and_merge_slash(self, path, status, cli):
        extra_middlewares = [
            web.normalize_path_middleware()]

        client = await cli(extra_middlewares)
        resp = await client.get(path)
        assert resp.status == status


async def test_old_style_middleware(loop, aiohttp_client):
    async def handler(request):
        return web.Response(body=b'OK')

    async def middleware_factory(app, handler):

        async def middleware(request):
            resp = await handler(request)
            assert 200 == resp.status
            resp.set_status(201)
            resp.text = resp.text + '[old style middleware]'
            return resp
        return middleware

    with pytest.warns(DeprecationWarning) as warning_checker:
        app = web.Application()
        app.middlewares.append(middleware_factory)
        app.router.add_route('GET', '/', handler)
        client = await aiohttp_client(app)
        resp = await client.get('/')
        assert 201 == resp.status
        txt = await resp.text()
        assert 'OK[old style middleware]' == txt

    assert len(warning_checker) == 1
    msg = str(warning_checker.list[0].message)
    assert re.match('^old-style middleware '
                    '"<function test_old_style_middleware.<locals>.'
                    'middleware_factory at 0x[0-9a-fA-F]+>" '
                    'deprecated, see #2252$',
                    msg)


async def test_mixed_middleware(loop, aiohttp_client):
    async def handler(request):
        return web.Response(body=b'OK')

    async def m_old1(app, handler):
        async def middleware(request):
            resp = await handler(request)
            resp.text += '[old style 1]'
            return resp
        return middleware

    @web.middleware
    async def m_new1(request, handler):
        resp = await handler(request)
        resp.text += '[new style 1]'
        return resp

    async def m_old2(app, handler):
        async def middleware(request):
            resp = await handler(request)
            resp.text += '[old style 2]'
            return resp
        return middleware

    @web.middleware
    async def m_new2(request, handler):
        resp = await handler(request)
        resp.text += '[new style 2]'
        return resp

    middlewares = m_old1, m_new1, m_old2, m_new2

    with pytest.warns(DeprecationWarning) as w:
        app = web.Application(middlewares=middlewares)
        app.router.add_route('GET', '/', handler)
        client = await aiohttp_client(app)
        resp = await client.get('/')
        assert 200 == resp.status
        txt = await resp.text()
        assert 'OK[new style 2][old style 2][new style 1][old style 1]' == txt

    assert len(w) == 2
    tmpl = ('^old-style middleware '
            '"<function test_mixed_middleware.<locals>.'
            '{} at 0x[0-9a-fA-F]+>" '
            'deprecated, see #2252$')
    p1 = tmpl.format('m_old1')
    p2 = tmpl.format('m_old2')

    assert re.match(p2, str(w.list[0].message))
    assert re.match(p1, str(w.list[1].message))


async def test_old_style_middleware_class(loop, aiohttp_client):
    async def handler(request):
        return web.Response(body=b'OK')

    class Middleware:
        async def __call__(self, app, handler):
            async def middleware(request):
                resp = await handler(request)
                assert 200 == resp.status
                resp.set_status(201)
                resp.text = resp.text + '[old style middleware]'
                return resp
            return middleware

    with pytest.warns(DeprecationWarning) as warning_checker:
        app = web.Application()
        app.middlewares.append(Middleware())
        app.router.add_route('GET', '/', handler)
        client = await aiohttp_client(app)
        resp = await client.get('/')
        assert 201 == resp.status
        txt = await resp.text()
        assert 'OK[old style middleware]' == txt

    assert len(warning_checker) == 1
    msg = str(warning_checker.list[0].message)
    assert re.match('^old-style middleware '
                    '"<test_web_middleware.test_old_style_middleware_class.'
                    '<locals>.Middleware object '
                    'at 0x[0-9a-fA-F]+>" deprecated, see #2252$', msg)


async def test_new_style_middleware_class(loop, aiohttp_client):
    async def handler(request):
        return web.Response(body=b'OK')

    @web.middleware
    class Middleware:
        async def __call__(self, request, handler):
            resp = await handler(request)
            assert 200 == resp.status
            resp.set_status(201)
            resp.text = resp.text + '[new style middleware]'
            return resp

    with pytest.warns(None) as warning_checker:
        app = web.Application()
        app.middlewares.append(Middleware())
        app.router.add_route('GET', '/', handler)
        client = await aiohttp_client(app)
        resp = await client.get('/')
        assert 201 == resp.status
        txt = await resp.text()
        assert 'OK[new style middleware]' == txt

    assert len(warning_checker) == 0


async def test_new_style_middleware_method(loop, aiohttp_client):
    async def handler(request):
        return web.Response(body=b'OK')

    class Middleware:
        @web.middleware
        async def call(self, request, handler):
            resp = await handler(request)
            assert 200 == resp.status
            resp.set_status(201)
            resp.text = resp.text + '[new style middleware]'
            return resp

    with pytest.warns(None) as warning_checker:
        app = web.Application()
        app.middlewares.append(Middleware().call)
        app.router.add_route('GET', '/', handler)
        client = await aiohttp_client(app)
        resp = await client.get('/')
        assert 201 == resp.status
        txt = await resp.text()
        assert 'OK[new style middleware]' == txt

    assert len(warning_checker) == 0
