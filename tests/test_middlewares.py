import asyncio
import pytest

from aiohttp import middlewares, web


class TestNormalizePathMiddleware:

    @asyncio.coroutine
    @pytest.mark.parametrize("path, status", [
        ('/resource1', 200),
        ('/resource1/', 404),
        ('/resource2', 200),
        ('/resource2/', 200)
    ])
    def test_add_trailing_when_necessary(
            self, path, status, create_app_and_client):
        app, client = yield from create_app_and_client()
        app.middlewares.append(
            middlewares.normalize_path(merge_slashes=False))
        app.router.add_route(
            'GET', '/resource1', lambda x: web.Response(text="OK"))
        app.router.add_route(
            'GET', '/resource2/', lambda x: web.Response(text="OK"))

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
            self, path, status, create_app_and_client):
        app, client = yield from create_app_and_client()
        app.middlewares.append(
            middlewares.normalize_path(
                append_slash=False, merge_slashes=False))
        app.router.add_route(
            'GET', '/resource1', lambda x: web.Response(text="OK"))
        app.router.add_route(
            'GET', '/resource2/', lambda x: web.Response(text="OK"))

        resp = yield from client.get(path)
        assert resp.status == status

    @asyncio.coroutine
    @pytest.mark.parametrize("path, status", [
        ('/resource1/a/b', 200),
        ('//resource1//a//b', 200),
        ('/////resource1/a///b', 200),
        ('/////resource1/a//b/', 404)
    ])
    def test_merge_slash(self, path, status, create_app_and_client):
        app, client = yield from create_app_and_client()
        app.middlewares.append(
            middlewares.normalize_path(append_slash=False))
        app.router.add_route(
            'GET', '/resource1/a/b', lambda x: web.Response(text="OK"))

        resp = yield from client.get(path)
        assert resp.status == status

    @asyncio.coroutine
    @pytest.mark.parametrize("path, status", [
        ('/resource1/a/b', 200),
        ('/resource1/a/b/', 404),
        ('//resource1//a//b', 200),
        ('//resource1//a//b/', 404),
        ('/////resource1/a///b', 200),
        ('/////resource1/a///b/', 404),
        ('/resource2/a/b', 200),
        ('//resource2//a//b', 200),
        ('//resource2//a//b/', 200),
        ('/////resource2/a///b', 200),
        ('/////resource2/a///b/', 200)
    ])
    def test_append_and_merge_slash(self, path, status, create_app_and_client):
        app, client = yield from create_app_and_client()
        app.middlewares.append(middlewares.normalize_path())
        app.router.add_route(
            'GET', '/resource1/a/b', lambda x: web.Response(text="OK"))
        app.router.add_route(
            'GET', '/resource2/a/b/', lambda x: web.Response(text="OK"))

        resp = yield from client.get(path)
        assert resp.status == status
