import re
from typing import Any

import pytest
from yarl import URL

from aiohttp import web
from aiohttp.typedefs import Handler


async def test_middleware_modifies_response(loop, aiohttp_client) -> None:
    async def handler(request):
        return web.Response(body=b"OK")

    @web.middleware
    async def middleware(request, handler: Handler):
        resp = await handler(request)
        assert 200 == resp.status
        resp.set_status(201)
        resp.text = resp.text + "[MIDDLEWARE]"
        return resp

    app = web.Application()
    app.middlewares.append(middleware)
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    # Call twice to verify cache works
    for _ in range(2):
        resp = await client.get("/")
        assert 201 == resp.status
        txt = await resp.text()
        assert "OK[MIDDLEWARE]" == txt


async def test_middleware_handles_exception(loop, aiohttp_client) -> None:
    async def handler(request):
        raise RuntimeError("Error text")

    @web.middleware
    async def middleware(request, handler: Handler):
        with pytest.raises(RuntimeError) as ctx:
            await handler(request)
        return web.Response(status=501, text=str(ctx.value) + "[MIDDLEWARE]")

    app = web.Application()
    app.middlewares.append(middleware)
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    # Call twice to verify cache works
    for _ in range(2):
        resp = await client.get("/")
        assert 501 == resp.status
        txt = await resp.text()
        assert "Error text[MIDDLEWARE]" == txt


async def test_middleware_chain(loop, aiohttp_client) -> None:
    async def handler(request):
        return web.Response(text="OK")

    handler.annotation = "annotation_value"

    async def handler2(request):
        return web.Response(text="OK")

    middleware_annotation_seen_values = []

    def make_middleware(num):
        @web.middleware
        async def middleware(request, handler: Handler):
            middleware_annotation_seen_values.append(
                getattr(handler, "annotation", None)
            )
            resp = await handler(request)
            resp.text = resp.text + f"[{num}]"
            return resp

        return middleware

    app = web.Application()
    app.middlewares.append(make_middleware(1))
    app.middlewares.append(make_middleware(2))
    app.router.add_route("GET", "/", handler)
    app.router.add_route("GET", "/r2", handler2)
    client = await aiohttp_client(app)
    resp = await client.get("/")
    assert 200 == resp.status
    txt = await resp.text()
    assert "OK[2][1]" == txt
    assert middleware_annotation_seen_values == ["annotation_value", "annotation_value"]

    # check that attributes from handler are not applied to handler2
    resp = await client.get("/r2")
    assert 200 == resp.status
    assert middleware_annotation_seen_values == [
        "annotation_value",
        "annotation_value",
        None,
        None,
    ]


async def test_middleware_subapp(loop, aiohttp_client) -> None:
    async def sub_handler(request):
        return web.Response(text="OK")

    sub_handler.annotation = "annotation_value"

    async def handler(request):
        return web.Response(text="OK")

    middleware_annotation_seen_values = []

    def make_middleware(num):
        @web.middleware
        async def middleware(request, handler: Handler):
            annotation = getattr(handler, "annotation", None)
            if annotation is not None:
                middleware_annotation_seen_values.append(f"{annotation}/{num}")
            return await handler(request)

        return middleware

    app = web.Application()
    app.middlewares.append(make_middleware(1))
    app.router.add_route("GET", "/r2", handler)

    subapp = web.Application()
    subapp.middlewares.append(make_middleware(2))
    subapp.router.add_route("GET", "/", sub_handler)
    app.add_subapp("/sub", subapp)

    client = await aiohttp_client(app)
    resp = await client.get("/sub/")
    assert 200 == resp.status
    await resp.text()
    assert middleware_annotation_seen_values == [
        "annotation_value/1",
        "annotation_value/2",
    ]

    # check that attributes from sub_handler are not applied to handler
    del middleware_annotation_seen_values[:]
    resp = await client.get("/r2")
    assert 200 == resp.status
    assert middleware_annotation_seen_values == []


@pytest.fixture
def cli(loop, aiohttp_client):
    async def handler(request):
        return web.Response(text="OK")

    def wrapper(extra_middlewares):
        app = web.Application()
        app.router.add_route("GET", "/resource1", handler)
        app.router.add_route("GET", "/resource2/", handler)
        app.router.add_route("GET", "/resource1/a/b", handler)
        app.router.add_route("GET", "/resource2/a/b/", handler)
        app.router.add_route("GET", "/resource2/a/b%2Fc/", handler)
        app.middlewares.extend(extra_middlewares)
        return aiohttp_client(app, server_kwargs={"skip_url_asserts": True})

    return wrapper


class TestNormalizePathMiddleware:
    @pytest.mark.parametrize(
        "path, status",
        [
            ("/resource1", 200),
            ("/resource1/", 404),
            ("/resource2", 200),
            ("/resource2/", 200),
            ("/resource1?p1=1&p2=2", 200),
            ("/resource1/?p1=1&p2=2", 404),
            ("/resource2?p1=1&p2=2", 200),
            ("/resource2/?p1=1&p2=2", 200),
            ("/resource2/a/b%2Fc", 200),
            ("/resource2/a/b%2Fc/", 200),
        ],
    )
    async def test_add_trailing_when_necessary(self, path, status, cli):
        extra_middlewares = [web.normalize_path_middleware(merge_slashes=False)]
        client = await cli(extra_middlewares)

        resp = await client.get(path)
        assert resp.status == status
        assert resp.url.query == URL(path).query

    @pytest.mark.parametrize(
        "path, status",
        [
            ("/resource1", 200),
            ("/resource1/", 200),
            ("/resource2", 404),
            ("/resource2/", 200),
            ("/resource1?p1=1&p2=2", 200),
            ("/resource1/?p1=1&p2=2", 200),
            ("/resource2?p1=1&p2=2", 404),
            ("/resource2/?p1=1&p2=2", 200),
            ("/resource2/a/b%2Fc", 404),
            ("/resource2/a/b%2Fc/", 200),
        ],
    )
    async def test_remove_trailing_when_necessary(self, path, status, cli) -> None:
        extra_middlewares = [
            web.normalize_path_middleware(
                append_slash=False, remove_slash=True, merge_slashes=False
            )
        ]
        client = await cli(extra_middlewares)

        resp = await client.get(path)
        assert resp.status == status
        assert resp.url.query == URL(path).query

    @pytest.mark.parametrize(
        "path, status",
        [
            ("/resource1", 200),
            ("/resource1/", 404),
            ("/resource2", 404),
            ("/resource2/", 200),
            ("/resource1?p1=1&p2=2", 200),
            ("/resource1/?p1=1&p2=2", 404),
            ("/resource2?p1=1&p2=2", 404),
            ("/resource2/?p1=1&p2=2", 200),
            ("/resource2/a/b%2Fc", 404),
            ("/resource2/a/b%2Fc/", 200),
        ],
    )
    async def test_no_trailing_slash_when_disabled(self, path, status, cli):
        extra_middlewares = [
            web.normalize_path_middleware(append_slash=False, merge_slashes=False)
        ]
        client = await cli(extra_middlewares)

        resp = await client.get(path)
        assert resp.status == status
        assert resp.url.query == URL(path).query

    @pytest.mark.parametrize(
        "path, status",
        [
            ("/resource1/a/b", 200),
            ("//resource1//a//b", 200),
            ("//resource1//a//b/", 404),
            ("///resource1//a//b", 200),
            ("/////resource1/a///b", 200),
            ("/////resource1/a//b/", 404),
            ("/resource1/a/b?p=1", 200),
            ("//resource1//a//b?p=1", 200),
            ("//resource1//a//b/?p=1", 404),
            ("///resource1//a//b?p=1", 200),
            ("/////resource1/a///b?p=1", 200),
            ("/////resource1/a//b/?p=1", 404),
        ],
    )
    async def test_merge_slash(self, path, status, cli) -> None:
        extra_middlewares = [web.normalize_path_middleware(append_slash=False)]
        client = await cli(extra_middlewares)

        resp = await client.get(path)
        assert resp.status == status
        assert resp.url.query == URL(path).query

    @pytest.mark.parametrize(
        "path, status",
        [
            ("/resource1/a/b", 200),
            ("/resource1/a/b/", 404),
            ("//resource2//a//b", 200),
            ("//resource2//a//b/", 200),
            ("///resource1//a//b", 200),
            ("///resource1//a//b/", 404),
            ("/////resource1/a///b", 200),
            ("/////resource1/a///b/", 404),
            ("/resource2/a/b", 200),
            ("//resource2//a//b", 200),
            ("//resource2//a//b/", 200),
            ("///resource2//a//b", 200),
            ("///resource2//a//b/", 200),
            ("/////resource2/a///b", 200),
            ("/////resource2/a///b/", 200),
            ("/resource1/a/b?p=1", 200),
            ("/resource1/a/b/?p=1", 404),
            ("//resource2//a//b?p=1", 200),
            ("//resource2//a//b/?p=1", 200),
            ("///resource1//a//b?p=1", 200),
            ("///resource1//a//b/?p=1", 404),
            ("/////resource1/a///b?p=1", 200),
            ("/////resource1/a///b/?p=1", 404),
            ("/resource2/a/b?p=1", 200),
            ("//resource2//a//b?p=1", 200),
            ("//resource2//a//b/?p=1", 200),
            ("///resource2//a//b?p=1", 200),
            ("///resource2//a//b/?p=1", 200),
            ("/////resource2/a///b?p=1", 200),
            ("/////resource2/a///b/?p=1", 200),
        ],
    )
    async def test_append_and_merge_slash(self, path, status, cli) -> None:
        extra_middlewares = [web.normalize_path_middleware()]

        client = await cli(extra_middlewares)
        resp = await client.get(path)
        assert resp.status == status
        assert resp.url.query == URL(path).query

    @pytest.mark.parametrize(
        "path, status",
        [
            ("/resource1/a/b", 200),
            ("/resource1/a/b/", 200),
            ("//resource2//a//b", 404),
            ("//resource2//a//b/", 200),
            ("///resource1//a//b", 200),
            ("///resource1//a//b/", 200),
            ("/////resource1/a///b", 200),
            ("/////resource1/a///b/", 200),
            ("/////resource1/a///b///", 200),
            ("/resource2/a/b", 404),
            ("//resource2//a//b", 404),
            ("//resource2//a//b/", 200),
            ("///resource2//a//b", 404),
            ("///resource2//a//b/", 200),
            ("/////resource2/a///b", 404),
            ("/////resource2/a///b/", 200),
            ("/resource1/a/b?p=1", 200),
            ("/resource1/a/b/?p=1", 200),
            ("//resource2//a//b?p=1", 404),
            ("//resource2//a//b/?p=1", 200),
            ("///resource1//a//b?p=1", 200),
            ("///resource1//a//b/?p=1", 200),
            ("/////resource1/a///b?p=1", 200),
            ("/////resource1/a///b/?p=1", 200),
            ("/resource2/a/b?p=1", 404),
            ("//resource2//a//b?p=1", 404),
            ("//resource2//a//b/?p=1", 200),
            ("///resource2//a//b?p=1", 404),
            ("///resource2//a//b/?p=1", 200),
            ("/////resource2/a///b?p=1", 404),
            ("/////resource2/a///b/?p=1", 200),
        ],
    )
    async def test_remove_and_merge_slash(self, path, status, cli) -> None:
        extra_middlewares = [
            web.normalize_path_middleware(append_slash=False, remove_slash=True)
        ]

        client = await cli(extra_middlewares)
        resp = await client.get(path)
        assert resp.status == status
        assert resp.url.query == URL(path).query

    async def test_cannot_remove_and_add_slash(self) -> None:
        with pytest.raises(AssertionError):
            web.normalize_path_middleware(append_slash=True, remove_slash=True)

    @pytest.mark.parametrize(
        ["append_slash", "remove_slash"],
        [
            (True, False),
            (False, True),
            (False, False),
        ],
    )
    async def test_open_redirects(
        self, append_slash: bool, remove_slash: bool, aiohttp_client: Any
    ) -> None:
        async def handle(request: web.Request) -> web.StreamResponse:
            pytest.fail(
                msg="Security advisory 'GHSA-v6wp-4m6f-gcjg' test handler "
                "matched unexpectedly",
                pytrace=False,
            )

        app = web.Application(
            middlewares=[
                web.normalize_path_middleware(
                    append_slash=append_slash, remove_slash=remove_slash
                )
            ]
        )
        app.add_routes([web.get("/", handle), web.get("/google.com", handle)])
        client = await aiohttp_client(app, server_kwargs={"skip_url_asserts": True})
        resp = await client.get("//google.com", allow_redirects=False)
        assert resp.status == 308
        assert resp.headers["Location"] == "/google.com"
        assert resp.url.query == URL("//google.com").query


async def test_old_style_middleware(loop, aiohttp_client) -> None:
    async def handler(request):
        return web.Response(body=b"OK")

    async def middleware_factory(app, handler: Handler):
        async def middleware(request):
            resp = await handler(request)
            assert 200 == resp.status
            resp.set_status(201)
            resp.text = resp.text + "[old style middleware]"
            return resp

        return middleware

    with pytest.warns(DeprecationWarning) as warning_checker:
        app = web.Application()
        app.middlewares.append(middleware_factory)
        app.router.add_route("GET", "/", handler)
        client = await aiohttp_client(app)
        resp = await client.get("/")
        assert 201 == resp.status
        txt = await resp.text()
        assert "OK[old style middleware]" == txt

    found = False
    for obj in warning_checker.list:
        msg = str(obj.message)
        if "old-style" not in msg:
            continue
        assert re.match(
            "^old-style middleware "
            '"<function .*test_old_style_middleware.<locals>.'
            'middleware_factory at 0x[0-9a-fA-F]+>" '
            "deprecated, see #2252$",
            msg,
        )
        found = True

    assert found


async def test_old_style_middleware_class(loop, aiohttp_client) -> None:
    async def handler(request):
        return web.Response(body=b"OK")

    class Middleware:
        async def __call__(self, app, handler: Handler):
            async def middleware(request):
                resp = await handler(request)
                assert 200 == resp.status
                resp.set_status(201)
                resp.text = resp.text + "[old style middleware]"
                return resp

            return middleware

    with pytest.warns(DeprecationWarning) as warning_checker:
        app = web.Application()
        app.middlewares.append(Middleware())
        app.router.add_route("GET", "/", handler)
        client = await aiohttp_client(app)
        resp = await client.get("/")
        assert 201 == resp.status
        txt = await resp.text()
        assert "OK[old style middleware]" == txt

    found = False
    for obj in warning_checker.list:
        msg = str(obj.message)
        if "old-style" not in msg:
            continue
        assert re.match(
            "^old-style middleware "
            '"<.*test_web_middleware.test_old_style_middleware_class.'
            "<locals>.Middleware object "
            'at 0x[0-9a-fA-F]+>" deprecated, see #2252$',
            msg,
        )
        found = True

    assert found


async def test_new_style_middleware_class(loop, aiohttp_client) -> None:
    async def handler(request):
        return web.Response(body=b"OK")

    @web.middleware
    class Middleware:
        async def __call__(self, request, handler: Handler):
            resp = await handler(request)
            assert 200 == resp.status
            resp.set_status(201)
            resp.text = resp.text + "[new style middleware]"
            return resp

    app = web.Application()
    app.middlewares.append(Middleware())
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.get("/")
    assert 201 == resp.status
    txt = await resp.text()
    assert "OK[new style middleware]" == txt


async def test_new_style_middleware_method(loop, aiohttp_client) -> None:
    async def handler(request):
        return web.Response(body=b"OK")

    class Middleware:
        @web.middleware
        async def call(self, request, handler: Handler):
            resp = await handler(request)
            assert 200 == resp.status
            resp.set_status(201)
            resp.text = resp.text + "[new style middleware]"
            return resp

    app = web.Application()
    app.middlewares.append(Middleware().call)
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.get("/")
    assert 201 == resp.status
    txt = await resp.text()
    assert "OK[new style middleware]" == txt
