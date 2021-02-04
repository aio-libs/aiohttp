# type: ignore
import pathlib
import re
from collections.abc import Container, Iterable, Mapping, MutableMapping, Sized
from functools import partial
from typing import Any
from urllib.parse import unquote

import pytest
from re_assert import Matches
from yarl import URL

import aiohttp
from aiohttp import hdrs, web
from aiohttp.test_utils import make_mocked_request
from aiohttp.web import HTTPMethodNotAllowed, HTTPNotFound, Response
from aiohttp.web_urldispatcher import (
    PATH_SEP,
    AbstractResource,
    Domain,
    DynamicResource,
    MaskDomain,
    PlainResource,
    ResourceRoute,
    StaticResource,
    SystemRoute,
    View,
    _default_expect_handler,
)


def make_handler():
    async def handler(request):
        return Response(request)  # pragma: no cover

    return handler


def make_partial_handler():
    async def handler(a, request):
        return Response(request)  # pragma: no cover

    return partial(handler, 5)


@pytest.fixture
def app():
    return web.Application()


@pytest.fixture
def router(app: Any):
    return app.router


@pytest.fixture
def fill_routes(router: Any):
    def go():
        route1 = router.add_route("GET", "/plain", make_handler())
        route2 = router.add_route("GET", "/variable/{name}", make_handler())
        resource = router.add_static("/static", pathlib.Path(aiohttp.__file__).parent)
        return [route1, route2] + list(resource)

    return go


def test_register_uncommon_http_methods(router: Any) -> None:
    uncommon_http_methods = {
        "PROPFIND",
        "PROPPATCH",
        "COPY",
        "LOCK",
        "UNLOCK",
        "MOVE",
        "SUBSCRIBE",
        "UNSUBSCRIBE",
        "NOTIFY",
    }

    for method in uncommon_http_methods:
        router.add_route(method, "/handler/to/path", make_handler())


async def test_add_partial_handler(router: Any) -> None:
    handler = make_partial_handler()
    router.add_get("/handler/to/path", handler)


async def test_add_sync_handler(router: Any) -> None:
    def handler(request):
        pass

    with pytest.raises(TypeError):
        router.add_get("/handler/to/path", handler)


async def test_add_route_root(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/", handler)
    req = make_mocked_request("GET", "/")
    info = await router.resolve(req)
    assert info is not None
    assert 0 == len(info)
    assert handler is info.handler
    assert info.route.name is None


async def test_add_route_simple(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/handler/to/path", handler)
    req = make_mocked_request("GET", "/handler/to/path")
    info = await router.resolve(req)
    assert info is not None
    assert 0 == len(info)
    assert handler is info.handler
    assert info.route.name is None


async def test_add_with_matchdict(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/handler/{to}", handler)
    req = make_mocked_request("GET", "/handler/tail")
    info = await router.resolve(req)
    assert info is not None
    assert {"to": "tail"} == info
    assert handler is info.handler
    assert info.route.name is None


async def test_add_with_matchdict_with_colon(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/handler/{to}", handler)
    req = make_mocked_request("GET", "/handler/1:2:3")
    info = await router.resolve(req)
    assert info is not None
    assert {"to": "1:2:3"} == info
    assert handler is info.handler
    assert info.route.name is None


async def test_add_route_with_add_get_shortcut(router: Any) -> None:
    handler = make_handler()
    router.add_get("/handler/to/path", handler)
    req = make_mocked_request("GET", "/handler/to/path")
    info = await router.resolve(req)
    assert info is not None
    assert 0 == len(info)
    assert handler is info.handler
    assert info.route.name is None


async def test_add_route_with_add_post_shortcut(router: Any) -> None:
    handler = make_handler()
    router.add_post("/handler/to/path", handler)
    req = make_mocked_request("POST", "/handler/to/path")
    info = await router.resolve(req)
    assert info is not None
    assert 0 == len(info)
    assert handler is info.handler
    assert info.route.name is None


async def test_add_route_with_add_put_shortcut(router: Any) -> None:
    handler = make_handler()
    router.add_put("/handler/to/path", handler)
    req = make_mocked_request("PUT", "/handler/to/path")
    info = await router.resolve(req)
    assert info is not None
    assert 0 == len(info)
    assert handler is info.handler
    assert info.route.name is None


async def test_add_route_with_add_patch_shortcut(router: Any) -> None:
    handler = make_handler()
    router.add_patch("/handler/to/path", handler)
    req = make_mocked_request("PATCH", "/handler/to/path")
    info = await router.resolve(req)
    assert info is not None
    assert 0 == len(info)
    assert handler is info.handler
    assert info.route.name is None


async def test_add_route_with_add_delete_shortcut(router: Any) -> None:
    handler = make_handler()
    router.add_delete("/handler/to/path", handler)
    req = make_mocked_request("DELETE", "/handler/to/path")
    info = await router.resolve(req)
    assert info is not None
    assert 0 == len(info)
    assert handler is info.handler
    assert info.route.name is None


async def test_add_route_with_add_head_shortcut(router: Any) -> None:
    handler = make_handler()
    router.add_head("/handler/to/path", handler)
    req = make_mocked_request("HEAD", "/handler/to/path")
    info = await router.resolve(req)
    assert info is not None
    assert 0 == len(info)
    assert handler is info.handler
    assert info.route.name is None


async def test_add_with_name(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/handler/to/path", handler, name="name")
    req = make_mocked_request("GET", "/handler/to/path")
    info = await router.resolve(req)
    assert info is not None
    assert "name" == info.route.name


async def test_add_with_tailing_slash(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/handler/to/path/", handler)
    req = make_mocked_request("GET", "/handler/to/path/")
    info = await router.resolve(req)
    assert info is not None
    assert {} == info
    assert handler is info.handler


def test_add_invalid_path(router: Any) -> None:
    handler = make_handler()
    with pytest.raises(ValueError):
        router.add_route("GET", "/{/", handler)


def test_add_url_invalid1(router: Any) -> None:
    handler = make_handler()
    with pytest.raises(ValueError):
        router.add_route("post", "/post/{id", handler)


def test_add_url_invalid2(router: Any) -> None:
    handler = make_handler()
    with pytest.raises(ValueError):
        router.add_route("post", "/post/{id{}}", handler)


def test_add_url_invalid3(router: Any) -> None:
    handler = make_handler()
    with pytest.raises(ValueError):
        router.add_route("post", "/post/{id{}", handler)


def test_add_url_invalid4(router: Any) -> None:
    handler = make_handler()
    with pytest.raises(ValueError):
        router.add_route("post", '/post/{id"}', handler)


async def test_add_url_escaping(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/+$", handler)

    req = make_mocked_request("GET", "/+$")
    info = await router.resolve(req)
    assert info is not None
    assert handler is info.handler


async def test_any_method(router: Any) -> None:
    handler = make_handler()
    route = router.add_route(hdrs.METH_ANY, "/", handler)

    req = make_mocked_request("GET", "/")
    info1 = await router.resolve(req)
    assert info1 is not None
    assert route is info1.route

    req = make_mocked_request("POST", "/")
    info2 = await router.resolve(req)
    assert info2 is not None

    assert info1.route is info2.route


async def test_match_second_result_in_table(router: Any) -> None:
    handler1 = make_handler()
    handler2 = make_handler()
    router.add_route("GET", "/h1", handler1)
    router.add_route("POST", "/h2", handler2)
    req = make_mocked_request("POST", "/h2")
    info = await router.resolve(req)
    assert info is not None
    assert {} == info
    assert handler2 is info.handler


async def test_raise_method_not_allowed(router: Any) -> None:
    handler1 = make_handler()
    handler2 = make_handler()
    router.add_route("GET", "/", handler1)
    router.add_route("POST", "/", handler2)
    req = make_mocked_request("PUT", "/")

    match_info = await router.resolve(req)
    assert isinstance(match_info.route, SystemRoute)
    assert {} == match_info

    with pytest.raises(HTTPMethodNotAllowed) as ctx:
        await match_info.handler(req)

    exc = ctx.value
    assert "PUT" == exc.method
    assert 405 == exc.status
    assert {"POST", "GET"} == exc.allowed_methods


async def test_raise_method_not_found(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/a", handler)
    req = make_mocked_request("GET", "/b")

    match_info = await router.resolve(req)
    assert isinstance(match_info.route, SystemRoute)
    assert {} == match_info

    with pytest.raises(HTTPNotFound) as ctx:
        await match_info.handler(req)

    exc = ctx.value
    assert 404 == exc.status


def test_double_add_url_with_the_same_name(router: Any) -> None:
    handler1 = make_handler()
    handler2 = make_handler()
    router.add_route("GET", "/get", handler1, name="name")

    regexp = "Duplicate 'name', already handled by"
    with pytest.raises(ValueError) as ctx:
        router.add_route("GET", "/get_other", handler2, name="name")
    assert Matches(regexp) == str(ctx.value)


def test_route_plain(router: Any) -> None:
    handler = make_handler()
    route = router.add_route("GET", "/get", handler, name="name")
    route2 = next(iter(router["name"]))
    url = route2.url_for()
    assert "/get" == str(url)
    assert route is route2


def test_route_unknown_route_name(router: Any) -> None:
    with pytest.raises(KeyError):
        router["unknown"]


def test_route_dynamic(router: Any) -> None:
    handler = make_handler()
    route = router.add_route("GET", "/get/{name}", handler, name="name")

    route2 = next(iter(router["name"]))
    url = route2.url_for(name="John")
    assert "/get/John" == str(url)
    assert route is route2


def test_add_static(router: Any) -> None:
    resource = router.add_static(
        "/st", pathlib.Path(aiohttp.__file__).parent, name="static"
    )
    assert router["static"] is resource
    url = resource.url_for(filename="/dir/a.txt")
    assert "/st/dir/a.txt" == str(url)
    assert len(resource) == 2


def test_add_static_append_version(router: Any) -> None:
    resource = router.add_static("/st", pathlib.Path(__file__).parent, name="static")
    url = resource.url_for(filename="/data.unknown_mime_type", append_version=True)
    expect_url = (
        "/st/data.unknown_mime_type?" "v=aUsn8CHEhhszc81d28QmlcBW0KQpfS2F4trgQKhOYd8%3D"
    )
    assert expect_url == str(url)


def test_add_static_append_version_set_from_constructor(router: Any) -> None:
    resource = router.add_static(
        "/st", pathlib.Path(__file__).parent, append_version=True, name="static"
    )
    url = resource.url_for(filename="/data.unknown_mime_type")
    expect_url = (
        "/st/data.unknown_mime_type?" "v=aUsn8CHEhhszc81d28QmlcBW0KQpfS2F4trgQKhOYd8%3D"
    )
    assert expect_url == str(url)


def test_add_static_append_version_override_constructor(router: Any) -> None:
    resource = router.add_static(
        "/st", pathlib.Path(__file__).parent, append_version=True, name="static"
    )
    url = resource.url_for(filename="/data.unknown_mime_type", append_version=False)
    expect_url = "/st/data.unknown_mime_type"
    assert expect_url == str(url)


def test_add_static_append_version_filename_without_slash(router: Any) -> None:
    resource = router.add_static("/st", pathlib.Path(__file__).parent, name="static")
    url = resource.url_for(filename="data.unknown_mime_type", append_version=True)
    expect_url = (
        "/st/data.unknown_mime_type?" "v=aUsn8CHEhhszc81d28QmlcBW0KQpfS2F4trgQKhOYd8%3D"
    )
    assert expect_url == str(url)


def test_add_static_append_version_non_exists_file(router: Any) -> None:
    resource = router.add_static("/st", pathlib.Path(__file__).parent, name="static")
    url = resource.url_for(filename="/non_exists_file", append_version=True)
    assert "/st/non_exists_file" == str(url)


def test_add_static_append_version_non_exists_file_without_slash(router: Any) -> None:
    resource = router.add_static("/st", pathlib.Path(__file__).parent, name="static")
    url = resource.url_for(filename="non_exists_file", append_version=True)
    assert "/st/non_exists_file" == str(url)


def test_add_static_append_version_follow_symlink(router: Any, tmp_path: Any) -> None:
    # Tests the access to a symlink, in static folder with apeend_version
    symlink_path = tmp_path / "append_version_symlink"
    symlink_target_path = pathlib.Path(__file__).parent
    pathlib.Path(str(symlink_path)).symlink_to(str(symlink_target_path), True)

    # Register global static route:
    resource = router.add_static(
        "/st", str(tmp_path), follow_symlinks=True, append_version=True
    )

    url = resource.url_for(filename="/append_version_symlink/data.unknown_mime_type")

    expect_url = (
        "/st/append_version_symlink/data.unknown_mime_type?"
        "v=aUsn8CHEhhszc81d28QmlcBW0KQpfS2F4trgQKhOYd8%3D"
    )
    assert expect_url == str(url)


def test_add_static_append_version_not_follow_symlink(
    router: Any, tmp_path: Any
) -> None:
    # Tests the access to a symlink, in static folder with apeend_version

    symlink_path = tmp_path / "append_version_symlink"
    symlink_target_path = pathlib.Path(__file__).parent

    pathlib.Path(str(symlink_path)).symlink_to(str(symlink_target_path), True)

    # Register global static route:
    resource = router.add_static(
        "/st", str(tmp_path), follow_symlinks=False, append_version=True
    )

    filename = "/append_version_symlink/data.unknown_mime_type"
    url = resource.url_for(filename=filename)
    assert "/st/append_version_symlink/data.unknown_mime_type" == str(url)


def test_add_static_quoting(router: Any) -> None:
    resource = router.add_static(
        "/пре %2Fфикс", pathlib.Path(aiohttp.__file__).parent, name="static"
    )
    assert router["static"] is resource
    url = resource.url_for(filename="/1 2/файл%2F.txt")
    assert url.path == "/пре /фикс/1 2/файл%2F.txt"
    assert str(url) == (
        "/%D0%BF%D1%80%D0%B5%20%2F%D1%84%D0%B8%D0%BA%D1%81"
        "/1%202/%D1%84%D0%B0%D0%B9%D0%BB%252F.txt"
    )
    assert len(resource) == 2


def test_plain_not_match(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/get/path", handler, name="name")
    route = router["name"]
    assert route._match("/another/path") is None


def test_dynamic_not_match(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/get/{name}", handler, name="name")
    route = router["name"]
    assert route._match("/another/path") is None


async def test_static_not_match(router: Any) -> None:
    router.add_static("/pre", pathlib.Path(aiohttp.__file__).parent, name="name")
    resource = router["name"]
    ret = await resource.resolve(make_mocked_request("GET", "/another/path"))
    assert (None, set()) == ret


def test_dynamic_with_trailing_slash(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/get/{name}/", handler, name="name")
    route = router["name"]
    assert {"name": "John"} == route._match("/get/John/")


def test_len(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/get1", handler, name="name1")
    router.add_route("GET", "/get2", handler, name="name2")
    assert 2 == len(router)


def test_iter(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/get1", handler, name="name1")
    router.add_route("GET", "/get2", handler, name="name2")
    assert {"name1", "name2"} == set(iter(router))


def test_contains(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/get1", handler, name="name1")
    router.add_route("GET", "/get2", handler, name="name2")
    assert "name1" in router
    assert "name3" not in router


def test_static_repr(router: Any) -> None:
    router.add_static("/get", pathlib.Path(aiohttp.__file__).parent, name="name")
    assert Matches(r"<StaticResource 'name' /get") == repr(router["name"])


def test_static_adds_slash(router: Any) -> None:
    route = router.add_static("/prefix", pathlib.Path(aiohttp.__file__).parent)
    assert "/prefix" == route._prefix


def test_static_remove_trailing_slash(router: Any) -> None:
    route = router.add_static("/prefix/", pathlib.Path(aiohttp.__file__).parent)
    assert "/prefix" == route._prefix


async def test_add_route_with_re(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", r"/handler/{to:\d+}", handler)

    req = make_mocked_request("GET", "/handler/1234")
    info = await router.resolve(req)
    assert info is not None
    assert {"to": "1234"} == info

    router.add_route("GET", r"/handler/{name}.html", handler)
    req = make_mocked_request("GET", "/handler/test.html")
    info = await router.resolve(req)
    assert {"name": "test"} == info


async def test_add_route_with_re_and_slashes(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", r"/handler/{to:[^/]+/?}", handler)
    req = make_mocked_request("GET", "/handler/1234/")
    info = await router.resolve(req)
    assert info is not None
    assert {"to": "1234/"} == info

    router.add_route("GET", r"/handler/{to:.+}", handler)
    req = make_mocked_request("GET", "/handler/1234/5/6/7")
    info = await router.resolve(req)
    assert info is not None
    assert {"to": "1234/5/6/7"} == info


async def test_add_route_with_re_not_match(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", r"/handler/{to:\d+}", handler)

    req = make_mocked_request("GET", "/handler/tail")
    match_info = await router.resolve(req)
    assert isinstance(match_info.route, SystemRoute)
    assert {} == match_info
    with pytest.raises(HTTPNotFound):
        await match_info.handler(req)


async def test_add_route_with_re_including_slashes(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", r"/handler/{to:.+}/tail", handler)
    req = make_mocked_request("GET", "/handler/re/with/slashes/tail")
    info = await router.resolve(req)
    assert info is not None
    assert {"to": "re/with/slashes"} == info


def test_add_route_with_invalid_re(router: Any) -> None:
    handler = make_handler()
    with pytest.raises(ValueError) as ctx:
        router.add_route("GET", r"/handler/{to:+++}", handler)
    s = str(ctx.value)
    assert s.startswith(
        "Bad pattern '"
        + PATH_SEP
        + "handler"
        + PATH_SEP
        + "(?P<to>+++)': nothing to repeat"
    )
    assert ctx.value.__cause__ is None


def test_route_dynamic_with_regex_spec(router: Any) -> None:
    handler = make_handler()
    route = router.add_route("GET", r"/get/{num:^\d+}", handler, name="name")

    url = route.url_for(num="123")
    assert "/get/123" == str(url)


def test_route_dynamic_with_regex_spec_and_trailing_slash(router: Any) -> None:
    handler = make_handler()
    route = router.add_route("GET", r"/get/{num:^\d+}/", handler, name="name")

    url = route.url_for(num="123")
    assert "/get/123/" == str(url)


def test_route_dynamic_with_regex(router: Any) -> None:
    handler = make_handler()
    route = router.add_route("GET", r"/{one}/{two:.+}", handler)

    url = route.url_for(one="1", two="2")
    assert "/1/2" == str(url)


def test_route_dynamic_quoting(router: Any) -> None:
    handler = make_handler()
    route = router.add_route("GET", r"/пре %2Fфикс/{arg}", handler)

    url = route.url_for(arg="1 2/текст%2F")
    assert url.path == "/пре /фикс/1 2/текст%2F"
    assert str(url) == (
        "/%D0%BF%D1%80%D0%B5%20%2F%D1%84%D0%B8%D0%BA%D1%81"
        "/1%202/%D1%82%D0%B5%D0%BA%D1%81%D1%82%252F"
    )


async def test_regular_match_info(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/get/{name}", handler)

    req = make_mocked_request("GET", "/get/john")
    match_info = await router.resolve(req)
    assert {"name": "john"} == match_info
    assert Matches("<MatchInfo {'name': 'john'}: .+<Dynamic.+>>") == repr(match_info)


async def test_match_info_with_plus(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/get/{version}", handler)

    req = make_mocked_request("GET", "/get/1.0+test")
    match_info = await router.resolve(req)
    assert {"version": "1.0+test"} == match_info


async def test_not_found_repr(router: Any) -> None:
    req = make_mocked_request("POST", "/path/to")
    match_info = await router.resolve(req)
    assert "<MatchInfoError 404: Not Found>" == repr(match_info)


async def test_not_allowed_repr(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/path/to", handler)

    handler2 = make_handler()
    router.add_route("POST", "/path/to", handler2)

    req = make_mocked_request("PUT", "/path/to")
    match_info = await router.resolve(req)
    assert "<MatchInfoError 405: Method Not Allowed>" == repr(match_info)


def test_default_expect_handler(router: Any) -> None:
    route = router.add_route("GET", "/", make_handler())
    assert route._expect_handler is _default_expect_handler


def test_custom_expect_handler_plain(router: Any) -> None:
    async def handler(request):
        pass

    route = router.add_route("GET", "/", make_handler(), expect_handler=handler)
    assert route._expect_handler is handler
    assert isinstance(route, ResourceRoute)


def test_custom_expect_handler_dynamic(router: Any) -> None:
    async def handler(request):
        pass

    route = router.add_route(
        "GET", "/get/{name}", make_handler(), expect_handler=handler
    )
    assert route._expect_handler is handler
    assert isinstance(route, ResourceRoute)


def test_expect_handler_non_coroutine(router: Any) -> None:
    def handler(request):
        pass

    with pytest.raises(AssertionError):
        router.add_route("GET", "/", make_handler(), expect_handler=handler)


async def test_dynamic_match_non_ascii(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/{var}", handler)
    req = make_mocked_request(
        "GET", "/%D1%80%D1%83%D1%81%20%D1%82%D0%B5%D0%BA%D1%81%D1%82"
    )
    match_info = await router.resolve(req)
    assert {"var": "рус текст"} == match_info


async def test_dynamic_match_with_static_part(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/{name}.html", handler)
    req = make_mocked_request("GET", "/file.html")
    match_info = await router.resolve(req)
    assert {"name": "file"} == match_info


async def test_dynamic_match_two_part2(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/{name}.{ext}", handler)
    req = make_mocked_request("GET", "/file.html")
    match_info = await router.resolve(req)
    assert {"name": "file", "ext": "html"} == match_info


async def test_dynamic_match_unquoted_path(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/{path}/{subpath}", handler)
    resource_id = "my%2Fpath%7Cwith%21some%25strange%24characters"
    req = make_mocked_request("GET", f"/path/{resource_id}")
    match_info = await router.resolve(req)
    assert match_info == {"path": "path", "subpath": unquote(resource_id)}


def test_add_route_not_started_with_slash(router: Any) -> None:
    with pytest.raises(ValueError):
        handler = make_handler()
        router.add_route("GET", "invalid_path", handler)


def test_add_route_invalid_method(router: Any) -> None:

    sample_bad_methods = {
        "BAD METHOD",
        "B@D_METHOD",
        "[BAD_METHOD]",
        "{BAD_METHOD}",
        "(BAD_METHOD)",
        "B?D_METHOD",
    }

    for bad_method in sample_bad_methods:
        with pytest.raises(ValueError):
            handler = make_handler()
            router.add_route(bad_method, "/path", handler)


def test_routes_view_len(router: Any, fill_routes: Any) -> None:
    fill_routes()
    assert 4 == len(router.routes())


def test_routes_view_iter(router: Any, fill_routes: Any) -> None:
    routes = fill_routes()
    assert list(routes) == list(router.routes())


def test_routes_view_contains(router: Any, fill_routes: Any) -> None:
    routes = fill_routes()
    for route in routes:
        assert route in router.routes()


def test_routes_abc(router: Any) -> None:
    assert isinstance(router.routes(), Sized)
    assert isinstance(router.routes(), Iterable)
    assert isinstance(router.routes(), Container)


def test_named_resources_abc(router: Any) -> None:
    assert isinstance(router.named_resources(), Mapping)
    assert not isinstance(router.named_resources(), MutableMapping)


def test_named_resources(router: Any) -> None:
    route1 = router.add_route("GET", "/plain", make_handler(), name="route1")
    route2 = router.add_route("GET", "/variable/{name}", make_handler(), name="route2")
    route3 = router.add_static(
        "/static", pathlib.Path(aiohttp.__file__).parent, name="route3"
    )
    names = {route1.name, route2.name, route3.name}

    assert 3 == len(router.named_resources())

    for name in names:
        assert name in router.named_resources()
        assert isinstance(router.named_resources()[name], AbstractResource)


def test_resource_iter(router: Any) -> None:
    async def handler(request):
        pass

    resource = router.add_resource("/path")
    r1 = resource.add_route("GET", handler)
    r2 = resource.add_route("POST", handler)
    assert 2 == len(resource)
    assert [r1, r2] == list(resource)


def test_view_route(router: Any) -> None:
    resource = router.add_resource("/path")

    route = resource.add_route("*", View)
    assert View is route.handler


def test_resource_route_match(router: Any) -> None:
    async def handler(request):
        pass

    resource = router.add_resource("/path")
    route = resource.add_route("GET", handler)
    assert {} == route.resource._match("/path")


def test_error_on_double_route_adding(router: Any) -> None:
    async def handler(request):
        pass

    resource = router.add_resource("/path")

    resource.add_route("GET", handler)
    with pytest.raises(RuntimeError):
        resource.add_route("GET", handler)


def test_error_on_adding_route_after_wildcard(router: Any) -> None:
    async def handler(request):
        pass

    resource = router.add_resource("/path")

    resource.add_route("*", handler)
    with pytest.raises(RuntimeError):
        resource.add_route("GET", handler)


async def test_http_exception_is_none_when_resolved(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/", handler)
    req = make_mocked_request("GET", "/")
    info = await router.resolve(req)
    assert info.http_exception is None


async def test_http_exception_is_not_none_when_not_resolved(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/", handler)
    req = make_mocked_request("GET", "/abc")
    info = await router.resolve(req)
    assert info.http_exception.status == 404


async def test_match_info_get_info_plain(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/", handler)
    req = make_mocked_request("GET", "/")
    info = await router.resolve(req)
    assert info.get_info() == {"path": "/"}


async def test_match_info_get_info_dynamic(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/{a}", handler)
    req = make_mocked_request("GET", "/value")
    info = await router.resolve(req)
    assert info.get_info() == {
        "pattern": re.compile(PATH_SEP + "(?P<a>[^{}/]+)"),
        "formatter": "/{a}",
    }


async def test_match_info_get_info_dynamic2(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/{a}/{b}", handler)
    req = make_mocked_request("GET", "/path/to")
    info = await router.resolve(req)
    assert info.get_info() == {
        "pattern": re.compile(
            PATH_SEP + "(?P<a>[^{}/]+)" + PATH_SEP + "(?P<b>[^{}/]+)"
        ),
        "formatter": "/{a}/{b}",
    }


def test_static_resource_get_info(router: Any) -> None:
    directory = pathlib.Path(aiohttp.__file__).parent.resolve()
    resource = router.add_static("/st", directory)
    info = resource.get_info()
    assert len(info) == 3
    assert info["directory"] == directory
    assert info["prefix"] == "/st"
    assert all([type(r) is ResourceRoute for r in info["routes"].values()])


async def test_system_route_get_info(router: Any) -> None:
    handler = make_handler()
    router.add_route("GET", "/", handler)
    req = make_mocked_request("GET", "/abc")
    info = await router.resolve(req)
    assert info.get_info()["http_exception"].status == 404


def test_resources_view_len(router: Any) -> None:
    router.add_resource("/plain")
    router.add_resource("/variable/{name}")
    assert 2 == len(router.resources())


def test_resources_view_iter(router: Any) -> None:
    resource1 = router.add_resource("/plain")
    resource2 = router.add_resource("/variable/{name}")
    resources = [resource1, resource2]
    assert list(resources) == list(router.resources())


def test_resources_view_contains(router: Any) -> None:
    resource1 = router.add_resource("/plain")
    resource2 = router.add_resource("/variable/{name}")
    resources = [resource1, resource2]
    for resource in resources:
        assert resource in router.resources()


def test_resources_abc(router: Any) -> None:
    assert isinstance(router.resources(), Sized)
    assert isinstance(router.resources(), Iterable)
    assert isinstance(router.resources(), Container)


def test_static_route_user_home(router: Any) -> None:
    here = pathlib.Path(aiohttp.__file__).parent
    try:
        static_dir = pathlib.Path("~") / here.relative_to(pathlib.Path.home())
    except ValueError:
        pytest.skip("aiohttp folder is not placed in user's HOME")
    route = router.add_static("/st", str(static_dir))
    assert here == route.get_info()["directory"]


def test_static_route_points_to_file(router: Any) -> None:
    here = pathlib.Path(aiohttp.__file__).parent / "__init__.py"
    with pytest.raises(ValueError):
        router.add_static("/st", here)


async def test_404_for_static_resource(router: Any) -> None:
    resource = router.add_static("/st", pathlib.Path(aiohttp.__file__).parent)
    ret = await resource.resolve(make_mocked_request("GET", "/unknown/path"))
    assert (None, set()) == ret


async def test_405_for_resource_adapter(router: Any) -> None:
    resource = router.add_static("/st", pathlib.Path(aiohttp.__file__).parent)
    ret = await resource.resolve(make_mocked_request("POST", "/st/abc.py"))
    assert (None, {"HEAD", "GET"}) == ret


async def test_check_allowed_method_for_found_resource(router: Any) -> None:
    handler = make_handler()
    resource = router.add_resource("/")
    resource.add_route("GET", handler)
    ret = await resource.resolve(make_mocked_request("GET", "/"))
    assert ret[0] is not None
    assert {"GET"} == ret[1]


def test_url_for_in_static_resource(router: Any) -> None:
    resource = router.add_static("/static", pathlib.Path(aiohttp.__file__).parent)
    assert URL("/static/file.txt") == resource.url_for(filename="file.txt")


def test_url_for_in_static_resource_pathlib(router: Any) -> None:
    resource = router.add_static("/static", pathlib.Path(aiohttp.__file__).parent)
    assert URL("/static/file.txt") == resource.url_for(
        filename=pathlib.Path("file.txt")
    )


def test_url_for_in_resource_route(router: Any) -> None:
    route = router.add_route("GET", "/get/{name}", make_handler(), name="name")
    assert URL("/get/John") == route.url_for(name="John")


def test_subapp_get_info(app: Any) -> None:
    subapp = web.Application()
    resource = subapp.add_subapp("/pre", subapp)
    assert resource.get_info() == {"prefix": "/pre", "app": subapp}


@pytest.mark.parametrize(
    "domain,error",
    [
        (None, TypeError),
        ("", ValueError),
        ("http://dom", ValueError),
        ("*.example.com", ValueError),
        ("example$com", ValueError),
    ],
)
def test_domain_validation_error(domain: Any, error: Any) -> None:
    with pytest.raises(error):
        Domain(domain)


def test_domain_valid() -> None:
    assert Domain("example.com:81").canonical == "example.com:81"
    assert MaskDomain("*.example.com").canonical == r".*\.example\.com"
    assert Domain("пуни.код").canonical == "xn--h1ajfq.xn--d1alm"


@pytest.mark.parametrize(
    "a,b,result",
    [
        ("example.com", "example.com", True),
        ("example.com:81", "example.com:81", True),
        ("example.com:81", "example.com", False),
        ("пуникод", "xn--d1ahgkhc2a", True),
        ("*.example.com", "jpg.example.com", True),
        ("*.example.com", "a.example.com", True),
        ("*.example.com", "example.com", False),
    ],
)
def test_match_domain(a: Any, b: Any, result: Any) -> None:
    if "*" in a:
        rule = MaskDomain(a)
    else:
        rule = Domain(a)
    assert rule.match_domain(b) is result


def test_add_subapp_errors(app: Any) -> None:
    with pytest.raises(TypeError):
        app.add_subapp(1, web.Application())


def test_subapp_rule_resource(app: Any) -> None:
    subapp = web.Application()
    subapp.router.add_get("/", make_handler())
    rule = Domain("example.com")
    assert rule.get_info() == {"domain": "example.com"}
    resource = app.add_domain("example.com", subapp)
    assert resource.canonical == "example.com"
    assert resource.get_info() == {"rule": resource._rule, "app": subapp}
    resource.add_prefix("/a")
    resource.raw_match("/b")
    assert len(resource)
    assert list(resource)
    assert repr(resource).startswith("<MatchedSubAppResource")
    with pytest.raises(RuntimeError):
        resource.url_for()


async def test_add_domain_not_str(app: Any, loop: Any) -> None:
    app = web.Application()
    with pytest.raises(TypeError):
        app.add_domain(1, app)


async def test_add_domain(app: Any, loop: Any) -> None:
    subapp1 = web.Application()
    h1 = make_handler()
    subapp1.router.add_get("/", h1)
    app.add_domain("example.com", subapp1)

    subapp2 = web.Application()
    h2 = make_handler()
    subapp2.router.add_get("/", h2)
    app.add_domain("*.example.com", subapp2)

    subapp3 = web.Application()
    h3 = make_handler()
    subapp3.router.add_get("/", h3)
    app.add_domain("*", subapp3)

    request = make_mocked_request("GET", "/", {"host": "example.com"})
    match_info = await app.router.resolve(request)
    assert match_info.route.handler is h1

    request = make_mocked_request("GET", "/", {"host": "a.example.com"})
    match_info = await app.router.resolve(request)
    assert match_info.route.handler is h2

    request = make_mocked_request("GET", "/", {"host": "example2.com"})
    match_info = await app.router.resolve(request)
    assert match_info.route.handler is h3

    request = make_mocked_request("POST", "/", {"host": "example.com"})
    match_info = await app.router.resolve(request)
    assert isinstance(match_info.http_exception, HTTPMethodNotAllowed)


def test_subapp_url_for(app: Any) -> None:
    subapp = web.Application()
    resource = app.add_subapp("/pre", subapp)
    with pytest.raises(RuntimeError):
        resource.url_for()


def test_subapp_repr(app: Any) -> None:
    subapp = web.Application()
    resource = app.add_subapp("/pre", subapp)
    assert repr(resource).startswith("<PrefixedSubAppResource /pre -> <Application")


def test_subapp_len(app: Any) -> None:
    subapp = web.Application()
    subapp.router.add_get("/", make_handler(), allow_head=False)
    subapp.router.add_post("/", make_handler())
    resource = app.add_subapp("/pre", subapp)
    assert len(resource) == 2


def test_subapp_iter(app: Any) -> None:
    subapp = web.Application()
    r1 = subapp.router.add_get("/", make_handler(), allow_head=False)
    r2 = subapp.router.add_post("/", make_handler())
    resource = app.add_subapp("/pre", subapp)
    assert list(resource) == [r1, r2]


def test_invalid_route_name(router: Any) -> None:
    with pytest.raises(ValueError):
        router.add_get("/", make_handler(), name="invalid name")


def test_invalid_route_name(router) -> None:
    with pytest.raises(ValueError):
        router.add_get("/", make_handler(), name="class")  # identifier


def test_frozen_router(router: Any) -> None:
    router.freeze()
    with pytest.raises(RuntimeError):
        router.add_get("/", make_handler())


def test_frozen_router_subapp(app: Any) -> None:
    subapp = web.Application()
    subapp.freeze()
    with pytest.raises(RuntimeError):
        app.add_subapp("/pre", subapp)


def test_frozen_app_on_subapp(app: Any) -> None:
    app.freeze()
    subapp = web.Application()
    with pytest.raises(RuntimeError):
        app.add_subapp("/pre", subapp)


def test_set_options_route(router: Any) -> None:
    resource = router.add_static("/static", pathlib.Path(aiohttp.__file__).parent)
    options = None
    for route in resource:
        if route.method == "OPTIONS":
            options = route
    assert options is None
    resource.set_options_route(make_handler())
    for route in resource:
        if route.method == "OPTIONS":
            options = route
    assert options is not None

    with pytest.raises(RuntimeError):
        resource.set_options_route(make_handler())


def test_dynamic_url_with_name_started_from_underscore(router: Any) -> None:
    route = router.add_route("GET", "/get/{_name}", make_handler())
    assert URL("/get/John") == route.url_for(_name="John")


def test_cannot_add_subapp_with_empty_prefix(app: Any) -> None:
    subapp = web.Application()
    with pytest.raises(ValueError):
        app.add_subapp("", subapp)


def test_cannot_add_subapp_with_slash_prefix(app: Any) -> None:
    subapp = web.Application()
    with pytest.raises(ValueError):
        app.add_subapp("/", subapp)


async def test_convert_empty_path_to_slash_on_freezing(router: Any) -> None:
    handler = make_handler()
    route = router.add_get("", handler)
    resource = route.resource
    assert resource.get_info() == {"path": ""}
    router.freeze()
    assert resource.get_info() == {"path": "/"}


def test_plain_resource_canonical() -> None:
    canonical = "/plain/path"
    res = PlainResource(path=canonical)
    assert res.canonical == canonical


def test_dynamic_resource_canonical() -> None:
    canonicals = {
        "/get/{name}": "/get/{name}",
        r"/get/{num:^\d+}": "/get/{num}",
        r"/handler/{to:\d+}": r"/handler/{to}",
        r"/{one}/{two:.+}": r"/{one}/{two}",
    }
    for pattern, canonical in canonicals.items():
        res = DynamicResource(path=pattern)
        assert res.canonical == canonical


def test_static_resource_canonical() -> None:
    prefix = "/prefix"
    directory = str(pathlib.Path(aiohttp.__file__).parent)
    canonical = prefix
    res = StaticResource(prefix=prefix, directory=directory)
    assert res.canonical == canonical


def test_prefixed_subapp_resource_canonical(app: Any) -> None:
    canonical = "/prefix"
    subapp = web.Application()
    res = subapp.add_subapp(canonical, subapp)
    assert res.canonical == canonical


async def test_prefixed_subapp_overlap(app: Any) -> None:
    # Subapp should not overshadow other subapps with overlapping prefixes
    subapp1 = web.Application()
    handler1 = make_handler()
    subapp1.router.add_get("/a", handler1)
    app.add_subapp("/s", subapp1)

    subapp2 = web.Application()
    handler2 = make_handler()
    subapp2.router.add_get("/b", handler2)
    app.add_subapp("/ss", subapp2)

    match_info = await app.router.resolve(make_mocked_request("GET", "/s/a"))
    assert match_info.route.handler is handler1
    match_info = await app.router.resolve(make_mocked_request("GET", "/ss/b"))
    assert match_info.route.handler is handler2


async def test_prefixed_subapp_empty_route(app: Any) -> None:
    subapp = web.Application()
    handler = make_handler()
    subapp.router.add_get("", handler)
    app.add_subapp("/s", subapp)

    match_info = await app.router.resolve(make_mocked_request("GET", "/s"))
    assert match_info.route.handler is handler
    match_info = await app.router.resolve(make_mocked_request("GET", "/s/"))
    assert "<MatchInfoError 404: Not Found>" == repr(match_info)


async def test_prefixed_subapp_root_route(app: Any) -> None:
    subapp = web.Application()
    handler = make_handler()
    subapp.router.add_get("/", handler)
    app.add_subapp("/s", subapp)

    match_info = await app.router.resolve(make_mocked_request("GET", "/s/"))
    assert match_info.route.handler is handler
    match_info = await app.router.resolve(make_mocked_request("GET", "/s"))
    assert "<MatchInfoError 404: Not Found>" == repr(match_info)
