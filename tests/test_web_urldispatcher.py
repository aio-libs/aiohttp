# type: ignore
import asyncio
import pathlib
from typing import Any
from unittest import mock
from unittest.mock import MagicMock

import pytest
import yarl

from aiohttp import web
from aiohttp.web_urldispatcher import SystemRoute


@pytest.mark.parametrize(
    "show_index,status,prefix,data",
    [
        pytest.param(False, 403, "/", None, id="index_forbidden"),
        pytest.param(
            True,
            200,
            "/",
            b"<html>\n<head>\n<title>Index of /.</title>\n"
            b"</head>\n<body>\n<h1>Index of /.</h1>\n<ul>\n"
            b'<li><a href="/my_dir">my_dir/</a></li>\n'
            b'<li><a href="/my_file">my_file</a></li>\n'
            b"</ul>\n</body>\n</html>",
            id="index_root",
        ),
        pytest.param(
            True,
            200,
            "/static",
            b"<html>\n<head>\n<title>Index of /.</title>\n"
            b"</head>\n<body>\n<h1>Index of /.</h1>\n<ul>\n"
            b'<li><a href="/static/my_dir">my_dir/</a></li>\n'
            b'<li><a href="/static/my_file">my_file</a></li>\n'
            b"</ul>\n</body>\n</html>",
            id="index_static",
        ),
    ],
)
async def test_access_root_of_static_handler(
    tmp_path: Any,
    aiohttp_client: Any,
    show_index: Any,
    status: Any,
    prefix: Any,
    data: Any,
) -> None:
    # Tests the operation of static file server.
    # Try to access the root of static file server, and make
    # sure that correct HTTP statuses are returned depending if we directory
    # index should be shown or not.
    my_file = tmp_path / "my_file"
    my_dir = tmp_path / "my_dir"
    my_dir.mkdir()
    my_file_in_dir = my_dir / "my_file_in_dir"

    with my_file.open("w") as fw:
        fw.write("hello")

    with my_file_in_dir.open("w") as fw:
        fw.write("world")

    app = web.Application()

    # Register global static route:
    app.router.add_static(prefix, str(tmp_path), show_index=show_index)
    client = await aiohttp_client(app)

    # Request the root of the static directory.
    r = await client.get(prefix)
    assert r.status == status

    if data:
        assert r.headers["Content-Type"] == "text/html; charset=utf-8"
        read_ = await r.read()
        assert read_ == data


async def test_follow_symlink(tmp_path: Any, aiohttp_client: Any) -> None:
    # Tests the access to a symlink, in static folder
    data = "hello world"

    my_dir_path = tmp_path / "my_dir"
    my_dir_path.mkdir()

    my_file_path = my_dir_path / "my_file_in_dir"
    with my_file_path.open("w") as fw:
        fw.write(data)

    my_symlink_path = tmp_path / "my_symlink"
    pathlib.Path(str(my_symlink_path)).symlink_to(str(my_dir_path), True)

    app = web.Application()

    # Register global static route:
    app.router.add_static("/", str(tmp_path), follow_symlinks=True)
    client = await aiohttp_client(app)

    # Request the root of the static directory.
    r = await client.get("/my_symlink/my_file_in_dir")
    assert r.status == 200
    assert (await r.text()) == data


@pytest.mark.parametrize(
    "dir_name,filename,data",
    [
        ("", "test file.txt", "test text"),
        ("test dir name", "test dir file .txt", "test text file folder"),
    ],
)
async def test_access_to_the_file_with_spaces(
    tmp_path: Any, aiohttp_client: Any, dir_name: Any, filename: Any, data: Any
) -> None:
    # Checks operation of static files with spaces

    my_dir_path = tmp_path / dir_name
    if my_dir_path != tmp_path:
        my_dir_path.mkdir()

    my_file_path = my_dir_path / filename
    with my_file_path.open("w") as fw:
        fw.write(data)

    app = web.Application()

    url = "/" + str(pathlib.Path(dir_name, filename))

    app.router.add_static("/", str(tmp_path))
    client = await aiohttp_client(app)

    r = await client.get(url)
    assert r.status == 200
    assert (await r.text()) == data
    await r.release()


async def test_access_non_existing_resource(tmp_path: Any, aiohttp_client: Any) -> None:
    # Tests accessing non-existing resource
    # Try to access a non-exiting resource and make sure that 404 HTTP status
    # returned.
    app = web.Application()

    # Register global static route:
    app.router.add_static("/", str(tmp_path), show_index=True)
    client = await aiohttp_client(app)

    # Request the root of the static directory.
    r = await client.get("/non_existing_resource")
    assert r.status == 404


@pytest.mark.parametrize(
    "registered_path,request_url",
    [
        ("/a:b", "/a:b"),
        ("/a@b", "/a@b"),
        ("/a:b", "/a%3Ab"),
    ],
)
async def test_url_escaping(
    aiohttp_client: Any, registered_path: Any, request_url: Any
) -> None:
    # Tests accessing a resource with
    app = web.Application()

    async def handler(request):
        return web.Response()

    app.router.add_get(registered_path, handler)
    client = await aiohttp_client(app)

    r = await client.get(request_url)
    assert r.status == 200


async def test_handler_metadata_persistence() -> None:
    # Tests accessing metadata of a handler after registering it on the app
    # router.
    app = web.Application()

    async def async_handler(request):
        """Doc"""
        return web.Response()

    app.router.add_get("/async", async_handler)

    for resource in app.router.resources():
        for route in resource:
            assert route.handler.__doc__ == "Doc"


async def test_unauthorized_folder_access(tmp_path: Any, aiohttp_client: Any) -> None:
    # Tests the unauthorized access to a folder of static file server.
    # Try to list a folder content of static file server when server does not
    # have permissions to do so for the folder.
    my_dir = tmp_path / "my_dir"
    my_dir.mkdir()

    app = web.Application()

    with mock.patch("pathlib.Path.__new__") as path_constructor:
        path = MagicMock()
        path.joinpath.return_value = path
        path.resolve.return_value = path
        path.iterdir.return_value.__iter__.side_effect = PermissionError()
        path_constructor.return_value = path

        # Register global static route:
        app.router.add_static("/", str(tmp_path), show_index=True)
        client = await aiohttp_client(app)

        # Request the root of the static directory.
        r = await client.get("/" + my_dir.name)
        assert r.status == 403


async def test_access_symlink_loop(tmp_path: Any, aiohttp_client: Any) -> None:
    # Tests the access to a looped symlink, which could not be resolved.
    my_dir_path = tmp_path / "my_symlink"
    pathlib.Path(str(my_dir_path)).symlink_to(str(my_dir_path), True)

    app = web.Application()

    # Register global static route:
    app.router.add_static("/", str(tmp_path), show_index=True)
    client = await aiohttp_client(app)

    # Request the root of the static directory.
    r = await client.get("/" + my_dir_path.name)
    assert r.status == 404


async def test_access_special_resource(tmp_path: Any, aiohttp_client: Any) -> None:
    # Tests the access to a resource that is neither a file nor a directory.
    # Checks that if a special resource is accessed (f.e. named pipe or UNIX
    # domain socket) then 404 HTTP status returned.
    app = web.Application()

    with mock.patch("pathlib.Path.__new__") as path_constructor:
        special = MagicMock()
        special.is_dir.return_value = False
        special.is_file.return_value = False

        path = MagicMock()
        path.joinpath.side_effect = lambda p: (special if p == "special" else path)
        path.resolve.return_value = path
        special.resolve.return_value = special

        path_constructor.return_value = path

        # Register global static route:
        app.router.add_static("/", str(tmp_path), show_index=True)
        client = await aiohttp_client(app)

        # Request the root of the static directory.
        r = await client.get("/special")
        assert r.status == 403


async def test_static_head(tmp_path: Any, aiohttp_client: Any) -> None:
    # Test HEAD on static route
    my_file_path = tmp_path / "test.txt"
    with my_file_path.open("wb") as fw:
        fw.write(b"should_not_see_this\n")

    app = web.Application()
    app.router.add_static("/", str(tmp_path))
    client = await aiohttp_client(app)

    r = await client.head("/test.txt")
    assert r.status == 200

    # Check that there is no content sent (see #4809). This can't easily be
    # done with aiohttp_client because the buffering can consume the content.
    reader, writer = await asyncio.open_connection(client.host, client.port)
    writer.write(b"HEAD /test.txt HTTP/1.1\r\n")
    writer.write(b"Host: localhost\r\n")
    writer.write(b"Connection: close\r\n")
    writer.write(b"\r\n")
    while await reader.readline() != b"\r\n":
        pass
    content = await reader.read()
    writer.close()
    assert content == b""


def test_system_route() -> None:
    route = SystemRoute(web.HTTPCreated(reason="test"))
    with pytest.raises(RuntimeError):
        route.url_for()
    assert route.name is None
    assert route.resource is None
    assert "<SystemRoute 201: test>" == repr(route)
    assert 201 == route.status
    assert "test" == route.reason


async def test_allow_head(aiohttp_client: Any) -> None:
    # Test allow_head on routes.
    app = web.Application()

    async def handler(_):
        return web.Response()

    app.router.add_get("/a", handler, name="a")
    app.router.add_get("/b", handler, allow_head=False, name="b")
    client = await aiohttp_client(app)

    r = await client.get("/a")
    assert r.status == 200
    await r.release()

    r = await client.head("/a")
    assert r.status == 200
    await r.release()

    r = await client.get("/b")
    assert r.status == 200
    await r.release()

    r = await client.head("/b")
    assert r.status == 405
    await r.release()


@pytest.mark.parametrize(
    "path",
    [
        "/a",
        "/{a}",
    ],
)
def test_reuse_last_added_resource(path: Any) -> None:
    # Test that adding a route with the same name and path of the last added
    # resource doesn't create a new resource.
    app = web.Application()

    async def handler(request):
        return web.Response()

    app.router.add_get(path, handler, name="a")
    app.router.add_post(path, handler, name="a")

    assert len(app.router.resources()) == 1


def test_resource_raw_match() -> None:
    app = web.Application()

    async def handler(request):
        return web.Response()

    route = app.router.add_get("/a", handler, name="a")
    assert route.resource.raw_match("/a")

    route = app.router.add_get("/{b}", handler, name="b")
    assert route.resource.raw_match("/{b}")

    resource = app.router.add_static("/static", ".")
    assert not resource.raw_match("/static")


async def test_add_view(aiohttp_client: Any) -> None:
    app = web.Application()

    class MyView(web.View):
        async def get(self):
            return web.Response()

        async def post(self):
            return web.Response()

    app.router.add_view("/a", MyView)

    client = await aiohttp_client(app)

    r = await client.get("/a")
    assert r.status == 200
    await r.release()

    r = await client.post("/a")
    assert r.status == 200
    await r.release()

    r = await client.put("/a")
    assert r.status == 405
    await r.release()


async def test_decorate_view(aiohttp_client: Any) -> None:
    routes = web.RouteTableDef()

    @routes.view("/a")
    class MyView(web.View):
        async def get(self):
            return web.Response()

        async def post(self):
            return web.Response()

    app = web.Application()
    app.router.add_routes(routes)

    client = await aiohttp_client(app)

    r = await client.get("/a")
    assert r.status == 200
    await r.release()

    r = await client.post("/a")
    assert r.status == 200
    await r.release()

    r = await client.put("/a")
    assert r.status == 405
    await r.release()


async def test_web_view(aiohttp_client: Any) -> None:
    app = web.Application()

    class MyView(web.View):
        async def get(self):
            return web.Response()

        async def post(self):
            return web.Response()

    app.router.add_routes([web.view("/a", MyView)])

    client = await aiohttp_client(app)

    r = await client.get("/a")
    assert r.status == 200
    await r.release()

    r = await client.post("/a")
    assert r.status == 200
    await r.release()

    r = await client.put("/a")
    assert r.status == 405
    await r.release()


async def test_static_absolute_url(aiohttp_client: Any, tmp_path: Any) -> None:
    # requested url is an absolute name like
    # /static/\\machine_name\c$ or /static/D:\path
    # where the static dir is totally different
    app = web.Application()
    file_path = tmp_path / "file.txt"
    file_path.write_text("sample text", "ascii")
    here = pathlib.Path(__file__).parent
    app.router.add_static("/static", here)
    client = await aiohttp_client(app)
    resp = await client.get("/static/" + str(file_path.resolve()))
    assert resp.status == 403


async def test_for_issue_5250(aiohttp_client: Any, tmp_path: Any) -> None:
    app = web.Application()
    app.router.add_static("/foo", tmp_path)

    async def get_foobar(request):
        return web.Response(body="success!")

    app.router.add_get("/foobar", get_foobar)

    client = await aiohttp_client(app)
    async with await client.get("/foobar") as resp:
        assert resp.status == 200
        assert (await resp.text()) == "success!"


@pytest.mark.xfail(
    raises=AssertionError,
    reason="Regression in v3.7: https://github.com/aio-libs/aiohttp/issues/5621",
)
@pytest.mark.parametrize(
    ("route_definition", "urlencoded_path", "expected_http_resp_status"),
    (
        ("/467,802,24834/hello", "/467%2C802%2C24834/hello", 200),
        ("/{user_ids:([0-9]+)(,([0-9]+))*}/hello", "/467%2C802%2C24834/hello", 200),
        ("/1%2C3/hello", "/1%2C3/hello", 404),
    ),
    ids=("urldecoded_route", "urldecoded_route_with_regex", "urlencoded_route"),
)
async def test_decoded_url_match(
    aiohttp_client,
    route_definition,
    urlencoded_path,
    expected_http_resp_status,
) -> None:
    app = web.Application()

    async def handler(_):
        return web.Response()

    app.router.add_get(route_definition, handler)
    client = await aiohttp_client(app)

    r = await client.get(yarl.URL(urlencoded_path, encoded=True))
    assert r.status == expected_http_resp_status
    await r.release()
