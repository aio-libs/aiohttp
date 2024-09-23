import asyncio
import functools
import os
import pathlib
import socket
import sys
from stat import S_IFIFO, S_IMODE
from typing import Any, Generator, NoReturn, Optional

import pytest
import yarl

from aiohttp import abc, web
from aiohttp.pytest_plugin import AiohttpClient
from aiohttp.web_urldispatcher import Resource, SystemRoute


@pytest.mark.parametrize(
    "show_index,status,prefix,request_path,data",
    [
        pytest.param(False, 403, "/", "/", None, id="index_forbidden"),
        pytest.param(
            True,
            200,
            "/",
            "/",
            b"<html>\n<head>\n<title>Index of /.</title>\n</head>\n<body>\n<h1>Index of"
            b' /.</h1>\n<ul>\n<li><a href="/my_dir">my_dir/</a></li>\n<li><a href="/my_file">'
            b"my_file</a></li>\n</ul>\n</body>\n</html>",
        ),
        pytest.param(
            True,
            200,
            "/static",
            "/static",
            b"<html>\n<head>\n<title>Index of /.</title>\n</head>\n<body>\n<h1>Index of"
            b' /.</h1>\n<ul>\n<li><a href="/static/my_dir">my_dir/</a></li>\n<li><a href="'
            b'/static/my_file">my_file</a></li>\n</ul>\n</body>\n</html>',
            id="index_static",
        ),
        pytest.param(
            True,
            200,
            "/static",
            "/static/my_dir",
            b"<html>\n<head>\n<title>Index of /my_dir</title>\n</head>\n<body>\n<h1>"
            b'Index of /my_dir</h1>\n<ul>\n<li><a href="/static/my_dir/my_file_in_dir">'
            b"my_file_in_dir</a></li>\n</ul>\n</body>\n</html>",
            id="index_subdir",
        ),
    ],
)
async def test_access_root_of_static_handler(
    tmp_path: pathlib.Path,
    aiohttp_client: AiohttpClient,
    show_index: bool,
    status: int,
    prefix: str,
    request_path: str,
    data: Optional[bytes],
) -> None:
    # Tests the operation of static file server.
    # Try to access the root of static file server, and make
    # sure that correct HTTP statuses are returned depending if we directory
    # index should be shown or not.
    # Put a file inside tmp_path:
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
    async with await client.get(request_path) as r:
        assert r.status == status

        if data:
            assert r.headers["Content-Type"] == "text/html; charset=utf-8"
            read_ = await r.read()
            assert read_ == data


@pytest.mark.internal  # Dependent on filesystem
@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Invalid filenames on some filesystems (like Windows)",
)
@pytest.mark.parametrize(
    "show_index,status,prefix,request_path,data",
    [
        pytest.param(False, 403, "/", "/", None, id="index_forbidden"),
        pytest.param(
            True,
            200,
            "/",
            "/",
            b"<html>\n<head>\n<title>Index of /.</title>\n</head>\n<body>\n<h1>Index of"
            b' /.</h1>\n<ul>\n<li><a href="/%3Cimg%20src=0%20onerror=alert(1)%3E.dir">&l'
            b't;img src=0 onerror=alert(1)&gt;.dir/</a></li>\n<li><a href="/%3Cimg%20sr'
            b'c=0%20onerror=alert(1)%3E.txt">&lt;img src=0 onerror=alert(1)&gt;.txt</a></l'
            b"i>\n</ul>\n</body>\n</html>",
        ),
        pytest.param(
            True,
            200,
            "/static",
            "/static",
            b"<html>\n<head>\n<title>Index of /.</title>\n</head>\n<body>\n<h1>Index of"
            b' /.</h1>\n<ul>\n<li><a href="/static/%3Cimg%20src=0%20onerror=alert(1)%3E.'
            b'dir">&lt;img src=0 onerror=alert(1)&gt;.dir/</a></li>\n<li><a href="/stat'
            b'ic/%3Cimg%20src=0%20onerror=alert(1)%3E.txt">&lt;img src=0 onerror=alert(1)&'
            b"gt;.txt</a></li>\n</ul>\n</body>\n</html>",
            id="index_static",
        ),
        pytest.param(
            True,
            200,
            "/static",
            "/static/<img src=0 onerror=alert(1)>.dir",
            b"<html>\n<head>\n<title>Index of /&lt;img src=0 onerror=alert(1)&gt;.dir</t"
            b"itle>\n</head>\n<body>\n<h1>Index of /&lt;img src=0 onerror=alert(1)&gt;.di"
            b'r</h1>\n<ul>\n<li><a href="/static/%3Cimg%20src=0%20onerror=alert(1)%3E.di'
            b'r/my_file_in_dir">my_file_in_dir</a></li>\n</ul>\n</body>\n</html>',
            id="index_subdir",
        ),
    ],
)
async def test_access_root_of_static_handler_xss(
    tmp_path: pathlib.Path,
    aiohttp_client: AiohttpClient,
    show_index: bool,
    status: int,
    prefix: str,
    request_path: str,
    data: Optional[bytes],
) -> None:
    # Tests the operation of static file server.
    # Try to access the root of static file server, and make
    # sure that correct HTTP statuses are returned depending if we directory
    # index should be shown or not.
    # Ensure that html in file names is escaped.
    # Ensure that links are url quoted.
    my_file = tmp_path / "<img src=0 onerror=alert(1)>.txt"
    my_dir = tmp_path / "<img src=0 onerror=alert(1)>.dir"
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
    async with await client.get(request_path) as r:
        assert r.status == status

        if data:
            assert r.headers["Content-Type"] == "text/html; charset=utf-8"
            read_ = await r.read()
            assert read_ == data


async def test_follow_symlink(
    tmp_path: pathlib.Path, aiohttp_client: AiohttpClient
) -> None:
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


async def test_follow_symlink_directory_traversal(
    tmp_path: pathlib.Path, aiohttp_client: AiohttpClient
) -> None:
    # Tests that follow_symlinks does not allow directory transversal
    data = "private"

    private_file = tmp_path / "private_file"
    private_file.write_text(data)

    safe_path = tmp_path / "safe_dir"
    safe_path.mkdir()

    app = web.Application()

    # Register global static route:
    app.router.add_static("/", str(safe_path), follow_symlinks=True)
    client = await aiohttp_client(app)

    await client.start_server()
    # We need to use a raw socket to test this, as the client will normalize
    # the path before sending it to the server.
    reader, writer = await asyncio.open_connection(client.host, client.port)
    writer.write(b"GET /../private_file HTTP/1.1\r\n\r\n")
    response = await reader.readuntil(b"\r\n\r\n")
    assert b"404 Not Found" in response
    writer.close()
    await writer.wait_closed()
    await client.close()


async def test_follow_symlink_directory_traversal_after_normalization(
    tmp_path: pathlib.Path, aiohttp_client: AiohttpClient
) -> None:
    # Tests that follow_symlinks does not allow directory transversal
    # after normalization
    #
    # Directory structure
    # |-- secret_dir
    # |   |-- private_file (should never be accessible)
    # |   |-- symlink_target_dir
    # |       |-- symlink_target_file (should be accessible via the my_symlink symlink)
    # |       |-- sandbox_dir
    # |           |-- my_symlink -> symlink_target_dir
    #
    secret_path = tmp_path / "secret_dir"
    secret_path.mkdir()

    # This file is below the symlink target and should not be reachable
    private_file = secret_path / "private_file"
    private_file.write_text("private")

    symlink_target_path = secret_path / "symlink_target_dir"
    symlink_target_path.mkdir()

    sandbox_path = symlink_target_path / "sandbox_dir"
    sandbox_path.mkdir()

    # This file should be reachable via the symlink
    symlink_target_file = symlink_target_path / "symlink_target_file"
    symlink_target_file.write_text("readable")

    my_symlink_path = sandbox_path / "my_symlink"
    pathlib.Path(str(my_symlink_path)).symlink_to(str(symlink_target_path), True)

    app = web.Application()

    # Register global static route:
    app.router.add_static("/", str(sandbox_path), follow_symlinks=True)
    client = await aiohttp_client(app)

    await client.start_server()
    # We need to use a raw socket to test this, as the client will normalize
    # the path before sending it to the server.
    reader, writer = await asyncio.open_connection(client.host, client.port)
    writer.write(b"GET /my_symlink/../private_file HTTP/1.1\r\n\r\n")
    response = await reader.readuntil(b"\r\n\r\n")
    assert b"404 Not Found" in response
    writer.close()
    await writer.wait_closed()

    reader, writer = await asyncio.open_connection(client.host, client.port)
    writer.write(b"GET /my_symlink/symlink_target_file HTTP/1.1\r\n\r\n")
    response = await reader.readuntil(b"\r\n\r\n")
    assert b"200 OK" in response
    response = await reader.readuntil(b"readable")
    assert response == b"readable"
    writer.close()
    await writer.wait_closed()
    await client.close()


@pytest.mark.parametrize(
    "dir_name,filename,data",
    [
        ("", "test file.txt", "test text"),
        ("test dir name", "test dir file .txt", "test text file folder"),
    ],
)
async def test_access_to_the_file_with_spaces(
    tmp_path: pathlib.Path,
    aiohttp_client: AiohttpClient,
    dir_name: str,
    filename: str,
    data: str,
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


async def test_access_non_existing_resource(
    tmp_path: pathlib.Path, aiohttp_client: AiohttpClient
) -> None:
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
    aiohttp_client: AiohttpClient, registered_path: str, request_url: str
) -> None:
    # Tests accessing a resource with
    app = web.Application()

    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    app.router.add_get(registered_path, handler)
    client = await aiohttp_client(app)

    r = await client.get(request_url)
    assert r.status == 200


async def test_handler_metadata_persistence() -> None:
    """Tests accessing metadata of a handler after registering it on the app router."""
    app = web.Application()

    async def async_handler(request: web.Request) -> web.Response:
        """Doc"""
        return web.Response()  # pragma: no cover

    def sync_handler(request):
        """Doc"""
        return web.Response()

    app.router.add_get("/async", async_handler)
    with pytest.warns(DeprecationWarning):
        app.router.add_get("/sync", sync_handler)

    for resource in app.router.resources():
        for route in resource:
            assert route.handler.__doc__ == "Doc"


@pytest.mark.skipif(
    sys.platform.startswith("win32"), reason="Cannot remove read access on Windows"
)
@pytest.mark.parametrize("file_request", ["", "my_file.txt"])
async def test_static_directory_without_read_permission(
    tmp_path: pathlib.Path, aiohttp_client: AiohttpClient, file_request: str
) -> None:
    """Test static directory without read permission receives forbidden response."""
    my_dir = tmp_path / "my_dir"
    my_dir.mkdir()
    my_dir.chmod(0o000)

    app = web.Application()
    app.router.add_static("/", str(tmp_path), show_index=True)
    client = await aiohttp_client(app)

    r = await client.get(f"/{my_dir.name}/{file_request}")
    assert r.status == 403


@pytest.mark.parametrize("file_request", ["", "my_file.txt"])
async def test_static_directory_with_mock_permission_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    aiohttp_client: AiohttpClient,
    file_request: str,
) -> None:
    """Test static directory with mock permission errors receives forbidden response."""
    my_dir = tmp_path / "my_dir"
    my_dir.mkdir()

    real_iterdir = pathlib.Path.iterdir
    real_is_dir = pathlib.Path.is_dir

    def mock_iterdir(self: pathlib.Path) -> Generator[pathlib.Path, None, None]:
        if my_dir.samefile(self):
            raise PermissionError()
        return real_iterdir(self)

    def mock_is_dir(self: pathlib.Path, **kwargs: Any) -> bool:
        if my_dir.samefile(self.parent):
            raise PermissionError()
        return real_is_dir(self, **kwargs)

    monkeypatch.setattr("pathlib.Path.iterdir", mock_iterdir)
    monkeypatch.setattr("pathlib.Path.is_dir", mock_is_dir)

    app = web.Application()
    app.router.add_static("/", str(tmp_path), show_index=True)
    client = await aiohttp_client(app)

    r = await client.get("/")
    assert r.status == 200
    r = await client.get(f"/{my_dir.name}/{file_request}")
    assert r.status == 403


@pytest.mark.skipif(
    sys.platform.startswith("win32"), reason="Cannot remove read access on Windows"
)
async def test_static_file_without_read_permission(
    tmp_path: pathlib.Path, aiohttp_client: AiohttpClient
) -> None:
    """Test static file without read permission receives forbidden response."""
    my_file = tmp_path / "my_file.txt"
    my_file.write_text("secret")
    my_file.chmod(0o000)

    app = web.Application()
    app.router.add_static("/", str(tmp_path))
    client = await aiohttp_client(app)

    r = await client.get(f"/{my_file.name}")
    assert r.status == 403


async def test_static_file_with_mock_permission_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    aiohttp_client: AiohttpClient,
) -> None:
    """Test static file with mock permission errors receives forbidden response."""
    my_file = tmp_path / "my_file.txt"
    my_file.write_text("secret")
    my_readable = tmp_path / "my_readable.txt"
    my_readable.write_text("info")

    real_open = pathlib.Path.open

    def mock_open(self: pathlib.Path, *args: Any, **kwargs: Any) -> Any:
        if my_file.samefile(self):
            raise PermissionError()
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr("pathlib.Path.open", mock_open)

    app = web.Application()
    app.router.add_static("/", str(tmp_path))
    client = await aiohttp_client(app)

    # Test the mock only applies to my_file, then test the permission error.
    r = await client.get(f"/{my_readable.name}")
    assert r.status == 200
    r = await client.get(f"/{my_file.name}")
    assert r.status == 403


async def test_access_symlink_loop(
    tmp_path: pathlib.Path, aiohttp_client: AiohttpClient
) -> None:
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


async def test_access_compressed_file_as_symlink(
    tmp_path: pathlib.Path, aiohttp_client: AiohttpClient
) -> None:
    """Test that compressed file variants as symlinks are ignored."""
    private_file = tmp_path / "private.txt"
    private_file.write_text("private info")
    www_dir = tmp_path / "www"
    www_dir.mkdir()
    gz_link = www_dir / "file.txt.gz"
    gz_link.symlink_to(f"../{private_file.name}")

    app = web.Application()
    app.router.add_static("/", www_dir)
    client = await aiohttp_client(app)

    # Symlink should be ignored; response reflects missing uncompressed file.
    resp = await client.get(f"/{gz_link.stem}", auto_decompress=False)
    assert resp.status == 404
    resp.release()

    # Again symlin is ignored, and then uncompressed is served.
    txt_file = gz_link.with_suffix("")
    txt_file.write_text("public data")
    resp = await client.get(f"/{txt_file.name}")
    assert resp.status == 200
    assert resp.headers.get("Content-Encoding") is None
    assert resp.content_type == "text/plain"
    assert await resp.text() == "public data"
    resp.release()
    await client.close()


async def test_access_special_resource(
    tmp_path_factory: pytest.TempPathFactory, aiohttp_client: AiohttpClient
) -> None:
    """Test access to non-regular files is forbidden using a UNIX domain socket."""
    if not getattr(socket, "AF_UNIX", None):
        pytest.skip("UNIX domain sockets not supported")

    tmp_path = tmp_path_factory.mktemp("special")
    my_special = tmp_path / "sock"
    my_socket = socket.socket(socket.AF_UNIX)
    my_socket.bind(str(my_special))
    assert my_special.is_socket()

    app = web.Application()
    app.router.add_static("/", str(tmp_path))

    client = await aiohttp_client(app)
    r = await client.get(f"/{my_special.name}")
    assert r.status == 403
    my_socket.close()


async def test_access_mock_special_resource(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    aiohttp_client: AiohttpClient,
) -> None:
    """Test access to non-regular files is forbidden using a mock FIFO."""
    my_special = tmp_path / "my_special"
    my_special.touch()

    real_result = my_special.stat()
    real_stat = pathlib.Path.stat

    def mock_stat(self: pathlib.Path, **kwargs: Any) -> os.stat_result:
        s = real_stat(self, **kwargs)
        if os.path.samestat(s, real_result):
            mock_mode = S_IFIFO | S_IMODE(s.st_mode)
            s = os.stat_result([mock_mode] + list(s)[1:])
        return s

    monkeypatch.setattr("pathlib.Path.stat", mock_stat)

    app = web.Application()
    app.router.add_static("/", str(tmp_path))
    client = await aiohttp_client(app)

    r = await client.get(f"/{my_special.name}")
    assert r.status == 403


async def test_partially_applied_handler(aiohttp_client: AiohttpClient) -> None:
    app = web.Application()

    async def handler(data, request):
        return web.Response(body=data)

    app.router.add_route("GET", "/", functools.partial(handler, b"hello"))

    client = await aiohttp_client(app)

    r = await client.get("/")
    data = await r.read()
    assert data == b"hello"


async def test_static_head(
    tmp_path: pathlib.Path, aiohttp_client: AiohttpClient
) -> None:
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


async def test_412_is_returned(aiohttp_client: AiohttpClient) -> None:
    class MyRouter(abc.AbstractRouter):
        async def resolve(self, request):
            raise web.HTTPPreconditionFailed()

    with pytest.warns(DeprecationWarning):
        app = web.Application(router=MyRouter())

    client = await aiohttp_client(app)

    resp = await client.get("/")

    assert resp.status == 412


async def test_allow_head(aiohttp_client: AiohttpClient) -> None:
    # Test allow_head on routes.
    app = web.Application()

    async def handler(request: web.Request) -> web.Response:
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
    (
        "/a",
        "/{a}",
        "/{a:.*}",
    ),
)
def test_reuse_last_added_resource(path: str) -> None:
    # Test that adding a route with the same name and path of the last added
    # resource doesn't create a new resource.
    app = web.Application()

    async def handler(request: web.Request) -> web.Response:
        return web.Response()  # pragma: no cover

    app.router.add_get(path, handler, name="a")
    app.router.add_post(path, handler, name="a")

    assert len(app.router.resources()) == 1


def test_resource_raw_match() -> None:
    app = web.Application()

    async def handler(request: web.Request) -> web.Response:
        return web.Response()  # pragma: no cover

    route = app.router.add_get("/a", handler, name="a")
    assert route.resource is not None
    assert route.resource.raw_match("/a")

    route = app.router.add_get("/{b}", handler, name="b")
    assert route.resource is not None
    assert route.resource.raw_match("/{b}")

    resource = app.router.add_static("/static", ".")
    assert not resource.raw_match("/static")


async def test_add_view(aiohttp_client: AiohttpClient) -> None:
    app = web.Application()

    class MyView(web.View):
        async def get(self) -> web.Response:
            return web.Response()

        async def post(self) -> web.Response:
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


async def test_decorate_view(aiohttp_client: AiohttpClient) -> None:
    routes = web.RouteTableDef()

    @routes.view("/a")
    class MyView(web.View):
        async def get(self) -> web.Response:
            return web.Response()

        async def post(self) -> web.Response:
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


async def test_web_view(aiohttp_client: AiohttpClient) -> None:
    app = web.Application()

    class MyView(web.View):
        async def get(self) -> web.Response:
            return web.Response()

        async def post(self) -> web.Response:
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


async def test_static_absolute_url(
    aiohttp_client: AiohttpClient, tmp_path: pathlib.Path
) -> None:
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


async def test_for_issue_5250(
    aiohttp_client: AiohttpClient, tmp_path: pathlib.Path
) -> None:
    app = web.Application()
    app.router.add_static("/foo", tmp_path)

    async def get_foobar(request: web.Request) -> web.Response:
        return web.Response(body="success!")

    app.router.add_get("/foobar", get_foobar)

    client = await aiohttp_client(app)
    async with await client.get("/foobar") as resp:
        assert resp.status == 200
        assert (await resp.text()) == "success!"


@pytest.mark.parametrize(
    ("route_definition", "urlencoded_path", "expected_http_resp_status"),
    (
        ("/467,802,24834/hello", "/467%2C802%2C24834/hello", 200),
        ("/{user_ids:([0-9]+)(,([0-9]+))*}/hello", "/467%2C802%2C24834/hello", 200),
        ("/467,802,24834/hello", "/467,802,24834/hello", 200),
        ("/{user_ids:([0-9]+)(,([0-9]+))*}/hello", "/467,802,24834/hello", 200),
        ("/1%2C3/hello", "/1%2C3/hello", 404),
    ),
)
async def test_decoded_url_match(
    aiohttp_client: AiohttpClient,
    route_definition: str,
    urlencoded_path: str,
    expected_http_resp_status: int,
) -> None:
    app = web.Application()

    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    app.router.add_get(route_definition, handler)
    client = await aiohttp_client(app)

    async with client.get(yarl.URL(urlencoded_path, encoded=True)) as resp:
        assert resp.status == expected_http_resp_status


async def test_decoded_raw_match_regex(aiohttp_client: AiohttpClient) -> None:
    """Verify that raw_match only matches decoded url."""
    app = web.Application()

    async def handler(request: web.Request) -> NoReturn:
        assert False

    app.router.add_get("/467%2C802%2C24834%2C24952%2C25362%2C40574/hello", handler)
    client = await aiohttp_client(app)

    async with client.get(
        yarl.URL("/467%2C802%2C24834%2C24952%2C25362%2C40574/hello", encoded=True)
    ) as resp:
        assert resp.status == 404  # should only match decoded url


async def test_order_is_preserved(aiohttp_client: AiohttpClient) -> None:
    """Test route order is preserved.

    Note that fixed/static paths are always preferred over a regex path.
    """
    app = web.Application()

    async def handler(request: web.Request) -> web.Response:
        assert isinstance(request.match_info._route.resource, Resource)
        return web.Response(text=request.match_info._route.resource.canonical)

    app.router.add_get("/first/x/{b}/", handler)
    app.router.add_get(r"/first/{x:.*/b}", handler)

    app.router.add_get(r"/second/{user}/info", handler)
    app.router.add_get("/second/bob/info", handler)

    app.router.add_get("/third/bob/info", handler)
    app.router.add_get(r"/third/{user}/info", handler)

    app.router.add_get(r"/forth/{name:\d+}", handler)
    app.router.add_get("/forth/42", handler)

    app.router.add_get("/fifth/42", handler)
    app.router.add_get(r"/fifth/{name:\d+}", handler)

    client = await aiohttp_client(app)

    r = await client.get("/first/x/b/")
    assert r.status == 200
    assert await r.text() == "/first/x/{b}/"

    r = await client.get("/second/frank/info")
    assert r.status == 200
    assert await r.text() == "/second/{user}/info"

    # Fixed/static paths are always preferred over regex paths
    r = await client.get("/second/bob/info")
    assert r.status == 200
    assert await r.text() == "/second/bob/info"

    r = await client.get("/third/bob/info")
    assert r.status == 200
    assert await r.text() == "/third/bob/info"

    r = await client.get("/third/frank/info")
    assert r.status == 200
    assert await r.text() == "/third/{user}/info"

    r = await client.get("/forth/21")
    assert r.status == 200
    assert await r.text() == "/forth/{name}"

    # Fixed/static paths are always preferred over regex paths
    r = await client.get("/forth/42")
    assert r.status == 200
    assert await r.text() == "/forth/42"

    r = await client.get("/fifth/21")
    assert r.status == 200
    assert await r.text() == "/fifth/{name}"

    r = await client.get("/fifth/42")
    assert r.status == 200
    assert await r.text() == "/fifth/42"


async def test_url_with_many_slashes(aiohttp_client: AiohttpClient) -> None:
    app = web.Application()

    class MyView(web.View):
        async def get(self) -> web.Response:
            return web.Response()

    app.router.add_routes([web.view("/a", MyView)])

    client = await aiohttp_client(app)

    r = await client.get("///a")
    assert r.status == 200
    await r.release()


async def test_route_with_regex(aiohttp_client: AiohttpClient) -> None:
    """Test a route with a regex preceded by a fixed string."""
    app = web.Application()

    async def handler(request: web.Request) -> web.Response:
        assert isinstance(request.match_info._route.resource, Resource)
        return web.Response(text=request.match_info._route.resource.canonical)

    app.router.add_get("/core/locations{tail:.*}", handler)
    client = await aiohttp_client(app)

    r = await client.get("/core/locations/tail/here")
    assert r.status == 200
    assert await r.text() == "/core/locations{tail}"

    r = await client.get("/core/locations_tail_here")
    assert r.status == 200
    assert await r.text() == "/core/locations{tail}"

    r = await client.get("/core/locations_tail;id=abcdef")
    assert r.status == 200
    assert await r.text() == "/core/locations{tail}"
