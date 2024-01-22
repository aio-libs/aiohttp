from io import BytesIO
from os import stat_result
from pathlib import Path
from typing import Any
from unittest import mock

from aiohttp import hdrs
from aiohttp.test_utils import make_mocked_coro, make_mocked_request
from aiohttp.web_fileresponse import FileResponse


def test_using_gzip_if_header_present_and_file_available(loop: Any) -> None:
    request = make_mocked_request(
        "GET", "http://python.org/logo.png", headers={hdrs.ACCEPT_ENCODING: "gzip"}
    )

    gz_filepath = mock.create_autospec(Path, spec_set=True)
    gz_filepath.stat.return_value.st_size = 1024
    gz_filepath.stat.return_value.st_mtime_ns = 1603733507222449291

    filepath = mock.create_autospec(Path, spec_set=True)
    filepath.name = "logo.png"
    filepath.with_name.return_value = gz_filepath

    file_sender = FileResponse(filepath)
    file_sender._path = filepath
    file_sender._sendfile = make_mocked_coro(None)  # type: ignore[method-assign]

    loop.run_until_complete(file_sender.prepare(request))

    assert not filepath.open.called
    assert gz_filepath.open.called


def test_gzip_if_header_not_present_and_file_available(loop: Any) -> None:
    request = make_mocked_request("GET", "http://python.org/logo.png", headers={})

    gz_filepath = mock.create_autospec(Path, spec_set=True)
    gz_filepath.stat.return_value.st_size = 1024
    gz_filepath.stat.return_value.st_mtime_ns = 1603733507222449291

    filepath = mock.create_autospec(Path, spec_set=True)
    filepath.name = "logo.png"
    filepath.with_name.return_value = gz_filepath
    filepath.stat.return_value.st_size = 1024
    filepath.stat.return_value.st_mtime_ns = 1603733507222449291

    file_sender = FileResponse(filepath)
    file_sender._path = filepath
    file_sender._sendfile = make_mocked_coro(None)  # type: ignore[method-assign]

    loop.run_until_complete(file_sender.prepare(request))

    assert filepath.open.called
    assert not gz_filepath.open.called


def test_gzip_if_header_not_present_and_file_not_available(loop: Any) -> None:
    request = make_mocked_request("GET", "http://python.org/logo.png", headers={})

    gz_filepath = mock.create_autospec(Path, spec_set=True)
    gz_filepath.stat.side_effect = OSError(2, "No such file or directory")

    filepath = mock.create_autospec(Path, spec_set=True)
    filepath.name = "logo.png"
    filepath.with_name.return_value = gz_filepath
    filepath.stat.return_value.st_size = 1024
    filepath.stat.return_value.st_mtime_ns = 1603733507222449291

    file_sender = FileResponse(filepath)
    file_sender._path = filepath
    file_sender._sendfile = make_mocked_coro(None)  # type: ignore[method-assign]

    loop.run_until_complete(file_sender.prepare(request))

    assert filepath.open.called
    assert not gz_filepath.open.called


def test_gzip_if_header_present_and_file_not_available(loop: Any) -> None:
    request = make_mocked_request(
        "GET", "http://python.org/logo.png", headers={hdrs.ACCEPT_ENCODING: "gzip"}
    )

    gz_filepath = mock.create_autospec(Path, spec_set=True)
    gz_filepath.stat.side_effect = OSError(2, "No such file or directory")

    filepath = mock.create_autospec(Path, spec_set=True)
    filepath.name = "logo.png"
    filepath.with_name.return_value = gz_filepath
    filepath.stat.return_value.st_size = 1024
    filepath.stat.return_value.st_mtime_ns = 1603733507222449291

    file_sender = FileResponse(filepath)
    file_sender._path = filepath
    file_sender._sendfile = make_mocked_coro(None)  # type: ignore[method-assign]

    loop.run_until_complete(file_sender.prepare(request))

    assert filepath.open.called
    assert not gz_filepath.open.called


def test_status_controlled_by_user(loop: Any) -> None:
    request = make_mocked_request("GET", "http://python.org/logo.png", headers={})

    filepath = mock.create_autospec(Path, spec_set=True)
    filepath.name = "logo.png"
    filepath.stat.return_value.st_size = 1024
    filepath.stat.return_value.st_mtime_ns = 1603733507222449291

    file_sender = FileResponse(filepath, status=203)
    file_sender._path = filepath
    file_sender._sendfile = make_mocked_coro(None)  # type: ignore[method-assign]

    loop.run_until_complete(file_sender.prepare(request))

    assert file_sender._status == 203


def test_custom_path(loop: Any) -> None:
    request = make_mocked_request("GET", "http://python.org/hello")

    # ZipFile has no with_name and stat
    # file = BytesIO()
    # zipfile = ZipFile(file, "w")
    # zipfile.writestr("hello", "world")
    # filepath = ZipPath(zipfile)

    class MyPath:
        name = "hello"
        content = b"world"

        def open(self, mode: str, *args, **kwargs):
            return BytesIO(self.content)

        def stat(self, **_):
            ts = 1701435976
            return stat_result(
                (
                    0o444,
                    -1,
                    -1,
                    1,
                    0,
                    0,
                    len(self.content),
                    ts,
                    ts,
                    ts,
                    ts,
                    ts,
                    ts,
                    ts * 1000000000,
                    ts * 1000000000,
                    ts * 1000000000,
                )
            )

        def with_name(self, name):
            return NoPath()

    class NoPath:
        def is_file(self):
            return False

    filepath = MyPath()
    file_sender = FileResponse(filepath)
    file_sender._sendfile = make_mocked_coro(None)  # type: ignore[method-assign]

    loop.run_until_complete(file_sender.prepare(request))
