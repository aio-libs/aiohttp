from pathlib import Path
from stat import S_IFREG, S_IRUSR, S_IWUSR
from unittest import mock

from aiohttp import hdrs
from aiohttp.test_utils import make_mocked_coro, make_mocked_request
from aiohttp.web_fileresponse import FileResponse

MOCK_MODE = S_IFREG | S_IRUSR | S_IWUSR


def test_using_gzip_if_header_present_and_file_available(loop) -> None:
    request = make_mocked_request(
        "GET",
        "http://python.org/logo.png",
        # Header uses some uppercase to ensure case-insensitive treatment
        headers={hdrs.ACCEPT_ENCODING: "GZip"},
    )

    gz_filepath = mock.create_autospec(Path, spec_set=True)
    gz_filepath.lstat.return_value.st_size = 1024
    gz_filepath.lstat.return_value.st_mtime_ns = 1603733507222449291
    gz_filepath.lstat.return_value.st_mode = MOCK_MODE

    filepath = mock.create_autospec(Path, spec_set=True)
    filepath.name = "logo.png"
    filepath.with_suffix.return_value = gz_filepath

    file_sender = FileResponse(filepath)
    file_sender._path = filepath
    file_sender._sendfile = make_mocked_coro(None)  # type: ignore[assignment]

    loop.run_until_complete(file_sender.prepare(request))

    assert not filepath.open.called
    assert gz_filepath.open.called


def test_gzip_if_header_not_present_and_file_available(loop) -> None:
    request = make_mocked_request("GET", "http://python.org/logo.png", headers={})

    gz_filepath = mock.create_autospec(Path, spec_set=True)
    gz_filepath.lstat.return_value.st_size = 1024
    gz_filepath.lstat.return_value.st_mtime_ns = 1603733507222449291
    gz_filepath.lstat.return_value.st_mode = MOCK_MODE

    filepath = mock.create_autospec(Path, spec_set=True)
    filepath.name = "logo.png"
    filepath.with_suffix.return_value = gz_filepath
    filepath.stat.return_value.st_size = 1024
    filepath.stat.return_value.st_mtime_ns = 1603733507222449291
    filepath.stat.return_value.st_mode = MOCK_MODE

    file_sender = FileResponse(filepath)
    file_sender._path = filepath
    file_sender._sendfile = make_mocked_coro(None)  # type: ignore[assignment]

    loop.run_until_complete(file_sender.prepare(request))

    assert filepath.open.called
    assert not gz_filepath.open.called


def test_gzip_if_header_not_present_and_file_not_available(loop) -> None:
    request = make_mocked_request("GET", "http://python.org/logo.png", headers={})

    gz_filepath = mock.create_autospec(Path, spec_set=True)
    gz_filepath.stat.side_effect = OSError(2, "No such file or directory")

    filepath = mock.create_autospec(Path, spec_set=True)
    filepath.name = "logo.png"
    filepath.with_suffix.return_value = gz_filepath
    filepath.stat.return_value.st_size = 1024
    filepath.stat.return_value.st_mtime_ns = 1603733507222449291
    filepath.stat.return_value.st_mode = MOCK_MODE

    file_sender = FileResponse(filepath)
    file_sender._path = filepath
    file_sender._sendfile = make_mocked_coro(None)  # type: ignore[assignment]

    loop.run_until_complete(file_sender.prepare(request))

    assert filepath.open.called
    assert not gz_filepath.open.called


def test_gzip_if_header_present_and_file_not_available(loop) -> None:
    request = make_mocked_request(
        "GET", "http://python.org/logo.png", headers={hdrs.ACCEPT_ENCODING: "gzip"}
    )

    gz_filepath = mock.create_autospec(Path, spec_set=True)
    gz_filepath.lstat.side_effect = OSError(2, "No such file or directory")

    filepath = mock.create_autospec(Path, spec_set=True)
    filepath.name = "logo.png"
    filepath.with_suffix.return_value = gz_filepath
    filepath.stat.return_value.st_size = 1024
    filepath.stat.return_value.st_mtime_ns = 1603733507222449291
    filepath.stat.return_value.st_mode = MOCK_MODE

    file_sender = FileResponse(filepath)
    file_sender._path = filepath
    file_sender._sendfile = make_mocked_coro(None)  # type: ignore[assignment]

    loop.run_until_complete(file_sender.prepare(request))

    assert filepath.open.called
    assert not gz_filepath.open.called


def test_status_controlled_by_user(loop) -> None:
    request = make_mocked_request("GET", "http://python.org/logo.png", headers={})

    filepath = mock.create_autospec(Path, spec_set=True)
    filepath.name = "logo.png"
    filepath.stat.return_value.st_size = 1024
    filepath.stat.return_value.st_mtime_ns = 1603733507222449291
    filepath.stat.return_value.st_mode = MOCK_MODE

    file_sender = FileResponse(filepath, status=203)
    file_sender._path = filepath
    file_sender._sendfile = make_mocked_coro(None)  # type: ignore[assignment]

    loop.run_until_complete(file_sender.prepare(request))

    assert file_sender._status == 203
