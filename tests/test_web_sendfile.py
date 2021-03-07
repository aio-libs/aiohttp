from typing import Any
from unittest import mock

from aiohttp import hdrs
from aiohttp.test_utils import make_mocked_coro, make_mocked_request
from aiohttp.web_fileresponse import FileResponse


def test_using_gzip_if_header_present_and_file_available(loop: Any) -> None:
    request = make_mocked_request(
        "GET", "http://python.org/logo.png", headers={hdrs.ACCEPT_ENCODING: "gzip"}
    )

    gz_filepath = mock.Mock()
    gz_filepath.open = mock.mock_open()
    gz_filepath.is_file.return_value = True
    gz_filepath.stat.return_value = mock.MagicMock()
    gz_filepath.stat.return_value.st_size = 1024
    gz_filepath.stat.return_value.st_mtime_ns = 1603733507222449291

    filepath = mock.Mock()
    filepath.name = "logo.png"
    filepath.open = mock.mock_open()
    filepath.with_name.return_value = gz_filepath

    file_sender = FileResponse(filepath)
    file_sender._sendfile = make_mocked_coro(None)  # type: ignore[assignment]

    loop.run_until_complete(file_sender.prepare(request))

    assert not filepath.open.called
    assert gz_filepath.open.called


def test_gzip_if_header_not_present_and_file_available(loop: Any) -> None:
    request = make_mocked_request("GET", "http://python.org/logo.png", headers={})

    gz_filepath = mock.Mock()
    gz_filepath.open = mock.mock_open()
    gz_filepath.is_file.return_value = True

    filepath = mock.Mock()
    filepath.name = "logo.png"
    filepath.open = mock.mock_open()
    filepath.with_name.return_value = gz_filepath
    filepath.stat.return_value = mock.MagicMock()
    filepath.stat.return_value.st_size = 1024
    filepath.stat.return_value.st_mtime_ns = 1603733507222449291

    file_sender = FileResponse(filepath)
    file_sender._sendfile = make_mocked_coro(None)  # type: ignore[assignment]

    loop.run_until_complete(file_sender.prepare(request))

    assert filepath.open.called
    assert not gz_filepath.open.called


def test_gzip_if_header_not_present_and_file_not_available(loop: Any) -> None:
    request = make_mocked_request("GET", "http://python.org/logo.png", headers={})

    gz_filepath = mock.Mock()
    gz_filepath.open = mock.mock_open()
    gz_filepath.is_file.return_value = False

    filepath = mock.Mock()
    filepath.name = "logo.png"
    filepath.open = mock.mock_open()
    filepath.with_name.return_value = gz_filepath
    filepath.stat.return_value = mock.MagicMock()
    filepath.stat.return_value.st_size = 1024
    filepath.stat.return_value.st_mtime_ns = 1603733507222449291

    file_sender = FileResponse(filepath)
    file_sender._sendfile = make_mocked_coro(None)  # type: ignore[assignment]

    loop.run_until_complete(file_sender.prepare(request))

    assert filepath.open.called
    assert not gz_filepath.open.called


def test_gzip_if_header_present_and_file_not_available(loop: Any) -> None:
    request = make_mocked_request(
        "GET", "http://python.org/logo.png", headers={hdrs.ACCEPT_ENCODING: "gzip"}
    )

    gz_filepath = mock.Mock()
    gz_filepath.open = mock.mock_open()
    gz_filepath.is_file.return_value = False

    filepath = mock.Mock()
    filepath.name = "logo.png"
    filepath.open = mock.mock_open()
    filepath.with_name.return_value = gz_filepath
    filepath.stat.return_value = mock.MagicMock()
    filepath.stat.return_value.st_size = 1024
    filepath.stat.return_value.st_mtime_ns = 1603733507222449291

    file_sender = FileResponse(filepath)
    file_sender._sendfile = make_mocked_coro(None)  # type: ignore[assignment]

    loop.run_until_complete(file_sender.prepare(request))

    assert filepath.open.called
    assert not gz_filepath.open.called


def test_status_controlled_by_user(loop: Any) -> None:
    request = make_mocked_request("GET", "http://python.org/logo.png", headers={})

    filepath = mock.Mock()
    filepath.name = "logo.png"
    filepath.open = mock.mock_open()
    filepath.stat.return_value = mock.MagicMock()
    filepath.stat.return_value.st_size = 1024
    filepath.stat.return_value.st_mtime_ns = 1603733507222449291

    file_sender = FileResponse(filepath, status=203)
    file_sender._sendfile = make_mocked_coro(None)  # type: ignore[assignment]

    loop.run_until_complete(file_sender.prepare(request))

    assert file_sender._status == 203
