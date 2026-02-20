import asyncio
import io
from pathlib import Path
from stat import S_IFREG, S_IRUSR, S_IWUSR
from unittest import mock

from aiohttp import hdrs
from aiohttp.http_writer import StreamWriter
from aiohttp.test_utils import make_mocked_request
from aiohttp.web_fileresponse import FileResponse

MOCK_MODE = S_IFREG | S_IRUSR | S_IWUSR


def test_using_gzip_if_header_present_and_file_available(
    loop: asyncio.AbstractEventLoop,
) -> None:
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
    file_sender._sendfile = mock.AsyncMock(return_value=None)  # type: ignore[method-assign]

    loop.run_until_complete(file_sender.prepare(request))

    assert not filepath.open.called
    assert gz_filepath.open.called


def test_gzip_if_header_not_present_and_file_available(
    loop: asyncio.AbstractEventLoop,
) -> None:
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
    file_sender._sendfile = mock.AsyncMock(return_value=None)  # type: ignore[method-assign]

    loop.run_until_complete(file_sender.prepare(request))

    assert filepath.open.called
    assert not gz_filepath.open.called


def test_gzip_if_header_not_present_and_file_not_available(
    loop: asyncio.AbstractEventLoop,
) -> None:
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
    file_sender._sendfile = mock.AsyncMock(return_value=None)  # type: ignore[method-assign]

    loop.run_until_complete(file_sender.prepare(request))

    assert filepath.open.called
    assert not gz_filepath.open.called


def test_gzip_if_header_present_and_file_not_available(
    loop: asyncio.AbstractEventLoop,
) -> None:
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
    file_sender._sendfile = mock.AsyncMock(return_value=None)  # type: ignore[method-assign]

    loop.run_until_complete(file_sender.prepare(request))

    assert filepath.open.called
    assert not gz_filepath.open.called


def test_status_controlled_by_user(loop: asyncio.AbstractEventLoop) -> None:
    request = make_mocked_request("GET", "http://python.org/logo.png", headers={})

    filepath = mock.create_autospec(Path, spec_set=True)
    filepath.name = "logo.png"
    filepath.stat.return_value.st_size = 1024
    filepath.stat.return_value.st_mtime_ns = 1603733507222449291
    filepath.stat.return_value.st_mode = MOCK_MODE

    file_sender = FileResponse(filepath, status=203)
    file_sender._path = filepath
    file_sender._sendfile = mock.AsyncMock(return_value=None)  # type: ignore[method-assign]

    loop.run_until_complete(file_sender.prepare(request))

    assert file_sender._status == 203


async def test_file_response_sends_headers_immediately() -> None:
    """Test that FileResponse sends headers immediately (inherits from StreamResponse)."""
    writer = mock.create_autospec(StreamWriter, spec_set=True, instance=True)

    request = make_mocked_request("GET", "http://python.org/logo.png", writer=writer)

    filepath = mock.create_autospec(Path, spec_set=True)
    filepath.name = "logo.png"
    filepath.stat.return_value.st_size = 1024
    filepath.stat.return_value.st_mtime_ns = 1603733507222449291
    filepath.stat.return_value.st_mode = MOCK_MODE

    file_sender = FileResponse(filepath)
    file_sender._path = filepath
    file_sender._sendfile = mock.AsyncMock(return_value=None)  # type: ignore[method-assign]

    # FileResponse inherits from StreamResponse, so should send immediately
    assert file_sender._send_headers_immediately is True

    # Prepare the response
    await file_sender.prepare(request)

    # Headers should be sent immediately
    writer.send_headers.assert_called_once()


async def test_sendfile_fallback_respects_count_boundary() -> None:
    """Regression test: _sendfile_fallback should not read beyond the requested count.

    Previously the first chunk used the full chunk_size even when count was smaller,
    and the loop subtracted chunk_size instead of the actual bytes read.  Both bugs
    could cause extra data to be sent when serving range requests.
    """
    file_data = b"A" * 100 + b"B" * 50  # 150 bytes total
    fobj = io.BytesIO(file_data)

    writer = mock.AsyncMock()
    written = bytearray()

    async def capture_write(data: bytes) -> None:
        written.extend(data)

    writer.write = capture_write
    writer.drain = mock.AsyncMock()

    file_sender = FileResponse("dummy.bin")
    file_sender._chunk_size = 64  # smaller than count to test multi-chunk

    # Request only the first 100 bytes (offset=0, count=100)
    await file_sender._sendfile_fallback(writer, fobj, offset=0, count=100)

    assert bytes(written) == b"A" * 100
    assert len(written) == 100
