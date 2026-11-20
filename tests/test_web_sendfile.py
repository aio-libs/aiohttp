import asyncio
import io
import ssl
from pathlib import Path
from stat import S_IFREG, S_IRUSR, S_IWUSR
from unittest import mock

import pytest

from aiohttp import hdrs
from aiohttp.http_writer import StreamWriter
from aiohttp.test_utils import make_mocked_request
from aiohttp.web_fileresponse import FileResponse

try:
    import aiofastnet
except ImportError:
    aiofastnet = None  # type: ignore[assignment]

MOCK_MODE = S_IFREG | S_IRUSR | S_IWUSR


def test_using_gzip_if_header_present_and_file_available(
    event_loop: asyncio.AbstractEventLoop,
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

    event_loop.run_until_complete(file_sender.prepare(request))

    assert not filepath.open.called
    assert gz_filepath.open.called


def test_gzip_if_header_not_present_and_file_available(
    event_loop: asyncio.AbstractEventLoop,
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

    event_loop.run_until_complete(file_sender.prepare(request))

    assert filepath.open.called
    assert not gz_filepath.open.called


def test_gzip_if_header_not_present_and_file_not_available(
    event_loop: asyncio.AbstractEventLoop,
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

    event_loop.run_until_complete(file_sender.prepare(request))

    assert filepath.open.called
    assert not gz_filepath.open.called


def test_gzip_if_header_present_and_file_not_available(
    event_loop: asyncio.AbstractEventLoop,
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

    event_loop.run_until_complete(file_sender.prepare(request))

    assert filepath.open.called
    assert not gz_filepath.open.called


def test_status_controlled_by_user(event_loop: asyncio.AbstractEventLoop) -> None:
    request = make_mocked_request("GET", "http://python.org/logo.png", headers={})

    filepath = mock.create_autospec(Path, spec_set=True)
    filepath.name = "logo.png"
    filepath.stat.return_value.st_size = 1024
    filepath.stat.return_value.st_mtime_ns = 1603733507222449291
    filepath.stat.return_value.st_mode = MOCK_MODE

    file_sender = FileResponse(filepath, status=203)
    file_sender._path = filepath
    file_sender._sendfile = mock.AsyncMock(return_value=None)  # type: ignore[method-assign]

    event_loop.run_until_complete(file_sender.prepare(request))

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

    # FileResponse inherits from StreamResponse, so should send immediately
    assert file_sender._send_headers_immediately is True

    # Mock the actual transfer but let _sendfile call super().prepare() to write headers
    with (
        mock.patch.object(
            file_sender, "_sendfile_fallback", autospec=True, spec_set=True
        ) as sendfile_fallback,
        mock.patch("aiohttp.web_fileresponse.NOSENDFILE", True),
    ):
        sendfile_fallback.return_value = writer
        await file_sender.prepare(request)

    # Headers should be sent immediately
    writer.send_headers.assert_called_once()


@pytest.fixture
def regular_file(tmp_path: Path) -> Path:
    filepath = tmp_path / "logo.png"
    filepath.write_bytes(b"x" * 1024)
    return filepath


async def test_sendfile_tls_uses_own_fallback(regular_file: Path) -> None:
    """Test loop.sendfile() is bypassed for TLS transports.

    asyncio does not raise NotImplementedError for TLS transports, it uses
    its own much slower fallback instead.
    """
    writer = mock.create_autospec(StreamWriter, spec_set=True, instance=True)
    request = make_mocked_request(
        "GET",
        "http://python.org/logo.png",
        writer=writer,
        sslcontext=mock.create_autospec(ssl.SSLContext, instance=True),
    )
    file_sender = FileResponse(regular_file)

    with (
        mock.patch.object(
            file_sender, "_sendfile_fallback", autospec=True, spec_set=True
        ) as sendfile_fallback,
        mock.patch.object(
            request._loop, "sendfile", autospec=True, spec_set=True
        ) as loop_sendfile,
        mock.patch("aiohttp.web_fileresponse.aiofastnet", None),
    ):
        sendfile_fallback.return_value = writer
        await file_sender.prepare(request)

    sendfile_fallback.assert_called_once()
    assert sendfile_fallback.call_args.args[2:] == (0, 1024)
    loop_sendfile.assert_not_called()


async def test_sendfile_without_tls_uses_loop_sendfile(regular_file: Path) -> None:
    """Test loop.sendfile() is still used for transports without TLS."""
    writer = mock.create_autospec(StreamWriter, spec_set=True, instance=True)
    request = make_mocked_request("GET", "http://python.org/logo.png", writer=writer)
    file_sender = FileResponse(regular_file)

    with (
        mock.patch.object(
            file_sender, "_sendfile_fallback", autospec=True, spec_set=True
        ) as sendfile_fallback,
        mock.patch.object(
            request._loop, "sendfile", autospec=True, spec_set=True
        ) as loop_sendfile,
        mock.patch("aiohttp.web_fileresponse.aiofastnet", None),
    ):
        await file_sender.prepare(request)

    loop_sendfile.assert_called_once()
    assert loop_sendfile.call_args.args[0] is request.transport
    assert loop_sendfile.call_args.args[2:] == (0, 1024)
    sendfile_fallback.assert_not_called()


@pytest.mark.skipif(aiofastnet is None, reason="aiofastnet not installed")
async def test_sendfile_tls_aiofastnet_transport_uses_aiofastnet(
    regular_file: Path,
) -> None:
    """Test aiofastnet transports with TLS still try native sendfile."""
    writer = mock.create_autospec(StreamWriter, spec_set=True, instance=True)
    transport = mock.Mock(spec=aiofastnet.Transport)
    transport.get_extra_info.return_value = mock.create_autospec(
        ssl.SSLContext, instance=True
    )
    request = make_mocked_request(
        "GET", "http://python.org/logo.png", writer=writer, transport=transport
    )
    file_sender = FileResponse(regular_file)

    with (
        mock.patch.object(
            file_sender, "_sendfile_fallback", autospec=True, spec_set=True
        ) as sendfile_fallback,
        mock.patch.object(
            aiofastnet, "sendfile", autospec=True, spec_set=True
        ) as aiofastnet_sendfile,
    ):
        await file_sender.prepare(request)

    aiofastnet_sendfile.assert_called_once()
    assert aiofastnet_sendfile.call_args.args[1] is transport
    sendfile_fallback.assert_not_called()


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
