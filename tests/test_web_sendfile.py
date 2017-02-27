from unittest import mock

from aiohttp import hdrs, helpers
from aiohttp.test_utils import make_mocked_coro, make_mocked_request
from aiohttp.web_fileresponse import FileResponse, SendfilePayloadWriter


def test_static_handle_eof(loop):
    fake_loop = mock.Mock()
    with mock.patch('aiohttp.web_fileresponse.os') as m_os:
        out_fd = 30
        in_fd = 31
        fut = helpers.create_future(loop)
        m_os.sendfile.return_value = 0
        writer = SendfilePayloadWriter(fake_loop, mock.Mock())
        writer._sendfile_cb(fut, out_fd, in_fd, 0, 100, fake_loop, False)
        m_os.sendfile.assert_called_with(out_fd, in_fd, 0, 100)
        assert fut.done()
        assert fut.result() is None
        assert not fake_loop.add_writer.called
        assert not fake_loop.remove_writer.called


def test_static_handle_again(loop):
    fake_loop = mock.Mock()
    with mock.patch('aiohttp.web_fileresponse.os') as m_os:
        out_fd = 30
        in_fd = 31
        fut = helpers.create_future(loop)
        m_os.sendfile.side_effect = BlockingIOError()
        writer = SendfilePayloadWriter(fake_loop, mock.Mock())
        writer._sendfile_cb(fut, out_fd, in_fd, 0, 100, fake_loop, False)
        m_os.sendfile.assert_called_with(out_fd, in_fd, 0, 100)
        assert not fut.done()
        fake_loop.add_writer.assert_called_with(out_fd,
                                                writer._sendfile_cb,
                                                fut, out_fd, in_fd, 0, 100,
                                                fake_loop, True)
        assert not fake_loop.remove_writer.called


def test_static_handle_exception(loop):
    fake_loop = mock.Mock()
    with mock.patch('aiohttp.web_fileresponse.os') as m_os:
        out_fd = 30
        in_fd = 31
        fut = helpers.create_future(loop)
        exc = OSError()
        m_os.sendfile.side_effect = exc
        writer = SendfilePayloadWriter(fake_loop, mock.Mock())
        writer._sendfile_cb(fut, out_fd, in_fd, 0, 100, fake_loop, False)
        m_os.sendfile.assert_called_with(out_fd, in_fd, 0, 100)
        assert fut.done()
        assert exc is fut.exception()
        assert not fake_loop.add_writer.called
        assert not fake_loop.remove_writer.called


def test__sendfile_cb_return_on_cancelling(loop):
    fake_loop = mock.Mock()
    with mock.patch('aiohttp.web_fileresponse.os') as m_os:
        out_fd = 30
        in_fd = 31
        fut = helpers.create_future(loop)
        fut.cancel()
        writer = SendfilePayloadWriter(fake_loop, mock.Mock())
        writer._sendfile_cb(fut, out_fd, in_fd, 0, 100, fake_loop, False)
        assert fut.done()
        assert not fake_loop.add_writer.called
        assert not fake_loop.remove_writer.called
        assert not m_os.sendfile.called


def test_using_gzip_if_header_present_and_file_available(loop):
    request = make_mocked_request(
        'GET', 'http://python.org/logo.png', headers={
            hdrs.ACCEPT_ENCODING: 'gzip'
        }
    )

    gz_filepath = mock.Mock()
    gz_filepath.open = mock.mock_open()
    gz_filepath.is_file.return_value = True
    gz_filepath.stat.return_value = mock.MagicMock()
    gz_filepath.stat.st_size = 1024

    filepath = mock.Mock()
    filepath.name = 'logo.png'
    filepath.open = mock.mock_open()
    filepath.with_name.return_value = gz_filepath

    file_sender = FileResponse(filepath)
    file_sender._sendfile = make_mocked_coro(None)

    loop.run_until_complete(file_sender.prepare(request))

    assert not filepath.open.called
    assert gz_filepath.open.called


def test_gzip_if_header_not_present_and_file_available(loop):
    request = make_mocked_request(
        'GET', 'http://python.org/logo.png', headers={
        }
    )

    gz_filepath = mock.Mock()
    gz_filepath.open = mock.mock_open()
    gz_filepath.is_file.return_value = True

    filepath = mock.Mock()
    filepath.name = 'logo.png'
    filepath.open = mock.mock_open()
    filepath.with_name.return_value = gz_filepath
    filepath.stat.return_value = mock.MagicMock()
    filepath.stat.st_size = 1024

    file_sender = FileResponse(filepath)
    file_sender._sendfile = make_mocked_coro(None)

    loop.run_until_complete(file_sender.prepare(request))

    assert filepath.open.called
    assert not gz_filepath.open.called


def test_gzip_if_header_not_present_and_file_not_available(loop):
    request = make_mocked_request(
        'GET', 'http://python.org/logo.png', headers={
        }
    )

    gz_filepath = mock.Mock()
    gz_filepath.open = mock.mock_open()
    gz_filepath.is_file.return_value = False

    filepath = mock.Mock()
    filepath.name = 'logo.png'
    filepath.open = mock.mock_open()
    filepath.with_name.return_value = gz_filepath
    filepath.stat.return_value = mock.MagicMock()
    filepath.stat.st_size = 1024

    file_sender = FileResponse(filepath)
    file_sender._sendfile = make_mocked_coro(None)

    loop.run_until_complete(file_sender.prepare(request))

    assert filepath.open.called
    assert not gz_filepath.open.called


def test_gzip_if_header_present_and_file_not_available(loop):
    request = make_mocked_request(
        'GET', 'http://python.org/logo.png', headers={
            hdrs.ACCEPT_ENCODING: 'gzip'
        }
    )

    gz_filepath = mock.Mock()
    gz_filepath.open = mock.mock_open()
    gz_filepath.is_file.return_value = False

    filepath = mock.Mock()
    filepath.name = 'logo.png'
    filepath.open = mock.mock_open()
    filepath.with_name.return_value = gz_filepath
    filepath.stat.return_value = mock.MagicMock()
    filepath.stat.st_size = 1024

    file_sender = FileResponse(filepath)
    file_sender._sendfile = make_mocked_coro(None)

    loop.run_until_complete(file_sender.prepare(request))

    assert filepath.open.called
    assert not gz_filepath.open.called
