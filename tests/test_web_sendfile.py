import os
from unittest import mock

from yarl import URL

from aiohttp import hdrs, helpers
from aiohttp.file_sender import FileSender
from aiohttp.test_utils import make_mocked_coro, make_mocked_request


def test_env_nosendfile():
    with mock.patch.dict(os.environ, {'AIOHTTP_NOSENDFILE': '1'}):
        file_sender = FileSender()
        assert file_sender._sendfile == file_sender._sendfile_fallback


def test_static_handle_eof(loop):
    fake_loop = mock.Mock()
    with mock.patch('aiohttp.file_sender.os') as m_os:
        out_fd = 30
        in_fd = 31
        fut = helpers.create_future(loop)
        m_os.sendfile.return_value = 0
        file_sender = FileSender()
        file_sender._sendfile_cb(fut, out_fd, in_fd, 0, 100, fake_loop, False)
        m_os.sendfile.assert_called_with(out_fd, in_fd, 0, 100)
        assert fut.done()
        assert fut.result() is None
        assert not fake_loop.add_writer.called
        assert not fake_loop.remove_writer.called


def test_static_handle_again(loop):
    fake_loop = mock.Mock()
    with mock.patch('aiohttp.file_sender.os') as m_os:
        out_fd = 30
        in_fd = 31
        fut = helpers.create_future(loop)
        m_os.sendfile.side_effect = BlockingIOError()
        file_sender = FileSender()
        file_sender._sendfile_cb(fut, out_fd, in_fd, 0, 100, fake_loop, False)
        m_os.sendfile.assert_called_with(out_fd, in_fd, 0, 100)
        assert not fut.done()
        fake_loop.add_writer.assert_called_with(out_fd,
                                                file_sender._sendfile_cb,
                                                fut, out_fd, in_fd, 0, 100,
                                                fake_loop, True)
        assert not fake_loop.remove_writer.called


def test_static_handle_exception(loop):
    fake_loop = mock.Mock()
    with mock.patch('aiohttp.file_sender.os') as m_os:
        out_fd = 30
        in_fd = 31
        fut = helpers.create_future(loop)
        exc = OSError()
        m_os.sendfile.side_effect = exc
        file_sender = FileSender()
        file_sender._sendfile_cb(fut, out_fd, in_fd, 0, 100, fake_loop, False)
        m_os.sendfile.assert_called_with(out_fd, in_fd, 0, 100)
        assert fut.done()
        assert exc is fut.exception()
        assert not fake_loop.add_writer.called
        assert not fake_loop.remove_writer.called


def test__sendfile_cb_return_on_cancelling(loop):
    fake_loop = mock.Mock()
    with mock.patch('aiohttp.file_sender.os') as m_os:
        out_fd = 30
        in_fd = 31
        fut = helpers.create_future(loop)
        fut.cancel()
        file_sender = FileSender()
        file_sender._sendfile_cb(fut, out_fd, in_fd, 0, 100, fake_loop, False)
        assert fut.done()
        assert not fake_loop.add_writer.called
        assert not fake_loop.remove_writer.called
        assert not m_os.sendfile.called


def test_using_gzip_if_header_present_and_file_available(loop):
    request = make_mocked_request(
        'GET', URL('http://python.org/logo.png'), headers={
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

    file_sender = FileSender()
    file_sender._sendfile = make_mocked_coro(None)

    loop.run_until_complete(file_sender.send(request, filepath))

    assert not filepath.open.called
    assert gz_filepath.open.called


def test_gzip_if_header_not_present_and_file_available(loop):
    request = make_mocked_request(
        'GET', URL('http://python.org/logo.png'), headers={
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

    file_sender = FileSender()
    file_sender._sendfile = make_mocked_coro(None)

    loop.run_until_complete(file_sender.send(request, filepath))

    assert filepath.open.called
    assert not gz_filepath.open.called


def test_gzip_if_header_not_present_and_file_not_available(loop):
    request = make_mocked_request(
        'GET', URL('http://python.org/logo.png'), headers={
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

    file_sender = FileSender()
    file_sender._sendfile = make_mocked_coro(None)

    loop.run_until_complete(file_sender.send(request, filepath))

    assert filepath.open.called
    assert not gz_filepath.open.called


def test_gzip_if_header_present_and_file_not_available(loop):
    request = make_mocked_request(
        'GET', URL('http://python.org/logo.png'), headers={
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

    file_sender = FileSender()
    file_sender._sendfile = make_mocked_coro(None)

    loop.run_until_complete(file_sender.send(request, filepath))

    assert filepath.open.called
    assert not gz_filepath.open.called
