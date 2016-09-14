import os
from unittest import mock

from aiohttp import helpers
from aiohttp.file_sender import FileSender


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
