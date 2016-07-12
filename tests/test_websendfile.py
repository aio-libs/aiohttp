import asyncio
import os
import unittest
from unittest import mock
from aiohttp import helpers
from aiohttp.web import UrlDispatcher
from aiohttp.file_sender import FileSender


class TestWebSendFile(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.router = UrlDispatcher()

    def tearDown(self):
        self.loop.close()

    def test_env_nosendfile(self):
        with mock.patch.dict(os.environ, {'AIOHTTP_NOSENDFILE': '1'}):
            file_sender = FileSender()
            self.assertEqual(file_sender._sendfile,
                             file_sender._sendfile_fallback)

    def test_static_handle_eof(self):
        loop = mock.Mock()
        with mock.patch('aiohttp.file_sender.os') as m_os:
            out_fd = 30
            in_fd = 31
            fut = helpers.create_future(self.loop)
            m_os.sendfile.return_value = 0
            file_sender = FileSender()
            file_sender._sendfile_cb(fut, out_fd, in_fd, 0, 100, loop, False)
            m_os.sendfile.assert_called_with(out_fd, in_fd, 0, 100)
            self.assertTrue(fut.done())
            self.assertIsNone(fut.result())
            self.assertFalse(loop.add_writer.called)
            self.assertFalse(loop.remove_writer.called)

    def test_static_handle_again(self):
        loop = mock.Mock()
        with mock.patch('aiohttp.file_sender.os') as m_os:
            out_fd = 30
            in_fd = 31
            fut = helpers.create_future(self.loop)
            m_os.sendfile.side_effect = BlockingIOError()
            file_sender = FileSender()
            file_sender._sendfile_cb(fut, out_fd, in_fd, 0, 100, loop, False)
            m_os.sendfile.assert_called_with(out_fd, in_fd, 0, 100)
            self.assertFalse(fut.done())
            loop.add_writer.assert_called_with(out_fd,
                                               file_sender._sendfile_cb,
                                               fut, out_fd, in_fd, 0, 100,
                                               loop, True)
            self.assertFalse(loop.remove_writer.called)

    def test_static_handle_exception(self):
        loop = mock.Mock()
        with mock.patch('aiohttp.file_sender.os') as m_os:
            out_fd = 30
            in_fd = 31
            fut = helpers.create_future(self.loop)
            exc = OSError()
            m_os.sendfile.side_effect = exc
            file_sender = FileSender()
            file_sender._sendfile_cb(fut, out_fd, in_fd, 0, 100, loop, False)
            m_os.sendfile.assert_called_with(out_fd, in_fd, 0, 100)
            self.assertTrue(fut.done())
            self.assertIs(exc, fut.exception())
            self.assertFalse(loop.add_writer.called)
            self.assertFalse(loop.remove_writer.called)
