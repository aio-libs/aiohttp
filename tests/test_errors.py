"""Tests for errors.py"""

import unittest
import unittest.mock

import aiohttp


class TestErrors(unittest.TestCase):

    def test_bad_status_line(self):
        err = aiohttp.BadStatusLine(b'')
        self.assertEqual(str(err), "b''")

        err = aiohttp.BadStatusLine('Test')
        self.assertEqual(str(err), 'Test')
