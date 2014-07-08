"""Tests for errors.py"""

import unittest
import unittest.mock

import aiohttp


class ErrorsTests(unittest.TestCase):

    def test_incomplete(self):
        err = aiohttp.IncompleteRead(10, 4)
        self.assertEqual(
            str(err), 'IncompleteRead(10 bytes read, 4 more expected)')

        err = aiohttp.IncompleteRead(10)
        self.assertEqual(
            str(err), 'IncompleteRead(10 bytes read)')

    def test_bad_status_line(self):
        err = aiohttp.BadStatusLine(b'')
        self.assertEqual(str(err), "b''")

        err = aiohttp.BadStatusLine('Test')
        self.assertEqual(str(err), 'Test')
