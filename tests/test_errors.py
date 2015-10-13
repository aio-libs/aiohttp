"""Tests for errors.py"""

import aiohttp


def test_bad_status_line1():
    err = aiohttp.BadStatusLine(b'')
    assert str(err) == "b''"


def test_bad_status_line2():
    err = aiohttp.BadStatusLine('Test')
    assert str(err) == 'Test'
