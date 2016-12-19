"""Tests for errors.py"""

import aiohttp


def test_bad_status_line1():
    err = aiohttp.BadStatusLine(b'')
    assert str(err) == "b''"


def test_bad_status_line2():
    err = aiohttp.BadStatusLine('Test')
    assert str(err) == 'Test'


def test_fingerprint_mismatch():
    err = aiohttp.FingerprintMismatch('exp', 'got', 'host', 8888)
    expected = '<FingerprintMismatch expected=exp got=got host=host port=8888>'
    assert expected == repr(err)
