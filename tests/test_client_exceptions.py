"""Tests for http_exceptions.py"""

from aiohttp import errors


def test_fingerprint_mismatch():
    err = errors.FingerprintMismatch('exp', 'got', 'host', 8888)
    expected = '<FingerprintMismatch expected=exp got=got host=host port=8888>'
    assert expected == repr(err)
