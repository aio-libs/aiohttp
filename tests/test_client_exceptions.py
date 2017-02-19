"""Tests for http_exceptions.py"""

from aiohttp import client


def test_fingerprint_mismatch():
    err = client.ServerFingerprintMismatch('exp', 'got', 'host', 8888)
    expected = ('<ServerFingerprintMismatch expected=exp'
                ' got=got host=host port=8888>')
    assert expected == repr(err)
