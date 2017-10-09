"""Tests for http_exceptions.py"""

from yarl import URL

from aiohttp import client


def test_fingerprint_mismatch():
    err = client.ServerFingerprintMismatch('exp', 'got', 'host', 8888)
    expected = ('<ServerFingerprintMismatch expected=exp'
                ' got=got host=host port=8888>')
    assert expected == repr(err)


def test_invalid_url():
    url = URL('http://example.com')
    err = client.InvalidURL(url)
    assert err.args[0] is url
    assert err.url is url
    assert repr(err) == "<InvalidURL http://example.com>"
