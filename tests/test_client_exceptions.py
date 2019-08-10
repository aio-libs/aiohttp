"""Tests for client_exceptions.py"""

from unittest import mock

import pytest
from yarl import URL

from aiohttp import client


def test_fingerprint_mismatch() -> None:
    err = client.ServerFingerprintMismatch('exp', 'got', 'host', 8888)
    expected = ('<ServerFingerprintMismatch expected=exp'
                ' got=got host=host port=8888>')
    assert expected == repr(err)


def test_invalid_url() -> None:
    url = URL('http://example.com')
    err = client.InvalidURL(url)
    assert err.args[0] is url
    assert err.url is url
    assert repr(err) == "<InvalidURL http://example.com>"


def test_response_default_status() -> None:
    request_info = mock.Mock(real_url='http://example.com')
    err = client.ClientResponseError(history=None,
                                     request_info=request_info)
    assert err.status == 0


def test_response_status() -> None:
    request_info = mock.Mock(real_url='http://example.com')
    err = client.ClientResponseError(status=400,
                                     history=None,
                                     request_info=request_info)
    assert err.status == 400


def test_response_deprecated_code_property() -> None:
    request_info = mock.Mock(real_url='http://example.com')
    with pytest.warns(DeprecationWarning):
        err = client.ClientResponseError(code=400,
                                         history=None,
                                         request_info=request_info)
    with pytest.warns(DeprecationWarning):
        assert err.code == err.status
    with pytest.warns(DeprecationWarning):
        err.code = '404'
    with pytest.warns(DeprecationWarning):
        assert err.code == err.status


def test_response_both_code_and_status() -> None:
    with pytest.raises(ValueError):
        client.ClientResponseError(code=400,
                                   status=400,
                                   history=None,
                                   request_info=None)
