"""Tests for http_exceptions.py"""

from aiohttp import http_exceptions


def test_bad_status_line1():
    err = http_exceptions.BadStatusLine(b'')
    assert str(err) == "b''"


def test_bad_status_line2():
    err = http_exceptions.BadStatusLine('Test')
    assert str(err) == 'Test'


def test_http_error_exception():
    exc = http_exceptions.HttpProcessingError(
        code=500, message='Internal error')
    assert exc.code == 500
    assert exc.message == 'Internal error'
