# Tests for http_exceptions.py

import pickle

from aiohttp import http_exceptions


class TestHttpProcessingError:
    def test_ctor(self) -> None:
        err = http_exceptions.HttpProcessingError(
            code=500, message="Internal error", headers={}
        )
        assert err.code == 500
        assert err.message == "Internal error"
        assert err.headers == {}

    def test_pickle(self) -> None:
        err = http_exceptions.HttpProcessingError(
            code=500, message="Internal error", headers={}
        )
        err.foo = "bar"
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(err, proto)
            err2 = pickle.loads(pickled)
            assert err2.code == 500
            assert err2.message == "Internal error"
            assert err2.headers == {}
            assert err2.foo == "bar"

    def test_str(self) -> None:
        err = http_exceptions.HttpProcessingError(
            code=500, message="Internal error", headers={}
        )
        assert str(err) == "500, message:\n  Internal error"

    def test_repr(self) -> None:
        err = http_exceptions.HttpProcessingError(
            code=500, message="Internal error", headers={}
        )
        assert repr(err) == ("<HttpProcessingError: 500, message='Internal error'>")


class TestBadHttpMessage:
    def test_ctor(self) -> None:
        err = http_exceptions.BadHttpMessage("Bad HTTP message", headers={})
        assert err.code == 400
        assert err.message == "Bad HTTP message"
        assert err.headers == {}

    def test_pickle(self) -> None:
        err = http_exceptions.BadHttpMessage(message="Bad HTTP message", headers={})
        err.foo = "bar"
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(err, proto)
            err2 = pickle.loads(pickled)
            assert err2.code == 400
            assert err2.message == "Bad HTTP message"
            assert err2.headers == {}
            assert err2.foo == "bar"

    def test_str(self) -> None:
        err = http_exceptions.BadHttpMessage(message="Bad HTTP message", headers={})
        assert str(err) == "400, message:\n  Bad HTTP message"

    def test_repr(self) -> None:
        err = http_exceptions.BadHttpMessage(message="Bad HTTP message", headers={})
        assert repr(err) == "<BadHttpMessage: 400, message='Bad HTTP message'>"


class TestLineTooLong:
    def test_ctor(self) -> None:
        err = http_exceptions.LineTooLong("spam", "10", "12")
        assert err.code == 400
        assert err.message == "Got more than 10 bytes (12) when reading spam."
        assert err.headers is None

    def test_pickle(self) -> None:
        err = http_exceptions.LineTooLong(line="spam", limit="10", actual_size="12")
        err.foo = "bar"
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(err, proto)
            err2 = pickle.loads(pickled)
            assert err2.code == 400
            assert err2.message == ("Got more than 10 bytes (12) " "when reading spam.")
            assert err2.headers is None
            assert err2.foo == "bar"

    def test_str(self) -> None:
        err = http_exceptions.LineTooLong(line="spam", limit="10", actual_size="12")
        expected = "400, message:\n  Got more than 10 bytes (12) when reading spam."
        assert str(err) == expected

    def test_repr(self) -> None:
        err = http_exceptions.LineTooLong(line="spam", limit="10", actual_size="12")
        assert repr(err) == (
            "<LineTooLong: 400, message='Got more than "
            "10 bytes (12) when reading spam.'>"
        )


class TestInvalidHeader:
    def test_ctor(self) -> None:
        err = http_exceptions.InvalidHeader("X-Spam")
        assert err.code == 400
        assert err.message == "Invalid HTTP header: 'X-Spam'"
        assert err.headers is None

    def test_pickle(self) -> None:
        err = http_exceptions.InvalidHeader(hdr="X-Spam")
        err.foo = "bar"
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(err, proto)
            err2 = pickle.loads(pickled)
            assert err2.code == 400
            assert err2.message == "Invalid HTTP header: 'X-Spam'"
            assert err2.headers is None
            assert err2.foo == "bar"

    def test_str(self) -> None:
        err = http_exceptions.InvalidHeader(hdr="X-Spam")
        assert str(err) == "400, message:\n  Invalid HTTP header: 'X-Spam'"

    def test_repr(self) -> None:
        err = http_exceptions.InvalidHeader(hdr="X-Spam")
        expected = "<InvalidHeader: 400, message=\"Invalid HTTP header: 'X-Spam'\">"
        assert repr(err) == expected


class TestBadStatusLine:
    def test_ctor(self) -> None:
        err = http_exceptions.BadStatusLine("Test")
        assert err.line == "Test"
        assert str(err) == "400, message:\n  Bad status line 'Test'"

    def test_ctor2(self) -> None:
        err = http_exceptions.BadStatusLine(b"")
        assert err.line == "b''"
        assert str(err) == "400, message:\n  Bad status line \"b''\""

    def test_pickle(self) -> None:
        err = http_exceptions.BadStatusLine("Test")
        err.foo = "bar"
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(err, proto)
            err2 = pickle.loads(pickled)
            assert err2.line == "Test"
            assert err2.foo == "bar"
