from unittest import mock

import pytest

from aiohttp import errors, parsers


@pytest.fixture
def stream():
    return mock.Mock()


@pytest.fixture
def buf():
    return parsers.ParserBuffer()


def test_feed_data(buf):
    buf.feed_data(b'')
    assert len(buf) == 0

    buf.feed_data(b'data')
    assert len(buf) == 4
    assert bytes(buf), b'data'


def test_feed_data_after_exception(buf):
    buf.feed_data(b'data')

    exc = ValueError()
    buf.set_exception(exc)
    buf.feed_data(b'more')
    assert len(buf) == 4
    assert bytes(buf) == b'data'


def test_read_exc(buf):
    p = buf.read(3)
    next(p)
    p.send(b'1')

    exc = ValueError()
    buf.set_exception(exc)
    assert buf.exception() is exc
    with pytest.raises(ValueError):
        p.send(b'1')


def test_read_exc_multiple(buf):
    p = buf.read(3)
    next(p)
    p.send(b'1')

    exc = ValueError()
    buf.set_exception(exc)
    assert buf.exception() is exc

    p = buf.read(3)
    with pytest.raises(ValueError):
        next(p)


def test_read(buf):
    p = buf.read(3)
    next(p)
    p.send(b'1')
    try:
        p.send(b'234')
    except StopIteration as exc:
        res = exc.value

    assert res == b'123'
    assert b'4' == bytes(buf)


def test_readsome(buf):
    p = buf.readsome(3)
    next(p)
    try:
        p.send(b'1')
    except StopIteration as exc:
        res = exc.value
    assert res == b'1'

    p = buf.readsome(2)
    next(p)
    try:
        p.send(b'234')
    except StopIteration as exc:
        res = exc.value
    assert res == b'23'
    assert b'4' == bytes(buf)


def test_readsome_exc(buf):
    buf.set_exception(ValueError())

    p = buf.readsome(3)
    with pytest.raises(ValueError):
        next(p)


def test_wait(buf):
    p = buf.wait(3)
    next(p)
    p.send(b'1')
    try:
        p.send(b'234')
    except StopIteration as exc:
        res = exc.value

    assert res == b'123'
    assert b'1234' == bytes(buf)


def test_wait_exc(buf):
    buf.set_exception(ValueError())

    p = buf.wait(3)
    with pytest.raises(ValueError):
        next(p)


def test_skip(buf):
    p = buf.skip(3)
    next(p)
    p.send(b'1')
    try:
        p.send(b'234')
    except StopIteration as exc:
        res = exc.value

    assert res is None
    assert b'4' == bytes(buf)


def test_skip_exc(buf):
    buf.set_exception(ValueError())
    p = buf.skip(3)
    with pytest.raises(ValueError):
        next(p)


def test_readuntil_limit(buf):
    p = buf.readuntil(b'\n', 4)
    next(p)
    p.send(b'1')
    p.send(b'234')
    with pytest.raises(errors.LineLimitExceededParserError):
        p.send(b'5')


def test_readuntil_limit2(buf):
    p = buf.readuntil(b'\n', 4)
    next(p)
    with pytest.raises(errors.LineLimitExceededParserError):
        p.send(b'12345\n6')


def test_readuntil_limit3(buf):
    p = buf.readuntil(b'\n', 4)
    next(p)
    with pytest.raises(errors.LineLimitExceededParserError):
        p.send(b'12345\n6')


def test_readuntil(buf):
    p = buf.readuntil(b'\n', 4)
    next(p)
    p.send(b'123')
    try:
        p.send(b'\n456')
    except StopIteration as exc:
        res = exc.value

    assert res == b'123\n'
    assert b'456' == bytes(buf)


def test_readuntil_exc(buf):
    buf.set_exception(ValueError())
    p = buf.readuntil(b'\n', 4)
    with pytest.raises(ValueError):
        next(p)


def test_waituntil_limit(buf):
    p = buf.waituntil(b'\n', 4)
    next(p)
    p.send(b'1')
    p.send(b'234')
    with pytest.raises(errors.LineLimitExceededParserError):
        p.send(b'5')


def test_waituntil_limit2(buf):
    p = buf.waituntil(b'\n', 4)
    next(p)
    with pytest.raises(errors.LineLimitExceededParserError):
        p.send(b'12345\n6')


def test_waituntil_limit3(buf):
    p = buf.waituntil(b'\n', 4)
    next(p)
    with pytest.raises(errors.LineLimitExceededParserError):
        p.send(b'12345\n6')


def test_waituntil(buf):
    p = buf.waituntil(b'\n', 4)
    next(p)
    p.send(b'123')
    try:
        p.send(b'\n456')
    except StopIteration as exc:
        res = exc.value

    assert res == b'123\n'
    assert b'123\n456' == bytes(buf)


def test_waituntil_exc(buf):
    buf.set_exception(ValueError())
    p = buf.waituntil(b'\n', 4)
    with pytest.raises(ValueError):
        next(p)


def test_skipuntil(buf):
    p = buf.skipuntil(b'\n')
    next(p)
    p.send(b'123')
    try:
        p.send(b'\n456\n')
    except StopIteration:
        pass
    assert b'456\n' == bytes(buf)

    p = buf.skipuntil(b'\n')
    try:
        next(p)
    except StopIteration:
        pass
    assert b'' == bytes(buf)


def test_skipuntil_exc(buf):
    buf.set_exception(ValueError())
    p = buf.skipuntil(b'\n')
    with pytest.raises(ValueError):
        next(p)
