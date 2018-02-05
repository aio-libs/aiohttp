import hashlib
from unittest import mock

import pytest

import aiohttp
from aiohttp.client_reqrep import _merge_ssl_params


ssl = pytest.importorskip('ssl')


def test_fingerprint_sha256():
    sha256 = hashlib.sha256(b'12345678'*64).digest()
    fp = aiohttp.Fingerprint(sha256)
    assert fp.fingerprint == sha256


def test_fingerprint_sha1():
    sha1 = hashlib.sha1(b'12345678'*64).digest()
    with pytest.raises(ValueError):
        aiohttp.Fingerprint(sha1)


def test_fingerprint_md5():
    md5 = hashlib.md5(b'12345678'*64).digest()
    with pytest.raises(ValueError):
        aiohttp.Fingerprint(md5)


def test_fingerprint_check_no_ssl():
    sha256 = hashlib.sha256(b'12345678'*64).digest()
    fp = aiohttp.Fingerprint(sha256)
    transport = mock.Mock()
    transport.get_extra_info.return_value = None
    assert fp.check(transport) is None


def test__merge_ssl_params_verify_ssl():
    with pytest.warns(DeprecationWarning):
        assert _merge_ssl_params(None, False, None, None) is False


def test__merge_ssl_params_verify_ssl_conflict():
    ctx = ssl.SSLContext()
    with pytest.warns(DeprecationWarning):
        with pytest.raises(ValueError):
            _merge_ssl_params(ctx, False, None, None)


def test__merge_ssl_params_ssl_context():
    ctx = ssl.SSLContext()
    with pytest.warns(DeprecationWarning):
        assert _merge_ssl_params(None, None, ctx, None) is ctx


def test__merge_ssl_params_ssl_context_conflict():
    ctx1 = ssl.SSLContext()
    ctx2 = ssl.SSLContext()
    with pytest.warns(DeprecationWarning):
        with pytest.raises(ValueError):
            _merge_ssl_params(ctx1, None, ctx2, None)


def test__merge_ssl_params_fingerprint():
    digest = hashlib.sha256(b'123').digest()
    with pytest.warns(DeprecationWarning):
        ret = _merge_ssl_params(None, None, None, digest)
        assert ret.fingerprint == digest


def test__merge_ssl_params_fingerprint_conflict():
    fingerprint = aiohttp.Fingerprint(hashlib.sha256(b'123').digest())
    ctx = ssl.SSLContext()
    with pytest.warns(DeprecationWarning):
        with pytest.raises(ValueError):
            _merge_ssl_params(ctx, None, None, fingerprint)


def test__merge_ssl_params_ssl():
    ctx = ssl.SSLContext()
    assert ctx is _merge_ssl_params(ctx, None, None, None)


def test__merge_ssl_params_invlid():
    with pytest.raises(TypeError):
        _merge_ssl_params(object(), None, None, None)
