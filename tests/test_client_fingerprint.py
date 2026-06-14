import hashlib
from unittest import mock

import pytest

import aiohttp
from aiohttp.client_exceptions import ServerFingerprintMismatch

ssl = pytest.importorskip("ssl")


def test_fingerprint_sha256() -> None:
    sha256 = hashlib.sha256(b"12345678" * 64).digest()
    fp = aiohttp.Fingerprint(sha256)
    assert fp.fingerprint == sha256


def test_fingerprint_sha1() -> None:
    sha1 = hashlib.sha1(b"12345678" * 64).digest()
    with pytest.raises(ValueError):
        aiohttp.Fingerprint(sha1)


def test_fingerprint_md5() -> None:
    md5 = hashlib.md5(b"12345678" * 64).digest()
    with pytest.raises(ValueError):
        aiohttp.Fingerprint(md5)


def test_fingerprint_check_no_ssl() -> None:
    sha256 = hashlib.sha256(b"12345678" * 64).digest()
    fp = aiohttp.Fingerprint(sha256)
    transport = mock.Mock()
    transport.get_extra_info.return_value = None
    fp.check(transport)


def test_fingerprint_check_passes_ssl_object_on_mismatch() -> None:
    sha256 = hashlib.sha256(b"12345678" * 64).digest()
    fp = aiohttp.Fingerprint(sha256)

    mock_ssl_object = mock.Mock(spec=ssl.SSLObject)
    bad_cert = b"bad_cert_data"
    mock_ssl_object.getpeercert.return_value = bad_cert

    transport = mock.Mock()

    def get_extra_info(key: str, default: object = None) -> object:
        if key == "sslcontext":
            return mock.Mock()
        if key == "ssl_object":
            return mock_ssl_object
        if key == "peername":
            return ("127.0.0.1", 443)
        return default

    transport.get_extra_info.side_effect = get_extra_info

    with pytest.raises(ServerFingerprintMismatch) as exc_info:
        fp.check(transport)

    assert exc_info.value.ssl_object is mock_ssl_object


def test_fingerprint_check_ssl_object_none_when_get_extra_info_raises() -> None:
    sha256 = hashlib.sha256(b"12345678" * 64).digest()
    fp = aiohttp.Fingerprint(sha256)

    mock_ssl_object = mock.Mock(spec=ssl.SSLObject)
    bad_cert = b"bad_cert_data"
    mock_ssl_object.getpeercert.return_value = bad_cert

    call_count = 0

    def get_extra_info(key: str, default: object = None) -> object:
        nonlocal call_count
        if key == "sslcontext":
            return mock.Mock()
        if key == "ssl_object":
            call_count += 1
            if call_count == 1:
                return mock_ssl_object
            raise RuntimeError("transport closed")
        if key == "peername":
            return ("127.0.0.1", 443)
        return default

    transport = mock.Mock()
    transport.get_extra_info.side_effect = get_extra_info

    with pytest.raises(ServerFingerprintMismatch) as exc_info:
        fp.check(transport)

    assert exc_info.value.ssl_object is None
