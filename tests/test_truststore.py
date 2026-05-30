"""Tests for automatic ``truststore`` preference on :class:`TCPConnector`.

The ``truststore`` library delegates TLS certificate verification to the
operating system's native trust store. When ``truststore`` is importable,
``aiohttp.connector`` automatically uses ``truststore.SSLContext`` for its
default verified context; otherwise it falls back to the stdlib
``ssl.create_default_context()``. This module covers both branches.

These tests intentionally do not perform live TLS handshakes — they exercise
the SSL-context construction and dispatch logic only.
"""

import ssl
from unittest import mock

import pytest

from aiohttp import TCPConnector, connector as connector_module
from aiohttp.client_reqrep import Fingerprint


def _has_truststore() -> bool:
    try:
        import truststore  # type: ignore[import-not-found,unused-ignore]  # noqa: F401
    except ImportError:
        return False
    return True


def test_has_truststore_matches_importability() -> None:
    """``HAS_TRUSTSTORE`` reflects whether the library can be imported."""
    assert connector_module.HAS_TRUSTSTORE is _has_truststore()


@pytest.mark.skipif(not _has_truststore(), reason="truststore not installed")
def test_make_ssl_context_uses_truststore_when_available() -> None:
    """Verified context is a truststore.SSLContext when the lib is installed."""
    import truststore  # type: ignore[import-not-found,unused-ignore]

    ctx = connector_module._make_ssl_context(True)
    assert isinstance(ctx, truststore.SSLContext)


def test_make_ssl_context_falls_back_to_stdlib_when_truststore_absent() -> None:
    """Verified context is a plain ssl.SSLContext when truststore is missing.

    Uses ``type() is`` rather than ``isinstance``: ``truststore.SSLContext``
    subclasses ``ssl.SSLContext``, so ``isinstance`` would pass in both
    branches and silently hide a regression here.
    """
    with mock.patch.object(connector_module, "HAS_TRUSTSTORE", False):
        ctx = connector_module._make_ssl_context(True)
    assert type(ctx) is ssl.SSLContext


def test_make_ssl_context_unverified_path_does_not_touch_truststore() -> None:
    """Unverified context never uses truststore, regardless of HAS_TRUSTSTORE."""
    with mock.patch.object(connector_module, "HAS_TRUSTSTORE", True):
        ctx = connector_module._make_ssl_context(False)
    assert type(ctx) is ssl.SSLContext
    assert ctx.verify_mode == ssl.CERT_NONE


@pytest.mark.skipif(not _has_truststore(), reason="truststore not installed")
def test_make_ssl_context_verified_with_truststore_sets_alpn() -> None:
    """``set_alpn_protocols`` works on a truststore-backed context."""
    ctx = connector_module._make_ssl_context(True)
    assert isinstance(ctx, ssl.SSLContext)


@pytest.mark.skipif(not _has_truststore(), reason="truststore not installed")
async def test_get_ssl_context_returns_module_level_verified() -> None:
    """Default verified request returns the module-level ``_SSL_CONTEXT_VERIFIED``."""
    import truststore  # type: ignore[import-not-found,unused-ignore]

    conn = TCPConnector()
    try:
        req = mock.Mock()
        req.is_ssl.return_value = True
        req.ssl = True
        returned = conn._get_ssl_context(req)
        assert returned is connector_module._SSL_CONTEXT_VERIFIED
        assert isinstance(returned, truststore.SSLContext)
    finally:
        await conn.close()


@pytest.mark.skipif(not _has_truststore(), reason="truststore not installed")
async def test_explicit_ssl_context_overrides_default() -> None:
    """An explicit ``ssl=<SSLContext>`` argument wins over the default."""
    explicit_ctx = ssl.create_default_context()
    conn = TCPConnector(ssl=explicit_ctx)
    try:
        req = mock.Mock()
        req.is_ssl.return_value = True
        req.ssl = True
        assert conn._get_ssl_context(req) is explicit_ctx
    finally:
        await conn.close()


@pytest.mark.skipif(not _has_truststore(), reason="truststore not installed")
async def test_fingerprint_uses_unverified_context_even_with_truststore() -> None:
    """A ``Fingerprint`` replaces CA verification; truststore must not apply."""
    fingerprint = Fingerprint(b"\x00" * 32)
    conn = TCPConnector(ssl=fingerprint)
    try:
        req = mock.Mock()
        req.is_ssl.return_value = True
        req.ssl = True
        returned = conn._get_ssl_context(req)
        assert returned is connector_module._SSL_CONTEXT_UNVERIFIED
    finally:
        await conn.close()
