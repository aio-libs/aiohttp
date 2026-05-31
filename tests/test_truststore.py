"""Tests for the opt-in ``use_truststore`` flag on :class:`TCPConnector`.

The ``truststore`` library delegates TLS certificate verification to the
operating system's native trust store (macOS Keychain, Windows certificate
stores). Passing ``use_truststore=True`` makes :class:`TCPConnector` build
its verified SSL context via :class:`truststore.SSLContext` instead of
:func:`ssl.create_default_context`. Default behaviour (``use_truststore=False``)
is unchanged and continues to use the module-level stdlib context built at
import time, which performs no I/O on the event loop at request time.

These tests intentionally do not perform live TLS handshakes — they exercise
the SSL-context construction and dispatch logic only. ``truststore``'s
``_configure_context`` runs on every ``wrap_socket`` call and does
file-existence probes; tests that exercise the opt-in path are marked
``skip_blockbuster`` because the user has explicitly accepted that cost.
"""

import ssl
from unittest import mock

import pytest

from aiohttp import TCPConnector, connector as connector_module
from aiohttp.client_reqrep import Fingerprint


def _has_truststore() -> bool:
    try:
        import truststore  # noqa: F401
    except ImportError:
        return False
    return True


def test_has_truststore_matches_importability() -> None:
    """``HAS_TRUSTSTORE`` reflects whether the library can be imported."""
    assert connector_module.HAS_TRUSTSTORE is _has_truststore()


def test_default_verified_context_does_not_use_truststore() -> None:
    """The module-level verified context is stdlib, even when truststore is installed.

    This is the load-bearing invariant: ``_SSL_CONTEXT_VERIFIED`` must be a
    plain ``ssl.SSLContext`` so the default request path performs zero
    per-handshake file I/O on the event loop, matching pre-PR behaviour.
    Uses ``type() is`` rather than ``isinstance``: ``truststore.SSLContext``
    subclasses ``ssl.SSLContext``, so ``isinstance`` would pass in both
    branches and silently hide a regression here.
    """
    assert type(connector_module._SSL_CONTEXT_VERIFIED) is ssl.SSLContext


@pytest.mark.skipif(not _has_truststore(), reason="truststore not installed")
def test_make_ssl_context_uses_truststore_when_opted_in() -> None:
    """``_make_ssl_context(True, use_truststore=True)`` returns a truststore context."""
    import truststore

    ctx = connector_module._make_ssl_context(True, use_truststore=True)
    assert isinstance(ctx, truststore.SSLContext)


def test_make_ssl_context_default_does_not_use_truststore() -> None:
    """Without ``use_truststore=True`` the default verified context is stdlib."""
    ctx = connector_module._make_ssl_context(True)
    assert type(ctx) is ssl.SSLContext


def test_make_ssl_context_raises_when_truststore_missing() -> None:
    """``use_truststore=True`` raises a clear error when the lib is absent."""
    with mock.patch.object(connector_module, "HAS_TRUSTSTORE", False):
        with pytest.raises(RuntimeError, match="truststore is not installed"):
            connector_module._make_ssl_context(True, use_truststore=True)


def test_make_ssl_context_unverified_ignores_use_truststore() -> None:
    """``use_truststore`` is a no-op on the unverified path."""
    ctx = connector_module._make_ssl_context(False, use_truststore=True)
    assert type(ctx) is ssl.SSLContext
    assert ctx.verify_mode == ssl.CERT_NONE


@pytest.mark.skipif(not _has_truststore(), reason="truststore not installed")
@pytest.mark.skip_blockbuster
async def test_use_truststore_true_returns_truststore_context() -> None:
    """``TCPConnector(use_truststore=True)`` returns a truststore context for verified requests."""
    import truststore

    conn = TCPConnector(use_truststore=True)
    try:
        req = mock.Mock()
        req.is_ssl.return_value = True
        req.ssl = True
        returned = conn._get_ssl_context(req)
        assert isinstance(returned, truststore.SSLContext)
        assert returned is conn._ssl_context_truststore
    finally:
        await conn.close()


async def test_use_truststore_false_returns_module_level_verified() -> None:
    """Default ``use_truststore=False`` returns ``_SSL_CONTEXT_VERIFIED``."""
    conn = TCPConnector()
    try:
        req = mock.Mock()
        req.is_ssl.return_value = True
        req.ssl = True
        returned = conn._get_ssl_context(req)
        assert returned is connector_module._SSL_CONTEXT_VERIFIED
    finally:
        await conn.close()


@pytest.mark.skipif(not _has_truststore(), reason="truststore not installed")
@pytest.mark.skip_blockbuster
async def test_explicit_ssl_context_overrides_use_truststore() -> None:
    """An explicit ``ssl=<SSLContext>`` argument wins over ``use_truststore=True``."""
    explicit_ctx = ssl.create_default_context()
    conn = TCPConnector(ssl=explicit_ctx, use_truststore=True)
    try:
        req = mock.Mock()
        req.is_ssl.return_value = True
        req.ssl = True
        assert conn._get_ssl_context(req) is explicit_ctx
    finally:
        await conn.close()


@pytest.mark.skipif(not _has_truststore(), reason="truststore not installed")
@pytest.mark.skip_blockbuster
async def test_fingerprint_uses_unverified_context_even_with_truststore() -> None:
    """A ``Fingerprint`` replaces CA verification; truststore must not apply."""
    fingerprint = Fingerprint(b"\x00" * 32)
    conn = TCPConnector(ssl=fingerprint, use_truststore=True)
    try:
        req = mock.Mock()
        req.is_ssl.return_value = True
        req.ssl = True
        returned = conn._get_ssl_context(req)
        assert returned is connector_module._SSL_CONTEXT_UNVERIFIED
    finally:
        await conn.close()


async def test_use_truststore_true_with_ssl_false_raises() -> None:
    """``use_truststore=True`` is incompatible with ``ssl=False``."""
    with pytest.raises(ValueError, match="incompatible with ssl=False"):
        TCPConnector(ssl=False, use_truststore=True)


async def test_use_truststore_true_without_truststore_raises() -> None:
    """``TCPConnector(use_truststore=True)`` raises when truststore is missing."""
    with mock.patch.object(connector_module, "HAS_TRUSTSTORE", False):
        with pytest.raises(RuntimeError, match="truststore is not installed"):
            TCPConnector(use_truststore=True)
