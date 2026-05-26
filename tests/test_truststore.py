"""Tests for the opt-in ``use_truststore`` flag on :class:`TCPConnector`.

The ``truststore`` library delegates TLS certificate verification to the
operating system's native trust store. This module covers the
``TCPConnector(use_truststore=True)`` opt-in code path added in
``aiohttp/connector.py``.

The tests intentionally do not perform live TLS handshakes — they exercise the
SSL-context construction and dispatch logic only. End-to-end verification of
the OS trust integration is documented in the PR description.
"""

import ssl
import sys
from typing import Any
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


async def test_use_truststore_default_is_false() -> None:
    """The default value preserves prior behaviour."""
    conn = TCPConnector()
    try:
        assert conn._use_truststore is False
        assert conn._ssl_context_truststore is None
    finally:
        await conn.close()


async def test_use_truststore_false_does_not_import_truststore() -> None:
    """With the flag off, the truststore module must not be imported."""
    original = sys.modules.pop("truststore", None)
    try:
        with mock.patch.object(
            connector_module,
            "_import_truststore",
            side_effect=AssertionError("must not be called"),
        ):
            conn = TCPConnector(use_truststore=False)
            try:
                assert conn._ssl_context_truststore is None
            finally:
                await conn.close()
    finally:
        if original is not None:
            sys.modules["truststore"] = original


@pytest.mark.skipif(not _has_truststore(), reason="truststore not installed")
async def test_use_truststore_true_uses_truststore_context() -> None:
    """When the flag is True and the library is present, a truststore
    SSLContext is built and returned from the dispatch."""
    import truststore

    conn = TCPConnector(use_truststore=True)
    try:
        assert conn._use_truststore is True
        assert isinstance(conn._ssl_context_truststore, truststore.SSLContext)
    finally:
        await conn.close()


async def test_use_truststore_true_raises_when_truststore_missing() -> None:
    """A friendly ``RuntimeError`` is raised at construction time when the
    optional dependency is not installed."""

    def fake_import() -> Any:
        raise RuntimeError(
            "truststore is not installed. Install it with "
            "`pip install aiohttp[truststore]` to enable use_truststore=True."
        )

    with mock.patch.object(connector_module, "_import_truststore", fake_import):
        with pytest.raises(RuntimeError, match="truststore is not installed"):
            TCPConnector(use_truststore=True)


def test_import_truststore_helper_wraps_importerror() -> None:
    """The ``_import_truststore`` helper translates ``ImportError`` from a
    missing ``truststore`` module into a ``RuntimeError`` with install hints.

    This test is synchronous because the helper does not touch the loop.
    """
    sentinel_missing = object()
    original = sys.modules.get("truststore", sentinel_missing)
    sys.modules["truststore"] = None  # type: ignore[assignment]
    try:
        with pytest.raises(RuntimeError) as excinfo:
            connector_module._import_truststore()
        assert "pip install aiohttp[truststore]" in str(excinfo.value)
        assert isinstance(excinfo.value.__cause__, ImportError)
    finally:
        if original is sentinel_missing:
            sys.modules.pop("truststore", None)
        else:
            sys.modules["truststore"] = original  # type: ignore[assignment]


async def test_use_truststore_true_with_ssl_false_raises_value_error() -> None:
    """``use_truststore=True`` is incompatible with ``ssl=False`` because there
    is no concept of an unverified trust-store context."""
    with pytest.raises(ValueError, match="incompatible with ssl=False"):
        TCPConnector(use_truststore=True, ssl=False)


@pytest.mark.skipif(not _has_truststore(), reason="truststore not installed")
async def test_explicit_ssl_context_overrides_use_truststore() -> None:
    """When the user passes both an explicit ``SSLContext`` and the flag, the
    explicit context wins. The truststore context remains cached but unused
    in the dispatch."""
    import truststore

    explicit_ctx = ssl.create_default_context()
    conn = TCPConnector(use_truststore=True, ssl=explicit_ctx)
    try:
        assert isinstance(conn._ssl_context_truststore, truststore.SSLContext)
        req = mock.Mock()
        req.is_ssl.return_value = True
        req.ssl = True
        assert conn._get_ssl_context(req) is explicit_ctx
    finally:
        await conn.close()


@pytest.mark.skipif(not _has_truststore(), reason="truststore not installed")
async def test_use_truststore_per_instance_no_singleton_bleed() -> None:
    """Two connectors get two distinct truststore contexts; enabling the flag
    on one connector does not affect another connector that did not opt in."""
    import truststore

    conn_a = TCPConnector(use_truststore=True)
    conn_b = TCPConnector(use_truststore=True)
    conn_c = TCPConnector()
    try:
        assert isinstance(conn_a._ssl_context_truststore, truststore.SSLContext)
        assert isinstance(conn_b._ssl_context_truststore, truststore.SSLContext)
        assert conn_a._ssl_context_truststore is not conn_b._ssl_context_truststore
        assert conn_c._ssl_context_truststore is None
    finally:
        await conn_a.close()
        await conn_b.close()
        await conn_c.close()


@pytest.mark.skipif(not _has_truststore(), reason="truststore not installed")
async def test_get_ssl_context_returns_truststore_context_for_verified_request() -> (
    None
):
    """The dispatch returns the per-connector truststore context in place of
    the module-level verified singleton when the flag is set."""
    import truststore

    conn = TCPConnector(use_truststore=True)
    try:
        req = mock.Mock()
        req.is_ssl.return_value = True
        req.ssl = True
        returned = conn._get_ssl_context(req)
        assert isinstance(returned, truststore.SSLContext)
        assert returned is conn._ssl_context_truststore
        assert returned is not connector_module._SSL_CONTEXT_VERIFIED
    finally:
        await conn.close()


@pytest.mark.skipif(not _has_truststore(), reason="truststore not installed")
async def test_use_truststore_with_fingerprint_uses_unverified_context() -> None:
    """``Fingerprint`` validation happens after the handshake. The existing
    dispatch returns the unverified singleton for fingerprint-pinned
    requests; enabling ``use_truststore`` does not change that, because
    fingerprint pinning replaces CA verification entirely."""
    fingerprint = Fingerprint(b"\x00" * 32)
    conn = TCPConnector(use_truststore=True, ssl=fingerprint)
    try:
        req = mock.Mock()
        req.is_ssl.return_value = True
        req.ssl = True
        returned = conn._get_ssl_context(req)
        assert returned is connector_module._SSL_CONTEXT_UNVERIFIED
    finally:
        await conn.close()


def test_make_ssl_context_unverified_ignores_use_truststore() -> None:
    """When ``verified=False``, ``use_truststore`` is silently ignored — there
    is no concept of an unverified truststore context. Synchronous because it
    only exercises the module-level helper."""
    with mock.patch.object(
        connector_module,
        "_import_truststore",
        side_effect=AssertionError("must not be called"),
    ):
        ctx = connector_module._make_ssl_context(False, use_truststore=True)
    assert isinstance(ctx, ssl.SSLContext)


@pytest.mark.skipif(not _has_truststore(), reason="truststore not installed")
def test_make_ssl_context_verified_with_truststore_sets_alpn() -> None:
    """``set_alpn_protocols`` must work on the truststore-backed context — it
    is a documented subclass of ``ssl.SSLContext``. Synchronous because it
    only exercises the module-level helper."""
    ctx = connector_module._make_ssl_context(True, use_truststore=True)
    assert isinstance(ctx, ssl.SSLContext)
