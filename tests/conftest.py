import os
import socket
import ssl
import sys
from hashlib import md5, sha256
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
import trustme

pytest_plugins = ['aiohttp.pytest_plugin', 'pytester']

IS_HPUX = sys.platform.startswith('hp-ux')
"""Specifies whether the current runtime is HP-UX."""
IS_LINUX = sys.platform.startswith('linux')
"""Specifies whether the current runtime is HP-UX."""
IS_UNIX = hasattr(socket, 'AF_UNIX')
"""Specifies whether the current runtime is *NIX."""

needs_unix = pytest.mark.skipif(not IS_UNIX, reason='requires UNIX sockets')


@pytest.fixture
def tls_certificate_authority():
    return trustme.CA()


@pytest.fixture
def tls_certificate(tls_certificate_authority):
    return tls_certificate_authority.issue_server_cert(
        'localhost',
        '127.0.0.1',
        '::1',
    )


@pytest.fixture
def ssl_ctx(tls_certificate):
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    tls_certificate.configure_cert(ssl_ctx)
    return ssl_ctx


@pytest.fixture
def client_ssl_ctx(tls_certificate_authority):
    ssl_ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    tls_certificate_authority.configure_trust(ssl_ctx)
    return ssl_ctx


@pytest.fixture
def tls_ca_certificate_pem_path(tls_certificate_authority):
    with tls_certificate_authority.cert_pem.tempfile() as ca_cert_pem:
        yield ca_cert_pem


@pytest.fixture
def tls_certificate_pem_path(tls_certificate):
    with tls_certificate.private_key_and_cert_chain_pem.tempfile() as cert_pem:
        yield cert_pem


@pytest.fixture
def tls_certificate_pem_bytes(tls_certificate):
    return tls_certificate.cert_chain_pems[0].bytes()


@pytest.fixture
def tls_certificate_fingerprint_sha256(tls_certificate_pem_bytes):
    tls_cert_der = ssl.PEM_cert_to_DER_cert(tls_certificate_pem_bytes.decode())
    return sha256(tls_cert_der).digest()


@pytest.fixture
@needs_unix
def unix_sockname(tmp_path, tmp_path_factory):
    """Generate an fs path to the UNIX domain socket for testing.

    N.B. Different OS kernels have different fs path length limitations
    for it. For Linux, it's 108, for HP-UX it's 92 (or higher) depending
    on its version. For for most of the BSDs (Open, Free, macOS) it's
    mostly 104 but sometimes it can be down to 100.

    Ref: https://github.com/aio-libs/aiohttp/issues/3572
    """
    max_sock_len = 92 if IS_HPUX else 108 if IS_LINUX else 100
    """Amount of bytes allocated for the UNIX socket path by OS kernel.

    Ref: https://unix.stackexchange.com/a/367012/27133
    """

    sock_file_name = 'unix.sock'

    root_tmp_dir = Path('/tmp').resolve()
    os_tmp_dir = Path(os.getenv('TMPDIR', '/tmp')).resolve()
    original_base_tmp_path = Path(tmp_path_factory.getbasetemp())

    original_base_tmp_path_hash = md5(
        str(original_base_tmp_path).encode(),
    ).hexdigest()

    def make_tmp_dir(base_tmp_dir):
        return TemporaryDirectory(
            dir=base_tmp_dir,
            prefix='pt-',
            suffix='-{}'.format(original_base_tmp_path_hash),
        )

    def assert_sock_fits(sock_path):
        sock_path_len = len(sock_path.encode())
        # exit-check to verify that it's correct and simplify debugging
        # in the future
        assert sock_path_len <= max_sock_len, (
            'Suggested UNIX socket ({sock_path}) is {sock_path_len} bytes '
            'long but the current kernel only has {max_sock_len} bytes '
            'allocated to hold it so it must be shorter. '
            'See https://github.com/aio-libs/aiohttp/issues/3572 '
            'for more info.'
        ).format_map(locals())

    sock_path = str(tmp_path.resolve() / sock_file_name)
    sock_path_len = len(sock_path.encode())

    if original_base_tmp_path == root_tmp_dir and os_tmp_dir == root_tmp_dir:
        assert_sock_fits(sock_path)

    if sock_path_len <= max_sock_len:
        yield sock_path
        return

    with make_tmp_dir(os_tmp_dir) as tmpd:
        sock_path = str(tmpd.resolve() / sock_file_name)
        sock_path_len = len(sock_path.encode())

        if os_tmp_dir == root_tmp_dir:
            assert_sock_fits(sock_path)
        # exit-check to verify that it's correct and simplify debugging
        # in the future
        if sock_path_len <= max_sock_len:
            yield sock_path
            return

    with make_tmp_dir(root_tmp_dir) as tmpd:
        sock_path = str(tmpd.resolve() / sock_file_name)

        assert_sock_fits(sock_path)

        yield sock_path
        return
