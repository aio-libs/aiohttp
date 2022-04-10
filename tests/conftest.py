import asyncio
import hashlib
import pathlib
import shutil
import ssl
import sys
import tempfile
import uuid

import pytest

from aiohttp.test_utils import loop_context

try:
    import trustme

    # Check if the CA is available in runtime, MacOS on Py3.10 fails somehow
    trustme.CA()

    TRUSTME: bool = True
except ImportError:
    TRUSTME = False

pytest_plugins = ["aiohttp.pytest_plugin", "pytester"]


@pytest.fixture
def shorttmpdir():
    # Provides a temporary directory with a shorter file system path than the
    # tmpdir fixture.
    tmpdir = pathlib.Path(tempfile.mkdtemp())
    yield tmpdir
    # str(tmpdir) is required, Python 3.5 doesn't have __fspath__
    # concept
    shutil.rmtree(str(tmpdir), ignore_errors=True)


@pytest.fixture
def tls_certificate_authority():
    if not TRUSTME:
        pytest.xfail("trustme is not supported")
    return trustme.CA()


@pytest.fixture
def tls_certificate(tls_certificate_authority):
    return tls_certificate_authority.issue_cert(
        "localhost",
        "127.0.0.1",
        "::1",
    )


@pytest.fixture
def ssl_ctx(tls_certificate):
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
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
    return hashlib.sha256(tls_cert_der).digest()


@pytest.fixture
def pipe_name():
    name = rf"\\.\pipe\{uuid.uuid4().hex}"
    return name


@pytest.fixture
def selector_loop():
    if sys.version_info >= (3, 8):
        policy = asyncio.WindowsSelectorEventLoopPolicy()
    else:
        policy = asyncio.DefaultEventLoopPolicy()
    asyncio.set_event_loop_policy(policy)

    with loop_context(policy.new_event_loop) as _loop:
        asyncio.set_event_loop(_loop)
        yield _loop
