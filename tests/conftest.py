import hashlib
import ssl

import pytest
import trustme

pytest_plugins = ['aiohttp.pytest_plugin', 'pytester']


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
    return hashlib.sha256(tls_cert_der).digest()
