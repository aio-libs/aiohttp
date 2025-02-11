import asyncio
import base64
import os
import socket
import ssl
import sys
from hashlib import md5, sha1, sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable, Generator, Iterator
from unittest import mock
from uuid import uuid4

import pytest
from blockbuster import blockbuster_ctx

from aiohttp.client_proto import ResponseHandler
from aiohttp.http import WS_KEY
from aiohttp.test_utils import get_unused_port_socket, loop_context

try:
    import trustme

    # Check if the CA is available in runtime, MacOS on Py3.10 fails somehow
    trustme.CA()

    TRUSTME: bool = True
except ImportError:
    TRUSTME = False

pytest_plugins = ("aiohttp.pytest_plugin", "pytester")

IS_HPUX = sys.platform.startswith("hp-ux")
IS_LINUX = sys.platform.startswith("linux")


@pytest.fixture(autouse=True)
def blockbuster(request: pytest.FixtureRequest) -> Iterator[None]:
    # No blockbuster for benchmark tests.
    node = request.node.parent
    while node:
        if node.name.startswith("test_benchmarks"):
            yield
            return
        node = node.parent
    with blockbuster_ctx(
        "aiohttp", excluded_modules=["aiohttp.pytest_plugin", "aiohttp.test_utils"]
    ) as bb:
        # TODO: Fix blocking call in ClientRequest's constructor.
        # https://github.com/aio-libs/aiohttp/issues/10435
        for func in ["io.TextIOWrapper.read", "os.stat"]:
            bb.functions[func].can_block_in("aiohttp/client_reqrep.py", "update_auth")
        for func in ["os.readlink", "os.stat", "os.path.abspath", "os.path.samestat"]:
            bb.functions[func].can_block_in(
                "aiohttp/web_urldispatcher.py", "add_static"
            )
        yield


@pytest.fixture
def tls_certificate_authority() -> trustme.CA:
    if not TRUSTME:
        pytest.xfail("trustme is not supported")
    return trustme.CA()


@pytest.fixture
def tls_certificate(tls_certificate_authority: trustme.CA) -> trustme.LeafCert:
    return tls_certificate_authority.issue_cert(
        "localhost",
        "xn--prklad-4va.localhost",
        "127.0.0.1",
        "::1",
    )


@pytest.fixture
def ssl_ctx(tls_certificate: trustme.LeafCert) -> ssl.SSLContext:
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_certificate.configure_cert(ssl_ctx)
    return ssl_ctx


@pytest.fixture
def client_ssl_ctx(tls_certificate_authority: trustme.CA) -> ssl.SSLContext:
    ssl_ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    tls_certificate_authority.configure_trust(ssl_ctx)
    return ssl_ctx


@pytest.fixture
def tls_ca_certificate_pem_path(tls_certificate_authority: trustme.CA) -> Iterator[str]:
    with tls_certificate_authority.cert_pem.tempfile() as ca_cert_pem:
        yield ca_cert_pem


@pytest.fixture
def tls_certificate_pem_path(tls_certificate: trustme.LeafCert) -> Iterator[str]:
    with tls_certificate.private_key_and_cert_chain_pem.tempfile() as cert_pem:
        yield cert_pem


@pytest.fixture
def tls_certificate_pem_bytes(tls_certificate: trustme.LeafCert) -> bytes:
    return tls_certificate.cert_chain_pems[0].bytes()


@pytest.fixture
def tls_certificate_fingerprint_sha256(tls_certificate_pem_bytes: bytes) -> bytes:
    tls_cert_der = ssl.PEM_cert_to_DER_cert(tls_certificate_pem_bytes.decode())
    return sha256(tls_cert_der).digest()


@pytest.fixture
def pipe_name() -> str:
    name = rf"\\.\pipe\{uuid4().hex}"
    return name


@pytest.fixture
def create_mocked_conn(
    loop: asyncio.AbstractEventLoop,
) -> Iterator[Callable[[], ResponseHandler]]:
    def _proto_factory() -> Any:
        proto = mock.create_autospec(ResponseHandler, instance=True)
        proto.closed = loop.create_future()
        proto.closed.set_result(None)
        return proto

    yield _proto_factory


@pytest.fixture
def unix_sockname(
    tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[str]:
    # Generate an fs path to the UNIX domain socket for testing.

    # N.B. Different OS kernels have different fs path length limitations
    # for it. For Linux, it's 108, for HP-UX it's 92 (or higher) depending
    # on its version. For most of the BSDs (Open, Free, macOS) it's
    # mostly 104 but sometimes it can be down to 100.

    # Ref: https://github.com/aio-libs/aiohttp/issues/3572
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("requires UNIX sockets")

    max_sock_len = 92 if IS_HPUX else 108 if IS_LINUX else 100
    # Amount of bytes allocated for the UNIX socket path by OS kernel.
    # Ref: https://unix.stackexchange.com/a/367012/27133

    sock_file_name = "unix.sock"
    unique_prefix = f"{uuid4()!s}-"
    unique_prefix_len = len(unique_prefix.encode())

    root_tmp_dir = Path("/tmp").resolve()
    os_tmp_dir = Path(os.getenv("TMPDIR", "/tmp")).resolve()
    original_base_tmp_path = Path(
        str(tmp_path_factory.getbasetemp()),
    ).resolve()

    original_base_tmp_path_hash = md5(
        str(original_base_tmp_path).encode(),
    ).hexdigest()

    def make_tmp_dir(base_tmp_dir: Path) -> TemporaryDirectory[str]:
        return TemporaryDirectory(
            dir=str(base_tmp_dir),
            prefix="pt-",
            suffix=f"-{original_base_tmp_path_hash!s}",
        )

    def assert_sock_fits(sock_path: str) -> None:
        sock_path_len = len(sock_path.encode())
        # exit-check to verify that it's correct and simplify debugging
        # in the future
        assert sock_path_len <= max_sock_len, (
            "Suggested UNIX socket ({sock_path}) is {sock_path_len} bytes "
            "long but the current kernel only has {max_sock_len} bytes "
            "allocated to hold it so it must be shorter. "
            "See https://github.com/aio-libs/aiohttp/issues/3572 "
            "for more info."
        ).format_map(locals())

    paths = original_base_tmp_path, os_tmp_dir, root_tmp_dir
    unique_paths = [p for n, p in enumerate(paths) if p not in paths[:n]]
    paths_num = len(unique_paths)

    for num, tmp_dir_path in enumerate(paths, 1):
        with make_tmp_dir(tmp_dir_path) as tmps:
            tmpd = Path(tmps).resolve()
            sock_path = str(tmpd / sock_file_name)
            sock_path_len = len(sock_path.encode())

            if num >= paths_num:
                # exit-check to verify that it's correct and simplify
                # debugging in the future
                assert_sock_fits(sock_path)

            if sock_path_len <= max_sock_len:
                if max_sock_len - sock_path_len >= unique_prefix_len:
                    # If we're lucky to have extra space in the path,
                    # let's also make it more unique
                    sock_path = str(tmpd / "".join((unique_prefix, sock_file_name)))
                    # Double-checking it:
                    assert_sock_fits(sock_path)
                yield sock_path
                return


@pytest.fixture
def selector_loop() -> Iterator[asyncio.AbstractEventLoop]:
    policy = asyncio.WindowsSelectorEventLoopPolicy()  # type: ignore[attr-defined]
    asyncio.set_event_loop_policy(policy)

    with loop_context(policy.new_event_loop) as _loop:
        asyncio.set_event_loop(_loop)
        yield _loop


@pytest.fixture
def netrc_contents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> Path:
    """
    Prepare :file:`.netrc` with given contents.

    Monkey-patches :envvar:`NETRC` to point to created file.
    """
    netrc_contents = getattr(request, "param", None)

    netrc_file_path = tmp_path / ".netrc"
    if netrc_contents is not None:
        netrc_file_path.write_text(netrc_contents)

    monkeypatch.setenv("NETRC", str(netrc_file_path))

    return netrc_file_path


@pytest.fixture
def start_connection() -> Iterator[mock.Mock]:
    with mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        autospec=True,
        spec_set=True,
    ) as start_connection_mock:
        yield start_connection_mock


@pytest.fixture
def key_data() -> bytes:
    return os.urandom(16)


@pytest.fixture
def key(key_data: bytes) -> bytes:
    return base64.b64encode(key_data)


@pytest.fixture
def ws_key(key: bytes) -> str:
    return base64.b64encode(sha1(key + WS_KEY).digest()).decode()


@pytest.fixture
def enable_cleanup_closed() -> Generator[None, None, None]:
    """Fixture to override the NEEDS_CLEANUP_CLOSED flag.

    On Python 3.12.7+ and 3.13.1+ enable_cleanup_closed is not needed,
    however we still want to test that it works.
    """
    with mock.patch("aiohttp.connector.NEEDS_CLEANUP_CLOSED", True):
        yield


@pytest.fixture
def unused_port_socket() -> Generator[socket.socket, None, None]:
    """Return a socket that is unused on the current host.

    Unlike aiohttp_used_port, the socket is yielded so there is no
    race condition between checking if the port is in use and
    binding to it later in the test.
    """
    s = get_unused_port_socket("127.0.0.1")
    try:
        yield s
    finally:
        s.close()
