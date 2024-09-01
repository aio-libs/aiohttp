import errno
import pickle

import pytest
from multidict import CIMultiDict, CIMultiDictProxy
from yarl import URL

from aiohttp import client, client_reqrep


class TestClientResponseError:
    request_info = client.RequestInfo(
        url=URL("http://example.com"),
        method="GET",
        headers=CIMultiDictProxy(CIMultiDict()),
        real_url=URL("http://example.com"),
    )

    def test_default_status(self) -> None:
        err = client.ClientResponseError(history=(), request_info=self.request_info)
        assert err.status == 0

    def test_status(self) -> None:
        err = client.ClientResponseError(
            status=400, history=(), request_info=self.request_info
        )
        assert err.status == 400

    @pytest.mark.xfail(reason="CIMultiDictProxy is not pickleable")
    def test_pickle(self) -> None:
        err = client.ClientResponseError(request_info=self.request_info, history=())
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(err, proto)
            err2 = pickle.loads(pickled)
            assert err2.request_info == self.request_info
            assert err2.history == ()
            assert err2.status == 0
            assert err2.message == ""
            assert err2.headers is None

        err = client.ClientResponseError(
            request_info=self.request_info,
            history=(),
            status=400,
            message="Something wrong",
            headers=CIMultiDict(foo="bar"),
        )
        err.foo = "bar"  # type: ignore[attr-defined]
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(err, proto)
            err2 = pickle.loads(pickled)
            assert err2.request_info == self.request_info
            assert err2.history == ()
            assert err2.status == 400
            assert err2.message == "Something wrong"
            # Use headers.get() to verify static type is correct.
            assert err2.headers.get("foo") == "bar"
            assert err2.foo == "bar"

    def test_repr(self) -> None:
        err = client.ClientResponseError(request_info=self.request_info, history=())
        assert repr(err) == (f"ClientResponseError({self.request_info!r}, ())")

        err = client.ClientResponseError(
            request_info=self.request_info,
            history=(),
            status=400,
            message="Something wrong",
            headers=CIMultiDict(),
        )
        assert repr(err) == (
            "ClientResponseError(%r, (), status=400, "
            "message='Something wrong', headers=<CIMultiDict()>)" % (self.request_info,)
        )

    def test_str(self) -> None:
        err = client.ClientResponseError(
            request_info=self.request_info,
            history=(),
            status=400,
            message="Something wrong",
            headers=CIMultiDict(),
        )
        assert str(err) == ("400, message='Something wrong', url='http://example.com'")


class TestClientConnectorError:
    connection_key = client_reqrep.ConnectionKey(
        host="example.com",
        port=8080,
        is_ssl=False,
        ssl=True,
        proxy=None,
        proxy_auth=None,
        proxy_headers_hash=None,
    )

    def test_ctor(self) -> None:
        err = client.ClientConnectorError(
            connection_key=self.connection_key,
            os_error=OSError(errno.ENOENT, "No such file"),
        )
        assert err.errno == errno.ENOENT
        assert err.strerror == "No such file"
        assert err.os_error.errno == errno.ENOENT
        assert err.os_error.strerror == "No such file"
        assert err.host == "example.com"
        assert err.port == 8080
        assert err.ssl is True

    def test_pickle(self) -> None:
        err = client.ClientConnectorError(
            connection_key=self.connection_key,
            os_error=OSError(errno.ENOENT, "No such file"),
        )
        err.foo = "bar"  # type: ignore[attr-defined]
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(err, proto)
            err2 = pickle.loads(pickled)
            assert err2.errno == errno.ENOENT
            assert err2.strerror == "No such file"
            assert err2.os_error.errno == errno.ENOENT
            assert err2.os_error.strerror == "No such file"
            assert err2.host == "example.com"
            assert err2.port == 8080
            assert err2.ssl is True
            assert err2.foo == "bar"

    def test_repr(self) -> None:
        os_error = OSError(errno.ENOENT, "No such file")
        err = client.ClientConnectorError(
            connection_key=self.connection_key, os_error=os_error
        )
        assert repr(err) == (
            f"ClientConnectorError({self.connection_key!r}, {os_error!r})"
        )

    def test_str(self) -> None:
        err = client.ClientConnectorError(
            connection_key=self.connection_key,
            os_error=OSError(errno.ENOENT, "No such file"),
        )
        assert str(err) == (
            "Cannot connect to host example.com:8080 ssl:default [No such file]"
        )


class TestClientConnectorCertificateError:
    connection_key = client_reqrep.ConnectionKey(
        host="example.com",
        port=8080,
        is_ssl=False,
        ssl=True,
        proxy=None,
        proxy_auth=None,
        proxy_headers_hash=None,
    )

    def test_ctor(self) -> None:
        certificate_error = Exception("Bad certificate")
        err = client.ClientConnectorCertificateError(
            connection_key=self.connection_key, certificate_error=certificate_error
        )
        assert err.certificate_error == certificate_error
        assert err.host == "example.com"
        assert err.port == 8080
        assert err.ssl is False

    def test_pickle(self) -> None:
        certificate_error = Exception("Bad certificate")
        err = client.ClientConnectorCertificateError(
            connection_key=self.connection_key, certificate_error=certificate_error
        )
        err.foo = "bar"
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(err, proto)
            err2 = pickle.loads(pickled)
            assert err2.certificate_error.args == ("Bad certificate",)
            assert err2.host == "example.com"
            assert err2.port == 8080
            assert err2.ssl is False
            assert err2.foo == "bar"

    def test_repr(self) -> None:
        certificate_error = Exception("Bad certificate")
        err = client.ClientConnectorCertificateError(
            connection_key=self.connection_key, certificate_error=certificate_error
        )
        assert repr(err) == (
            "ClientConnectorCertificateError(%r, %r)"
            % (self.connection_key, certificate_error)
        )

    def test_str(self) -> None:
        certificate_error = Exception("Bad certificate")
        err = client.ClientConnectorCertificateError(
            connection_key=self.connection_key, certificate_error=certificate_error
        )
        assert str(err) == (
            "Cannot connect to host example.com:8080 ssl:False"
            " [Exception: ('Bad certificate',)]"
        )


class TestServerDisconnectedError:
    def test_ctor(self) -> None:
        err = client.ServerDisconnectedError()
        assert err.message == "Server disconnected"

        err = client.ServerDisconnectedError(message="No connection")
        assert err.message == "No connection"

    def test_pickle(self) -> None:
        err = client.ServerDisconnectedError(message="No connection")
        err.foo = "bar"  # type: ignore[attr-defined]
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(err, proto)
            err2 = pickle.loads(pickled)
            assert err2.message == "No connection"
            assert err2.foo == "bar"

    def test_repr(self) -> None:
        err = client.ServerDisconnectedError()
        assert repr(err) == ("ServerDisconnectedError('Server disconnected')")

        err = client.ServerDisconnectedError(message="No connection")
        assert repr(err) == "ServerDisconnectedError('No connection')"

    def test_str(self) -> None:
        err = client.ServerDisconnectedError()
        assert str(err) == "Server disconnected"

        err = client.ServerDisconnectedError(message="No connection")
        assert str(err) == "No connection"


class TestServerFingerprintMismatch:
    def test_ctor(self) -> None:
        err = client.ServerFingerprintMismatch(
            expected=b"exp", got=b"got", host="example.com", port=8080
        )
        assert err.expected == b"exp"
        assert err.got == b"got"
        assert err.host == "example.com"
        assert err.port == 8080

    def test_pickle(self) -> None:
        err = client.ServerFingerprintMismatch(
            expected=b"exp", got=b"got", host="example.com", port=8080
        )
        err.foo = "bar"  # type: ignore[attr-defined]
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(err, proto)
            err2 = pickle.loads(pickled)
            assert err2.expected == b"exp"
            assert err2.got == b"got"
            assert err2.host == "example.com"
            assert err2.port == 8080
            assert err2.foo == "bar"

    def test_repr(self) -> None:
        err = client.ServerFingerprintMismatch(b"exp", b"got", "example.com", 8080)
        assert repr(err) == (
            "<ServerFingerprintMismatch expected=b'exp' "
            "got=b'got' host='example.com' port=8080>"
        )


class TestInvalidURL:
    def test_ctor(self) -> None:
        err = client.InvalidURL(url=":wrong:url:", description=":description:")
        assert err.url == ":wrong:url:"
        assert err.description == ":description:"

    def test_pickle(self) -> None:
        err = client.InvalidURL(url=":wrong:url:")
        err.foo = "bar"  # type: ignore[attr-defined]
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(err, proto)
            err2 = pickle.loads(pickled)
            assert err2.url == ":wrong:url:"
            assert err2.foo == "bar"

    def test_repr_no_description(self) -> None:
        err = client.InvalidURL(url=":wrong:url:")
        assert err.args == (":wrong:url:",)
        assert repr(err) == "<InvalidURL :wrong:url:>"

    def test_repr_yarl_URL(self) -> None:
        err = client.InvalidURL(url=URL(":wrong:url:"))
        assert repr(err) == "<InvalidURL :wrong:url:>"

    def test_repr_with_description(self) -> None:
        err = client.InvalidURL(url=":wrong:url:", description=":description:")
        assert repr(err) == "<InvalidURL :wrong:url: - :description:>"

    def test_str_no_description(self) -> None:
        err = client.InvalidURL(url=":wrong:url:")
        assert str(err) == ":wrong:url:"

    def test_none_description(self) -> None:
        err = client.InvalidURL(":wrong:url:")
        assert err.description is None

    def test_str_with_description(self) -> None:
        err = client.InvalidURL(url=":wrong:url:", description=":description:")
        assert str(err) == ":wrong:url: - :description:"
