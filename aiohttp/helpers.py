"""Various helper functions"""

import asyncio
import base64
import binascii
import contextlib
import dataclasses
import datetime
import enum
import functools
import inspect
import netrc
import os
import platform
import re
import sys
import time
import warnings
import weakref
from collections import namedtuple
from contextlib import suppress
from email.parser import HeaderParser
from email.utils import parsedate
from http.cookies import SimpleCookie
from math import ceil
from pathlib import Path
from types import TracebackType
from typing import (
    Any,
    Callable,
    ContextManager,
    Dict,
    Generator,
    Generic,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Pattern,
    Protocol,
    Tuple,
    Type,
    TypeVar,
    Union,
    final,
    get_args,
    overload,
)
from urllib.parse import quote
from urllib.request import getproxies, proxy_bypass

from multidict import CIMultiDict, MultiDict, MultiDictProxy
from yarl import URL

from . import hdrs
from .log import client_logger
from .typedefs import PathLike  # noqa

if sys.version_info >= (3, 11):
    import asyncio as async_timeout
else:
    import async_timeout

__all__ = ("BasicAuth", "ChainMapProxy", "ETag")

PY_310 = sys.version_info >= (3, 10)

COOKIE_MAX_LENGTH = 4096

_T = TypeVar("_T")
_S = TypeVar("_S")

_SENTINEL = enum.Enum("_SENTINEL", "sentinel")
sentinel = _SENTINEL.sentinel

NO_EXTENSIONS = bool(os.environ.get("AIOHTTP_NO_EXTENSIONS"))

DEBUG = sys.flags.dev_mode or (
    not sys.flags.ignore_environment and bool(os.environ.get("PYTHONASYNCIODEBUG"))
)


CHAR = {chr(i) for i in range(0, 128)}
CTL = {chr(i) for i in range(0, 32)} | {
    chr(127),
}
SEPARATORS = {
    "(",
    ")",
    "<",
    ">",
    "@",
    ",",
    ";",
    ":",
    "\\",
    '"',
    "/",
    "[",
    "]",
    "?",
    "=",
    "{",
    "}",
    " ",
    chr(9),
}
TOKEN = CHAR ^ CTL ^ SEPARATORS


class noop:
    def __await__(self) -> Generator[None, None, None]:
        yield


json_re = re.compile(r"(?:application/|[\w.-]+/[\w.+-]+?\+)json$", re.IGNORECASE)


class BasicAuth(namedtuple("BasicAuth", ["login", "password", "encoding"])):
    """Http basic authentication helper."""

    def __new__(
        cls, login: str, password: str = "", encoding: str = "latin1"
    ) -> "BasicAuth":
        if login is None:
            raise ValueError("None is not allowed as login value")

        if password is None:
            raise ValueError("None is not allowed as password value")

        if ":" in login:
            raise ValueError('A ":" is not allowed in login (RFC 1945#section-11.1)')

        return super().__new__(cls, login, password, encoding)

    @classmethod
    def decode(cls, auth_header: str, encoding: str = "latin1") -> "BasicAuth":
        """Create a BasicAuth object from an Authorization HTTP header."""
        try:
            auth_type, encoded_credentials = auth_header.split(" ", 1)
        except ValueError:
            raise ValueError("Could not parse authorization header.")

        if auth_type.lower() != "basic":
            raise ValueError("Unknown authorization method %s" % auth_type)

        try:
            decoded = base64.b64decode(
                encoded_credentials.encode("ascii"), validate=True
            ).decode(encoding)
        except binascii.Error:
            raise ValueError("Invalid base64 encoding.")

        try:
            # RFC 2617 HTTP Authentication
            # https://www.ietf.org/rfc/rfc2617.txt
            # the colon must be present, but the username and password may be
            # otherwise blank.
            username, password = decoded.split(":", 1)
        except ValueError:
            raise ValueError("Invalid credentials.")

        return cls(username, password, encoding=encoding)

    @classmethod
    def from_url(cls, url: URL, *, encoding: str = "latin1") -> Optional["BasicAuth"]:
        """Create BasicAuth from url."""
        if not isinstance(url, URL):
            raise TypeError("url should be yarl.URL instance")
        if url.user is None:
            return None
        return cls(url.user, url.password or "", encoding=encoding)

    def encode(self) -> str:
        """Encode credentials."""
        creds = (f"{self.login}:{self.password}").encode(self.encoding)
        return "Basic %s" % base64.b64encode(creds).decode(self.encoding)


def strip_auth_from_url(url: URL) -> Tuple[URL, Optional[BasicAuth]]:
    auth = BasicAuth.from_url(url)
    if auth is None:
        return url, None
    else:
        return url.with_user(None), auth


def netrc_from_env() -> Optional[netrc.netrc]:
    """Load netrc from file.

    Attempt to load it from the path specified by the env-var
    NETRC or in the default location in the user's home directory.

    Returns None if it couldn't be found or fails to parse.
    """
    netrc_env = os.environ.get("NETRC")

    if netrc_env is not None:
        netrc_path = Path(netrc_env)
    else:
        try:
            home_dir = Path.home()
        except RuntimeError as e:  # pragma: no cover
            # if pathlib can't resolve home, it may raise a RuntimeError
            client_logger.debug(
                "Could not resolve home directory when "
                "trying to look for .netrc file: %s",
                e,
            )
            return None

        netrc_path = home_dir / (
            "_netrc" if platform.system() == "Windows" else ".netrc"
        )

    try:
        return netrc.netrc(str(netrc_path))
    except netrc.NetrcParseError as e:
        client_logger.warning("Could not parse .netrc file: %s", e)
    except OSError as e:
        netrc_exists = False
        with contextlib.suppress(OSError):
            netrc_exists = netrc_path.is_file()
        # we couldn't read the file (doesn't exist, permissions, etc.)
        if netrc_env or netrc_exists:
            # only warn if the environment wanted us to load it,
            # or it appears like the default file does actually exist
            client_logger.warning("Could not read .netrc file: %s", e)

    return None


@dataclasses.dataclass(frozen=True)
class ProxyInfo:
    proxy: URL
    proxy_auth: Optional[BasicAuth]


def basicauth_from_netrc(netrc_obj: Optional[netrc.netrc], host: str) -> BasicAuth:
    """
    Return :py:class:`~aiohttp.BasicAuth` credentials for ``host`` from ``netrc_obj``.

    :raises LookupError: if ``netrc_obj`` is :py:data:`None` or if no
            entry is found for the ``host``.
    """
    if netrc_obj is None:
        raise LookupError("No .netrc file found")
    auth_from_netrc = netrc_obj.authenticators(host)

    if auth_from_netrc is None:
        raise LookupError(f"No entry for {host!s} found in the `.netrc` file.")
    login, account, password = auth_from_netrc

    # TODO(PY311): username = login or account
    # Up to python 3.10, account could be None if not specified,
    # and login will be empty string if not specified. From 3.11,
    # login and account will be empty string if not specified.
    username = login if (login or account is None) else account

    # TODO(PY311): Remove this, as password will be empty string
    # if not specified
    if password is None:
        password = ""

    return BasicAuth(username, password)


def proxies_from_env() -> Dict[str, ProxyInfo]:
    proxy_urls = {
        k: URL(v)
        for k, v in getproxies().items()
        if k in ("http", "https", "ws", "wss")
    }
    netrc_obj = netrc_from_env()
    stripped = {k: strip_auth_from_url(v) for k, v in proxy_urls.items()}
    ret = {}
    for proto, val in stripped.items():
        proxy, auth = val
        if proxy.scheme in ("https", "wss"):
            client_logger.warning(
                "%s proxies %s are not supported, ignoring", proxy.scheme.upper(), proxy
            )
            continue
        if netrc_obj and auth is None:
            if proxy.host is not None:
                try:
                    auth = basicauth_from_netrc(netrc_obj, proxy.host)
                except LookupError:
                    auth = None
        ret[proto] = ProxyInfo(proxy, auth)
    return ret


def get_env_proxy_for_url(url: URL) -> Tuple[URL, Optional[BasicAuth]]:
    """Get a permitted proxy for the given URL from the env."""
    if url.host is not None and proxy_bypass(url.host):
        raise LookupError(f"Proxying is disallowed for `{url.host!r}`")

    proxies_in_env = proxies_from_env()
    try:
        proxy_info = proxies_in_env[url.scheme]
    except KeyError:
        raise LookupError(f"No proxies found for `{url!s}` in the env")
    else:
        return proxy_info.proxy, proxy_info.proxy_auth


@dataclasses.dataclass(frozen=True)
class MimeType:
    type: str
    subtype: str
    suffix: str
    parameters: "MultiDictProxy[str]"


@functools.lru_cache(maxsize=56)
def parse_mimetype(mimetype: str) -> MimeType:
    """Parses a MIME type into its components.

    mimetype is a MIME type string.

    Returns a MimeType object.

    Example:

    >>> parse_mimetype('text/html; charset=utf-8')
    MimeType(type='text', subtype='html', suffix='',
             parameters={'charset': 'utf-8'})

    """
    if not mimetype:
        return MimeType(
            type="", subtype="", suffix="", parameters=MultiDictProxy(MultiDict())
        )

    parts = mimetype.split(";")
    params: MultiDict[str] = MultiDict()
    for item in parts[1:]:
        if not item:
            continue
        key, _, value = item.partition("=")
        params.add(key.lower().strip(), value.strip(' "'))

    fulltype = parts[0].strip().lower()
    if fulltype == "*":
        fulltype = "*/*"

    mtype, _, stype = fulltype.partition("/")
    stype, _, suffix = stype.partition("+")

    return MimeType(
        type=mtype, subtype=stype, suffix=suffix, parameters=MultiDictProxy(params)
    )


def guess_filename(obj: Any, default: Optional[str] = None) -> Optional[str]:
    name = getattr(obj, "name", None)
    if name and isinstance(name, str) and name[0] != "<" and name[-1] != ">":
        return Path(name).name
    return default


not_qtext_re = re.compile(r"[^\041\043-\133\135-\176]")
QCONTENT = {chr(i) for i in range(0x20, 0x7F)} | {"\t"}


def quoted_string(content: str) -> str:
    """Return 7-bit content as quoted-string.

    Format content into a quoted-string as defined in RFC5322 for
    Internet Message Format. Notice that this is not the 8-bit HTTP
    format, but the 7-bit email format. Content must be in usascii or
    a ValueError is raised.
    """
    if not (QCONTENT > set(content)):
        raise ValueError(f"bad content for quoted-string {content!r}")
    return not_qtext_re.sub(lambda x: "\\" + x.group(0), content)


def content_disposition_header(
    disptype: str, quote_fields: bool = True, _charset: str = "utf-8", **params: str
) -> str:
    """Sets ``Content-Disposition`` header for MIME.

    This is the MIME payload Content-Disposition header from RFC 2183
    and RFC 7579 section 4.2, not the HTTP Content-Disposition from
    RFC 6266.

    disptype is a disposition type: inline, attachment, form-data.
    Should be valid extension token (see RFC 2183)

    quote_fields performs value quoting to 7-bit MIME headers
    according to RFC 7578. Set to quote_fields to False if recipient
    can take 8-bit file names and field values.

    _charset specifies the charset to use when quote_fields is True.

    params is a dict with disposition params.
    """
    if not disptype or not (TOKEN > set(disptype)):
        raise ValueError("bad content disposition type {!r}" "".format(disptype))

    value = disptype
    if params:
        lparams = []
        for key, val in params.items():
            if not key or not (TOKEN > set(key)):
                raise ValueError(
                    "bad content disposition parameter" " {!r}={!r}".format(key, val)
                )
            if quote_fields:
                if key.lower() == "filename":
                    qval = quote(val, "", encoding=_charset)
                    lparams.append((key, '"%s"' % qval))
                else:
                    try:
                        qval = quoted_string(val)
                    except ValueError:
                        qval = "".join(
                            (_charset, "''", quote(val, "", encoding=_charset))
                        )
                        lparams.append((key + "*", qval))
                    else:
                        lparams.append((key, '"%s"' % qval))
            else:
                qval = val.replace("\\", "\\\\").replace('"', '\\"')
                lparams.append((key, '"%s"' % qval))
        sparams = "; ".join("=".join(pair) for pair in lparams)
        value = "; ".join((value, sparams))
    return value


def is_expected_content_type(
    response_content_type: str, expected_content_type: str
) -> bool:
    """Checks if received content type is processable as an expected one.

    Both arguments should be given without parameters.
    """
    if expected_content_type == "application/json":
        return json_re.match(response_content_type) is not None
    return expected_content_type in response_content_type


class _TSelf(Protocol, Generic[_T]):
    _cache: Dict[str, _T]


class reify(Generic[_T]):
    """Use as a class method decorator.

    It operates almost exactly like
    the Python `@property` decorator, but it puts the result of the
    method it decorates into the instance dict after the first call,
    effectively replacing the function it decorates with an instance
    variable.  It is, in Python parlance, a data descriptor.
    """

    def __init__(self, wrapped: Callable[..., _T]) -> None:
        self.wrapped = wrapped
        self.__doc__ = wrapped.__doc__
        self.name = wrapped.__name__

    def __get__(self, inst: _TSelf[_T], owner: Optional[Type[Any]] = None) -> _T:
        try:
            try:
                return inst._cache[self.name]
            except KeyError:
                val = self.wrapped(inst)
                inst._cache[self.name] = val
                return val
        except AttributeError:
            if inst is None:
                return self
            raise

    def __set__(self, inst: _TSelf[_T], value: _T) -> None:
        raise AttributeError("reified property is read-only")


reify_py = reify

try:
    from ._helpers import reify as reify_c

    if not NO_EXTENSIONS:
        reify = reify_c  # type: ignore[misc,assignment]
except ImportError:
    pass

_ipv4_pattern = (
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
_ipv6_pattern = (
    r"^(?:(?:(?:[A-F0-9]{1,4}:){6}|(?=(?:[A-F0-9]{0,4}:){0,6}"
    r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}$)(([0-9A-F]{1,4}:){0,5}|:)"
    r"((:[0-9A-F]{1,4}){1,5}:|:)|::(?:[A-F0-9]{1,4}:){5})"
    r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])|(?:[A-F0-9]{1,4}:){7}"
    r"[A-F0-9]{1,4}|(?=(?:[A-F0-9]{0,4}:){0,7}[A-F0-9]{0,4}$)"
    r"(([0-9A-F]{1,4}:){1,7}|:)((:[0-9A-F]{1,4}){1,7}|:)|(?:[A-F0-9]{1,4}:){7}"
    r":|:(:[A-F0-9]{1,4}){7})$"
)
_ipv4_regex = re.compile(_ipv4_pattern)
_ipv6_regex = re.compile(_ipv6_pattern, flags=re.IGNORECASE)
_ipv4_regexb = re.compile(_ipv4_pattern.encode("ascii"))
_ipv6_regexb = re.compile(_ipv6_pattern.encode("ascii"), flags=re.IGNORECASE)


def _is_ip_address(
    regex: Pattern[str], regexb: Pattern[bytes], host: Optional[Union[str, bytes]]
) -> bool:
    if host is None:
        return False
    if isinstance(host, str):
        return bool(regex.match(host))
    elif isinstance(host, (bytes, bytearray, memoryview)):
        return bool(regexb.match(host))
    else:
        raise TypeError(f"{host} [{type(host)}] is not a str or bytes")


is_ipv4_address = functools.partial(_is_ip_address, _ipv4_regex, _ipv4_regexb)
is_ipv6_address = functools.partial(_is_ip_address, _ipv6_regex, _ipv6_regexb)


def is_ip_address(host: Optional[Union[str, bytes, bytearray, memoryview]]) -> bool:
    return is_ipv4_address(host) or is_ipv6_address(host)


def next_whole_second() -> datetime.datetime:
    """Return current time rounded up to the next whole second."""
    return datetime.datetime.now(datetime.timezone.utc).replace(
        microsecond=0
    ) + datetime.timedelta(seconds=0)


_cached_current_datetime: Optional[int] = None
_cached_formatted_datetime = ""


def rfc822_formatted_time() -> str:
    global _cached_current_datetime
    global _cached_formatted_datetime

    now = int(time.time())
    if now != _cached_current_datetime:
        # Weekday and month names for HTTP date/time formatting;
        # always English!
        # Tuples are constants stored in codeobject!
        _weekdayname = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
        _monthname = (
            "",  # Dummy so we can use 1-based month numbers
            "Jan",
            "Feb",
            "Mar",
            "Apr",
            "May",
            "Jun",
            "Jul",
            "Aug",
            "Sep",
            "Oct",
            "Nov",
            "Dec",
        )

        year, month, day, hh, mm, ss, wd, *tail = time.gmtime(now)
        _cached_formatted_datetime = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
            _weekdayname[wd],
            day,
            _monthname[month],
            year,
            hh,
            mm,
            ss,
        )
        _cached_current_datetime = now
    return _cached_formatted_datetime


def _weakref_handle(info: "Tuple[weakref.ref[object], str]") -> None:
    ref, name = info
    ob = ref()
    if ob is not None:
        with suppress(Exception):
            getattr(ob, name)()


def weakref_handle(
    ob: object,
    name: str,
    timeout: Optional[float],
    loop: asyncio.AbstractEventLoop,
    timeout_ceil_threshold: float = 5,
) -> Optional[asyncio.TimerHandle]:
    if timeout is not None and timeout > 0:
        when = loop.time() + timeout
        if timeout >= timeout_ceil_threshold:
            when = ceil(when)

        return loop.call_at(when, _weakref_handle, (weakref.ref(ob), name))
    return None


def call_later(
    cb: Callable[[], Any],
    timeout: Optional[float],
    loop: asyncio.AbstractEventLoop,
    timeout_ceil_threshold: float = 5,
) -> Optional[asyncio.TimerHandle]:
    if timeout is not None and timeout > 0:
        when = loop.time() + timeout
        if timeout > timeout_ceil_threshold:
            when = ceil(when)
        return loop.call_at(when, cb)
    return None


class TimeoutHandle:
    """Timeout handle"""

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        timeout: Optional[float],
        ceil_threshold: float = 5,
    ) -> None:
        self._timeout = timeout
        self._loop = loop
        self._ceil_threshold = ceil_threshold
        self._callbacks: List[
            Tuple[Callable[..., None], Tuple[Any, ...], Dict[str, Any]]
        ] = []

    def register(
        self, callback: Callable[..., None], *args: Any, **kwargs: Any
    ) -> None:
        self._callbacks.append((callback, args, kwargs))

    def close(self) -> None:
        self._callbacks.clear()

    def start(self) -> Optional[asyncio.Handle]:
        timeout = self._timeout
        if timeout is not None and timeout > 0:
            when = self._loop.time() + timeout
            if timeout >= self._ceil_threshold:
                when = ceil(when)
            return self._loop.call_at(when, self.__call__)
        else:
            return None

    def timer(self) -> "BaseTimerContext":
        if self._timeout is not None and self._timeout > 0:
            timer = TimerContext(self._loop)
            self.register(timer.timeout)
            return timer
        else:
            return TimerNoop()

    def __call__(self) -> None:
        for cb, args, kwargs in self._callbacks:
            with suppress(Exception):
                cb(*args, **kwargs)

        self._callbacks.clear()


class BaseTimerContext(ContextManager["BaseTimerContext"]):
    def assert_timeout(self) -> None:
        """Raise TimeoutError if timeout has been exceeded."""


class TimerNoop(BaseTimerContext):
    def __enter__(self) -> BaseTimerContext:
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        return


class TimerContext(BaseTimerContext):
    """Low resolution timeout context manager"""

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._tasks: List[asyncio.Task[Any]] = []
        self._cancelled = False

    def assert_timeout(self) -> None:
        """Raise TimeoutError if timer has already been cancelled."""
        if self._cancelled:
            raise asyncio.TimeoutError from None

    def __enter__(self) -> BaseTimerContext:
        task = asyncio.current_task(loop=self._loop)

        if task is None:
            raise RuntimeError(
                "Timeout context manager should be used inside a task"
            )

        if self._cancelled:
            raise asyncio.TimeoutError from None

        self._tasks.append(task)
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> Optional[bool]:
        if self._tasks:
            self._tasks.pop()  # type: ignore[unused-awaitable]

        if exc_type is asyncio.CancelledError and self._cancelled:
            raise asyncio.TimeoutError from None
        return None

    def timeout(self) -> None:
        if not self._cancelled:
            for task in set(self._tasks):
                task.cancel()

            self._cancelled = True


def ceil_timeout(
    delay: Optional[float], ceil_threshold: float = 5
) -> async_timeout.Timeout:
    if delay is None or delay <= 0:
        return async_timeout.timeout(None)

    loop = asyncio.get_running_loop()
    now = loop.time()
    when = now + delay
    if delay > ceil_threshold:
        when = ceil(when)
    return async_timeout.timeout_at(when)


class HeadersMixin:
    __slots__ = ("_content_type", "_content_dict", "_stored_content_type")

    def __init__(self) -> None:
        super().__init__()
        self._content_type: Optional[str] = None
        self._content_dict: Optional[Dict[str, str]] = None
        self._stored_content_type: Union[str, _SENTINEL] = sentinel

    def _parse_content_type(self, raw: str) -> None:
        self._stored_content_type = raw
        if raw is None:
            # default value according to RFC 2616
            self._content_type = "application/octet-stream"
            self._content_dict = {}
        else:
            msg = HeaderParser().parsestr("Content-Type: " + raw)
            self._content_type = msg.get_content_type()
            params = msg.get_params(())
            self._content_dict = dict(params[1:])  # First element is content type again

    @property
    def content_type(self) -> str:
        """The value of content part for Content-Type HTTP header."""
        raw = self._headers.get(hdrs.CONTENT_TYPE)  # type: ignore[attr-defined]
        if self._stored_content_type != raw:
            self._parse_content_type(raw)
        return self._content_type  # type: ignore[return-value]

    @property
    def charset(self) -> Optional[str]:
        """The value of charset part for Content-Type HTTP header."""
        raw = self._headers.get(hdrs.CONTENT_TYPE)  # type: ignore[attr-defined]
        if self._stored_content_type != raw:
            self._parse_content_type(raw)
        return self._content_dict.get("charset")  # type: ignore[union-attr]

    @property
    def content_length(self) -> Optional[int]:
        """The value of Content-Length HTTP header."""
        content_length = self._headers.get(  # type: ignore[attr-defined]
            hdrs.CONTENT_LENGTH
        )

        if content_length is not None:
            return int(content_length)
        else:
            return None


def set_result(fut: "asyncio.Future[_T]", result: _T) -> None:
    if not fut.done():
        fut.set_result(result)


def set_exception(fut: "asyncio.Future[_T]", exc: BaseException) -> None:
    if not fut.done():
        fut.set_exception(exc)


@functools.total_ordering
class AppKey(Generic[_T]):
    """Keys for static typing support in Application."""

    __slots__ = ("_name", "_t", "__orig_class__")

    # This may be set by Python when instantiating with a generic type. We need to
    # support this, in order to support types that are not concrete classes,
    # like Iterable, which can't be passed as the second parameter to __init__.
    __orig_class__: Type[object]

    def __init__(self, name: str, t: Optional[Type[_T]] = None):
        # Prefix with module name to help deduplicate key names.
        frame = inspect.currentframe()
        while frame:
            if frame.f_code.co_name == "<module>":
                module: str = frame.f_globals["__name__"]
                break
            frame = frame.f_back
        else:
            raise RuntimeError("Failed to get module name.")

        # https://github.com/python/mypy/issues/14209
        self._name = module + "." + name  # type: ignore[possibly-undefined]
        self._t = t

    def __lt__(self, other: object) -> bool:
        if isinstance(other, AppKey):
            return self._name < other._name
        return True  # Order AppKey above other types.

    def __repr__(self) -> str:
        t = self._t
        if t is None:
            with suppress(AttributeError):
                # Set to type arg.
                t = get_args(self.__orig_class__)[0]

        if t is None:
            t_repr = "<<Unkown>>"
        elif isinstance(t, type):
            if t.__module__ == "builtins":
                t_repr = t.__qualname__
            else:
                t_repr = f"{t.__module__}.{t.__qualname__}"
        else:
            t_repr = repr(t)
        return f"<AppKey({self._name}, type={t_repr})>"


@final
class ChainMapProxy(Mapping[Union[str, AppKey[Any]], Any]):
    __slots__ = ("_maps",)

    def __init__(self, maps: Iterable[Mapping[Union[str, AppKey[Any]], Any]]) -> None:
        self._maps = tuple(maps)

    def __init_subclass__(cls) -> None:
        raise TypeError(
            "Inheritance class {} from ChainMapProxy "
            "is forbidden".format(cls.__name__)
        )

    @overload  # type: ignore[override]
    def __getitem__(self, key: AppKey[_T]) -> _T:
        ...

    @overload
    def __getitem__(self, key: str) -> Any:
        ...

    def __getitem__(self, key: Union[str, AppKey[_T]]) -> Any:
        for mapping in self._maps:
            try:
                return mapping[key]
            except KeyError:
                pass
        raise KeyError(key)

    @overload  # type: ignore[override]
    def get(self, key: AppKey[_T], default: _S) -> Union[_T, _S]:
        ...

    @overload
    def get(self, key: AppKey[_T], default: None = ...) -> Optional[_T]:
        ...

    @overload
    def get(self, key: str, default: Any = ...) -> Any:
        ...

    def get(self, key: Union[str, AppKey[_T]], default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def __len__(self) -> int:
        # reuses stored hash values if possible
        return len(set().union(*self._maps))

    def __iter__(self) -> Iterator[Union[str, AppKey[Any]]]:
        d: Dict[Union[str, AppKey[Any]], Any] = {}
        for mapping in reversed(self._maps):
            # reuses stored hash values if possible
            d.update(mapping)
        return iter(d)

    def __contains__(self, key: object) -> bool:
        return any(key in m for m in self._maps)

    def __bool__(self) -> bool:
        return any(self._maps)

    def __repr__(self) -> str:
        content = ", ".join(map(repr, self._maps))
        return f"ChainMapProxy({content})"


class CookieMixin:
    # The `_cookies` slots is not defined here because non-empty slots cannot
    # be combined with an Exception base class, as is done in HTTPException.
    # CookieMixin subclasses with slots should define the `_cookies`
    # slot themselves.
    __slots__ = ()

    def __init__(self) -> None:
        super().__init__()
        # Mypy doesn't like that _cookies isn't in __slots__.
        # See the comment on this class's __slots__ for why this is OK.
        self._cookies: SimpleCookie[str] = SimpleCookie()  # type: ignore[misc]

    @property
    def cookies(self) -> "SimpleCookie[str]":
        return self._cookies

    def set_cookie(
        self,
        name: str,
        value: str,
        *,
        expires: Optional[str] = None,
        domain: Optional[str] = None,
        max_age: Optional[Union[int, str]] = None,
        path: str = "/",
        secure: Optional[bool] = None,
        httponly: Optional[bool] = None,
        version: Optional[str] = None,
        samesite: Optional[str] = None,
    ) -> None:
        """Set or update response cookie.

        Sets new cookie or updates existent with new value.
        Also updates only those params which are not None.
        """
        old = self._cookies.get(name)
        if old is not None and old.coded_value == "":
            # deleted cookie
            self._cookies.pop(name, None)

        self._cookies[name] = value
        c = self._cookies[name]

        if expires is not None:
            c["expires"] = expires
        elif c.get("expires") == "Thu, 01 Jan 1970 00:00:00 GMT":
            del c["expires"]

        if domain is not None:
            c["domain"] = domain

        if max_age is not None:
            c["max-age"] = str(max_age)
        elif "max-age" in c:
            del c["max-age"]

        c["path"] = path

        if secure is not None:
            c["secure"] = secure
        if httponly is not None:
            c["httponly"] = httponly
        if version is not None:
            c["version"] = version
        if samesite is not None:
            c["samesite"] = samesite

        if DEBUG:
            cookie_length = len(c.output(header="")[1:])
            if cookie_length > COOKIE_MAX_LENGTH:
                warnings.warn(
                    "The size of is too large, it might get ignored by the client.",
                    UserWarning,
                    stacklevel=2,
                )

    def del_cookie(
        self, name: str, *, domain: Optional[str] = None, path: str = "/"
    ) -> None:
        """Delete cookie.

        Creates new empty expired cookie.
        """
        # TODO: do we need domain/path here?
        self._cookies.pop(name, None)
        self.set_cookie(
            name,
            "",
            max_age=0,
            expires="Thu, 01 Jan 1970 00:00:00 GMT",
            domain=domain,
            path=path,
        )


def populate_with_cookies(
    headers: "CIMultiDict[str]", cookies: "SimpleCookie[str]"
) -> None:
    for cookie in cookies.values():
        value = cookie.output(header="")[1:]
        headers.add(hdrs.SET_COOKIE, value)


# https://tools.ietf.org/html/rfc7232#section-2.3
_ETAGC = r"[!#-}\x80-\xff]+"
_ETAGC_RE = re.compile(_ETAGC)
_QUOTED_ETAG = rf'(W/)?"({_ETAGC})"'
QUOTED_ETAG_RE = re.compile(_QUOTED_ETAG)
LIST_QUOTED_ETAG_RE = re.compile(rf"({_QUOTED_ETAG})(?:\s*,\s*|$)|(.)")

ETAG_ANY = "*"


@dataclasses.dataclass(frozen=True)
class ETag:
    value: str
    is_weak: bool = False


def validate_etag_value(value: str) -> None:
    if value != ETAG_ANY and not _ETAGC_RE.fullmatch(value):
        raise ValueError(
            f"Value {value!r} is not a valid etag. Maybe it contains '\"'?"
        )


def parse_http_date(date_str: Optional[str]) -> Optional[datetime.datetime]:
    """Process a date string, return a datetime object"""
    if date_str is not None:
        timetuple = parsedate(date_str)
        if timetuple is not None:
            with suppress(ValueError):
                return datetime.datetime(*timetuple[:6], tzinfo=datetime.timezone.utc)
    return None
