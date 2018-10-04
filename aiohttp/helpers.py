"""Various helper functions"""

import asyncio
import base64
import binascii
import cgi
import datetime
import functools
import inspect
import logging
import netrc
import os
import re
import sys
import time
import weakref
from collections import namedtuple
from contextlib import suppress
from math import ceil
from pathlib import Path
from types import TracebackType
from typing import (TYPE_CHECKING, Any, Callable, Dict, Iterable, Iterator,
                    List, Mapping, Optional, Pattern, Tuple, Type, TypeVar,
                    Union, cast)
from urllib.parse import quote
from urllib.request import getproxies

import async_timeout
import attr
from multidict import MultiDict
from yarl import URL

from . import hdrs
from .abc import AbstractAccessLogger
from .log import client_logger
from .typedefs import PathLike  # noqa


__all__ = ('BasicAuth', 'ChainMapProxy')

PY_36 = sys.version_info >= (3, 6)
PY_37 = sys.version_info >= (3, 7)

if not PY_37:
    import idna_ssl
    idna_ssl.patch_match_hostname()

try:
    from typing import ContextManager
except ImportError:
    from typing_extensions import ContextManager


if TYPE_CHECKING:  # pragma: no cover
    # run in mypy mode only to prevent circular imports
    from .web_request import BaseRequest  # noqa
    from .web_response import StreamResponse  # noqa


_T = TypeVar('_T')


sentinel = object()  # type: Any
NO_EXTENSIONS = bool(os.environ.get('AIOHTTP_NO_EXTENSIONS'))  # type: bool

# N.B. sys.flags.dev_mode is available on Python 3.7+, use getattr
# for compatibility with older versions
DEBUG = (getattr(sys.flags, 'dev_mode', False) or
         (not sys.flags.ignore_environment and
          bool(os.environ.get('PYTHONASYNCIODEBUG'))))


CHAR = set(chr(i) for i in range(0, 128))
CTL = set(chr(i) for i in range(0, 32)) | {chr(127), }
SEPARATORS = {'(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']',
              '?', '=', '{', '}', ' ', chr(9)}
TOKEN = CHAR ^ CTL ^ SEPARATORS


coroutines = asyncio.coroutines
old_debug = coroutines._DEBUG  # type: ignore

# prevent "coroutine noop was never awaited" warning.
coroutines._DEBUG = False  # type: ignore


@asyncio.coroutine
def noop(*args, **kwargs):  # type: ignore
    return  # type: ignore


coroutines._DEBUG = old_debug  # type: ignore


class BasicAuth(namedtuple('BasicAuth', ['login', 'password', 'encoding'])):
    """Http basic authentication helper."""

    def __new__(cls, login: str,
                password: str='',
                encoding: str='latin1') -> 'BasicAuth':
        if login is None:
            raise ValueError('None is not allowed as login value')

        if password is None:
            raise ValueError('None is not allowed as password value')

        if ':' in login:
            raise ValueError(
                'A ":" is not allowed in login (RFC 1945#section-11.1)')

        return super().__new__(cls, login, password, encoding)

    @classmethod
    def decode(cls, auth_header: str, encoding: str='latin1') -> 'BasicAuth':
        """Create a BasicAuth object from an Authorization HTTP header."""
        try:
            auth_type, encoded_credentials = auth_header.split(' ', 1)
        except ValueError:
            raise ValueError('Could not parse authorization header.')

        if auth_type.lower() != 'basic':
            raise ValueError('Unknown authorization method %s' % auth_type)

        try:
            decoded = base64.b64decode(
                encoded_credentials.encode('ascii'), validate=True
            ).decode(encoding)
        except binascii.Error:
            raise ValueError('Invalid base64 encoding.')

        try:
            # RFC 2617 HTTP Authentication
            # https://www.ietf.org/rfc/rfc2617.txt
            # the colon must be present, but the username and password may be
            # otherwise blank.
            username, password = decoded.split(':', 1)
        except ValueError:
            raise ValueError('Invalid credentials.')

        return cls(username, password, encoding=encoding)

    @classmethod
    def from_url(cls, url: URL,
                 *, encoding: str='latin1') -> Optional['BasicAuth']:
        """Create BasicAuth from url."""
        if not isinstance(url, URL):
            raise TypeError("url should be yarl.URL instance")
        if url.user is None:
            return None
        return cls(url.user, url.password or '', encoding=encoding)

    def encode(self) -> str:
        """Encode credentials."""
        creds = ('%s:%s' % (self.login, self.password)).encode(self.encoding)
        return 'Basic %s' % base64.b64encode(creds).decode(self.encoding)


def strip_auth_from_url(url: URL) -> Tuple[URL, Optional[BasicAuth]]:
    auth = BasicAuth.from_url(url)
    if auth is None:
        return url, None
    else:
        return url.with_user(None), auth


def netrc_from_env() -> Optional[netrc.netrc]:
    netrc_obj = None
    netrc_path = os.environ.get('NETRC')  # type: Optional[PathLike]
    try:
        if netrc_path is not None:
            netrc_path = Path(netrc_path)
        else:
            home_dir = Path.home()
            if os.name == 'nt':  # pragma: no cover
                netrc_path = home_dir.joinpath('_netrc')
            else:
                netrc_path = home_dir.joinpath('.netrc')

        if netrc_path and netrc_path.is_file():
            try:
                netrc_obj = netrc.netrc(str(netrc_path))
            except (netrc.NetrcParseError, OSError) as e:
                client_logger.warning(".netrc file parses fail: %s", e)

        if netrc_obj is None:
            client_logger.warning("could't find .netrc file")
    except RuntimeError as e:  # pragma: no cover
        """ handle error raised by pathlib """
        client_logger.warning("could't find .netrc file: %s", e)
    return netrc_obj


@attr.s(frozen=True, slots=True)
class ProxyInfo:
    proxy = attr.ib(type=URL)
    proxy_auth = attr.ib(type=Optional[BasicAuth])


def proxies_from_env() -> Dict[str, ProxyInfo]:
    proxy_urls = {k: URL(v) for k, v in getproxies().items()
                  if k in ('http', 'https')}
    netrc_obj = netrc_from_env()
    stripped = {k: strip_auth_from_url(v) for k, v in proxy_urls.items()}
    ret = {}
    for proto, val in stripped.items():
        proxy, auth = val
        if proxy.scheme == 'https':
            client_logger.warning(
                "HTTPS proxies %s are not supported, ignoring", proxy)
            continue
        if netrc_obj and auth is None:
            auth_from_netrc = None
            if proxy.host is not None:
                auth_from_netrc = netrc_obj.authenticators(proxy.host)
            if auth_from_netrc is not None:
                # auth_from_netrc is a (`user`, `account`, `password`) tuple,
                # `user` and `account` both can be username,
                # if `user` is None, use `account`
                *logins, password = auth_from_netrc
                auth = BasicAuth(logins[0] if logins[0] else logins[-1],
                                 password, 'latin1')
        ret[proto] = ProxyInfo(proxy, auth)
    return ret


def current_task(loop: Optional[asyncio.AbstractEventLoop]=None) -> asyncio.Task:  # type: ignore  # noqa  # Return type is intentionly Generic here
    if PY_37:
        return asyncio.current_task(loop=loop)  # type: ignore
    else:
        return asyncio.Task.current_task(loop=loop)  # type: ignore


def isasyncgenfunction(obj: Any) -> bool:
    func = getattr(inspect, 'isasyncgenfunction', None)
    if func is not None:
        return func(obj)
    else:
        return False


@attr.s(frozen=True, slots=True)
class MimeType:
    type = attr.ib(type=str)
    subtype = attr.ib(type=str)
    suffix = attr.ib(type=str)
    parameters = attr.ib(type=MultiDict)  # type: MultiDict[str]


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
        return MimeType(type='', subtype='', suffix='', parameters=MultiDict())

    parts = mimetype.split(';')
    params_lst = []
    for item in parts[1:]:
        if not item:
            continue
        key, value = cast(Tuple[str, str],
                          item.split('=', 1) if '=' in item else (item, ''))
        params_lst.append((key.lower().strip(), value.strip(' "')))
    params = MultiDict(params_lst)

    fulltype = parts[0].strip().lower()
    if fulltype == '*':
        fulltype = '*/*'

    mtype, stype = (cast(Tuple[str, str], fulltype.split('/', 1))
                    if '/' in fulltype else (fulltype, ''))
    stype, suffix = (cast(Tuple[str, str], stype.split('+', 1))
                     if '+' in stype else (stype, ''))

    return MimeType(type=mtype, subtype=stype, suffix=suffix,
                    parameters=params)


def guess_filename(obj: Any, default: Optional[str]=None) -> Optional[str]:
    name = getattr(obj, 'name', None)
    if name and isinstance(name, str) and name[0] != '<' and name[-1] != '>':
        return Path(name).name
    return default


def content_disposition_header(disptype: str,
                               quote_fields: bool=True,
                               **params: str) -> str:
    """Sets ``Content-Disposition`` header.

    disptype is a disposition type: inline, attachment, form-data.
    Should be valid extension token (see RFC 2183)

    params is a dict with disposition params.
    """
    if not disptype or not (TOKEN > set(disptype)):
        raise ValueError('bad content disposition type {!r}'
                         ''.format(disptype))

    value = disptype
    if params:
        lparams = []
        for key, val in params.items():
            if not key or not (TOKEN > set(key)):
                raise ValueError('bad content disposition parameter'
                                 ' {!r}={!r}'.format(key, val))
            qval = quote(val, '') if quote_fields else val
            lparams.append((key, '"%s"' % qval))
            if key == 'filename':
                lparams.append(('filename*', "utf-8''" + qval))
        sparams = '; '.join('='.join(pair) for pair in lparams)
        value = '; '.join((value, sparams))
    return value


KeyMethod = namedtuple('KeyMethod', 'key method')


class AccessLogger(AbstractAccessLogger):
    """Helper object to log access.

    Usage:
        log = logging.getLogger("spam")
        log_format = "%a %{User-Agent}i"
        access_logger = AccessLogger(log, log_format)
        access_logger.log(request, response, time)

    Format:
        %%  The percent sign
        %a  Remote IP-address (IP-address of proxy if using reverse proxy)
        %t  Time when the request was started to process
        %P  The process ID of the child that serviced the request
        %r  First line of request
        %s  Response status code
        %b  Size of response in bytes, including HTTP headers
        %T  Time taken to serve the request, in seconds
        %Tf Time taken to serve the request, in seconds with floating fraction
            in .06f format
        %D  Time taken to serve the request, in microseconds
        %{FOO}i  request.headers['FOO']
        %{FOO}o  response.headers['FOO']
        %{FOO}e  os.environ['FOO']

    """
    LOG_FORMAT_MAP = {
        'a': 'remote_address',
        't': 'request_start_time',
        'P': 'process_id',
        'r': 'first_request_line',
        's': 'response_status',
        'b': 'response_size',
        'T': 'request_time',
        'Tf': 'request_time_frac',
        'D': 'request_time_micro',
        'i': 'request_header',
        'o': 'response_header',
    }

    LOG_FORMAT = '%a %t "%r" %s %b "%{Referer}i" "%{User-Agent}i"'
    FORMAT_RE = re.compile(r'%(\{([A-Za-z0-9\-_]+)\}([ioe])|[atPrsbOD]|Tf?)')
    CLEANUP_RE = re.compile(r'(%[^s])')
    _FORMAT_CACHE = {}  # type: Dict[str, Tuple[str, List[KeyMethod]]]

    def __init__(self, logger: logging.Logger,
                 log_format: str=LOG_FORMAT) -> None:
        """Initialise the logger.

        logger is a logger object to be used for logging.
        log_format is an string with apache compatible log format description.

        """
        super().__init__(logger, log_format=log_format)

        _compiled_format = AccessLogger._FORMAT_CACHE.get(log_format)
        if not _compiled_format:
            _compiled_format = self.compile_format(log_format)
            AccessLogger._FORMAT_CACHE[log_format] = _compiled_format

        self._log_format, self._methods = _compiled_format

    def compile_format(self, log_format: str) -> Tuple[str, List[KeyMethod]]:
        """Translate log_format into form usable by modulo formatting

        All known atoms will be replaced with %s
        Also methods for formatting of those atoms will be added to
        _methods in appropriate order

        For example we have log_format = "%a %t"
        This format will be translated to "%s %s"
        Also contents of _methods will be
        [self._format_a, self._format_t]
        These method will be called and results will be passed
        to translated string format.

        Each _format_* method receive 'args' which is list of arguments
        given to self.log

        Exceptions are _format_e, _format_i and _format_o methods which
        also receive key name (by functools.partial)

        """
        # list of (key, method) tuples, we don't use an OrderedDict as users
        # can repeat the same key more than once
        methods = list()

        for atom in self.FORMAT_RE.findall(log_format):
            if atom[1] == '':
                format_key1 = self.LOG_FORMAT_MAP[atom[0]]
                m = getattr(AccessLogger, '_format_%s' % atom[0])
                key_method = KeyMethod(format_key1, m)
            else:
                format_key2 = (self.LOG_FORMAT_MAP[atom[2]], atom[1])
                m = getattr(AccessLogger, '_format_%s' % atom[2])
                key_method = KeyMethod(format_key2,
                                       functools.partial(m, atom[1]))

            methods.append(key_method)

        log_format = self.FORMAT_RE.sub(r'%s', log_format)
        log_format = self.CLEANUP_RE.sub(r'%\1', log_format)
        return log_format, methods

    @staticmethod
    def _format_i(key: str,
                  request: 'BaseRequest',
                  response: 'StreamResponse',
                  time: float) -> str:
        if request is None:
            return '(no headers)'

        # suboptimal, make istr(key) once
        return request.headers.get(key, '-')

    @staticmethod
    def _format_o(key: str,
                  request: 'BaseRequest',
                  response: 'StreamResponse',
                  time: float) -> str:
        # suboptimal, make istr(key) once
        return response.headers.get(key, '-')

    @staticmethod
    def _format_a(request: 'BaseRequest',
                  response: 'StreamResponse',
                  time: float) -> str:
        if request is None:
            return '-'
        ip = request.remote
        return ip if ip is not None else '-'

    @staticmethod
    def _format_t(request: 'BaseRequest',
                  response: 'StreamResponse',
                  time: float) -> str:
        now = datetime.datetime.utcnow()
        start_time = now - datetime.timedelta(seconds=time)
        return start_time.strftime('[%d/%b/%Y:%H:%M:%S +0000]')

    @staticmethod
    def _format_P(request: 'BaseRequest',
                  response: 'StreamResponse',
                  time: float) -> str:
        return "<%s>" % os.getpid()

    @staticmethod
    def _format_r(request: 'BaseRequest',
                  response: 'StreamResponse',
                  time: float) -> str:
        if request is None:
            return '-'
        return '%s %s HTTP/%s.%s' % (request.method, request.path_qs,
                                     request.version.major,
                                     request.version.minor)

    @staticmethod
    def _format_s(request: 'BaseRequest',
                  response: 'StreamResponse',
                  time: float) -> str:
        return response.status

    @staticmethod
    def _format_b(request: 'BaseRequest',
                  response: 'StreamResponse',
                  time: float) -> str:
        return response.body_length

    @staticmethod
    def _format_T(request: 'BaseRequest',
                  response: 'StreamResponse',
                  time: float) -> str:
        return str(round(time))

    @staticmethod
    def _format_Tf(request: 'BaseRequest',
                   response: 'StreamResponse',
                   time: float) -> str:
        return '%06f' % time

    @staticmethod
    def _format_D(request: 'BaseRequest',
                  response: 'StreamResponse',
                  time: float) -> str:
        return str(round(time * 1000000))

    def _format_line(self,
                     request: 'BaseRequest',
                     response: 'StreamResponse',
                     time: float) -> Iterable[Tuple[str,
                                                    Callable[['BaseRequest',
                                                              'StreamResponse',
                                                              float],
                                                             str]]]:
        return [(key, method(request, response, time))
                for key, method in self._methods]

    def log(self,
            request: 'BaseRequest',
            response: 'StreamResponse',
            time: float) -> None:
        try:
            fmt_info = self._format_line(request, response, time)

            values = list()
            extra = dict()
            for key, value in fmt_info:
                values.append(value)

                if key.__class__ is str:
                    extra[key] = value
                else:
                    k1, k2 = key
                    dct = extra.get(k1, {})
                    dct[k2] = value  # type: ignore
                    extra[k1] = dct  # type: ignore

            self.logger.info(self._log_format % tuple(values), extra=extra)
        except Exception:
            self.logger.exception("Error in logging")


class reify:
    """Use as a class method decorator.  It operates almost exactly like
    the Python `@property` decorator, but it puts the result of the
    method it decorates into the instance dict after the first call,
    effectively replacing the function it decorates with an instance
    variable.  It is, in Python parlance, a data descriptor.

    """

    def __init__(self, wrapped: Callable[..., Any]) -> None:
        self.wrapped = wrapped
        self.__doc__ = wrapped.__doc__
        self.name = wrapped.__name__

    def __get__(self, inst: Any, owner: Any) -> Any:
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

    def __set__(self, inst: Any, value: Any) -> None:
        raise AttributeError("reified property is read-only")


reify_py = reify

try:
    from ._helpers import reify as reify_c
    if not NO_EXTENSIONS:
        reify = reify_c  # type: ignore
except ImportError:
    pass

_ipv4_pattern = (r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                 r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
_ipv6_pattern = (
    r'^(?:(?:(?:[A-F0-9]{1,4}:){6}|(?=(?:[A-F0-9]{0,4}:){0,6}'
    r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}$)(([0-9A-F]{1,4}:){0,5}|:)'
    r'((:[0-9A-F]{1,4}){1,5}:|:)|::(?:[A-F0-9]{1,4}:){5})'
    r'(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])|(?:[A-F0-9]{1,4}:){7}'
    r'[A-F0-9]{1,4}|(?=(?:[A-F0-9]{0,4}:){0,7}[A-F0-9]{0,4}$)'
    r'(([0-9A-F]{1,4}:){1,7}|:)((:[0-9A-F]{1,4}){1,7}|:)|(?:[A-F0-9]{1,4}:){7}'
    r':|:(:[A-F0-9]{1,4}){7})$')
_ipv4_regex = re.compile(_ipv4_pattern)
_ipv6_regex = re.compile(_ipv6_pattern, flags=re.IGNORECASE)
_ipv4_regexb = re.compile(_ipv4_pattern.encode('ascii'))
_ipv6_regexb = re.compile(_ipv6_pattern.encode('ascii'), flags=re.IGNORECASE)


def _is_ip_address(
        regex: Pattern, regexb: Pattern,
        host: Optional[Union[str, bytes, bytearray, memoryview]])-> bool:
    if host is None:
        return False
    if isinstance(host, str):
        return bool(regex.match(host))
    elif isinstance(host, (bytes, bytearray, memoryview)):
        return bool(regexb.match(host))
    else:
        raise TypeError("{} [{}] is not a str or bytes"
                        .format(host, type(host)))


is_ipv4_address = functools.partial(_is_ip_address, _ipv4_regex, _ipv4_regexb)
is_ipv6_address = functools.partial(_is_ip_address, _ipv6_regex, _ipv6_regexb)


def is_ip_address(
        host: Optional[Union[str, bytes, bytearray, memoryview]]) -> bool:
    return is_ipv4_address(host) or is_ipv6_address(host)


_cached_current_datetime = None
_cached_formatted_datetime = None


def rfc822_formatted_time() -> str:
    global _cached_current_datetime
    global _cached_formatted_datetime

    now = int(time.time())
    if now != _cached_current_datetime:
        # Weekday and month names for HTTP date/time formatting;
        # always English!
        # Tuples are constants stored in codeobject!
        _weekdayname = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
        _monthname = ("",  # Dummy so we can use 1-based month numbers
                      "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

        year, month, day, hh, mm, ss, wd, y, z = time.gmtime(now)  # type: ignore  # noqa
        _cached_formatted_datetime = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
            _weekdayname[wd], day, _monthname[month], year, hh, mm, ss
        )
        _cached_current_datetime = now
    return _cached_formatted_datetime  # type: ignore


def _weakref_handle(info):  # type: ignore
    ref, name = info
    ob = ref()
    if ob is not None:
        with suppress(Exception):
            getattr(ob, name)()


def weakref_handle(ob, name, timeout, loop, ceil_timeout=True):  # type: ignore
    if timeout is not None and timeout > 0:
        when = loop.time() + timeout
        if ceil_timeout:
            when = ceil(when)

        return loop.call_at(when, _weakref_handle, (weakref.ref(ob), name))


def call_later(cb, timeout, loop):  # type: ignore
    if timeout is not None and timeout > 0:
        when = ceil(loop.time() + timeout)
        return loop.call_at(when, cb)


class TimeoutHandle:
    """ Timeout handle """

    def __init__(self,
                 loop: asyncio.AbstractEventLoop,
                 timeout: Optional[float]) -> None:
        self._timeout = timeout
        self._loop = loop
        self._callbacks = []  # type: List[Tuple[Callable[..., None], Tuple[Any, ...], Dict[str, Any]]]  # noqa

    def register(self, callback: Callable[..., None],
                 *args: Any, **kwargs: Any) -> None:
        self._callbacks.append((callback, args, kwargs))

    def close(self) -> None:
        self._callbacks.clear()

    def start(self) -> Optional[asyncio.Handle]:
        if self._timeout is not None and self._timeout > 0:
            at = ceil(self._loop.time() + self._timeout)
            return self._loop.call_at(at, self.__call__)
        else:
            return None

    def timer(self) -> 'BaseTimerContext':
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


class BaseTimerContext(ContextManager['BaseTimerContext']):
    pass


class TimerNoop(BaseTimerContext):

    def __enter__(self) -> BaseTimerContext:
        return self

    def __exit__(self, exc_type: Optional[Type[BaseException]],
                 exc_val: Optional[BaseException],
                 exc_tb: Optional[TracebackType]) -> Optional[bool]:
        return False


class TimerContext(BaseTimerContext):
    """ Low resolution timeout context manager """

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._tasks = []  # type: List[asyncio.Task[Any]]
        self._cancelled = False

    def __enter__(self) -> BaseTimerContext:
        task = current_task(loop=self._loop)

        if task is None:
            raise RuntimeError('Timeout context manager should be used '
                               'inside a task')

        if self._cancelled:
            task.cancel()
            raise asyncio.TimeoutError from None

        self._tasks.append(task)
        return self

    def __exit__(self, exc_type: Optional[Type[BaseException]],
                 exc_val: Optional[BaseException],
                 exc_tb: Optional[TracebackType]) -> Optional[bool]:
        if self._tasks:
            self._tasks.pop()

        if exc_type is asyncio.CancelledError and self._cancelled:
            raise asyncio.TimeoutError from None
        return None

    def timeout(self) -> None:
        if not self._cancelled:
            for task in set(self._tasks):
                task.cancel()

            self._cancelled = True


class CeilTimeout(async_timeout.timeout):

    def __enter__(self) -> async_timeout.timeout:
        if self._timeout is not None:
            self._task = current_task(loop=self._loop)
            if self._task is None:
                raise RuntimeError(
                    'Timeout context manager should be used inside a task')
            self._cancel_handler = self._loop.call_at(
                ceil(self._loop.time() + self._timeout), self._cancel_task)
        return self


class HeadersMixin:

    ATTRS = frozenset([
        '_content_type', '_content_dict', '_stored_content_type'])

    _content_type = None
    _content_dict = None
    _stored_content_type = sentinel

    def _parse_content_type(self, raw: str) -> None:
        self._stored_content_type = raw
        if raw is None:
            # default value according to RFC 2616
            self._content_type = 'application/octet-stream'
            self._content_dict = {}
        else:
            self._content_type, self._content_dict = cgi.parse_header(raw)

    @property
    def content_type(self) -> str:
        """The value of content part for Content-Type HTTP header."""
        raw = self._headers.get(hdrs.CONTENT_TYPE)  # type: ignore
        if self._stored_content_type != raw:
            self._parse_content_type(raw)
        return self._content_type  # type: ignore

    @property
    def charset(self) -> Optional[str]:
        """The value of charset part for Content-Type HTTP header."""
        raw = self._headers.get(hdrs.CONTENT_TYPE)  # type: ignore
        if self._stored_content_type != raw:
            self._parse_content_type(raw)
        return self._content_dict.get('charset')  # type: ignore

    @property
    def content_length(self) -> Optional[int]:
        """The value of Content-Length HTTP header."""
        content_length = self._headers.get(hdrs.CONTENT_LENGTH)  # type: ignore

        if content_length is not None:
            return int(content_length)
        else:
            return None


def set_result(fut: 'asyncio.Future[_T]', result: _T) -> None:
    if not fut.done():
        fut.set_result(result)


def set_exception(fut: 'asyncio.Future[_T]', exc: BaseException) -> None:
    if not fut.done():
        fut.set_exception(exc)


class ChainMapProxy(Mapping[str, Any]):
    __slots__ = ('_maps',)

    def __init__(self, maps: Iterable[Mapping[str, Any]]) -> None:
        self._maps = tuple(maps)

    def __init_subclass__(cls) -> None:
        raise TypeError("Inheritance class {} from ChainMapProxy "
                        "is forbidden".format(cls.__name__))

    def __getitem__(self, key: str) -> Any:
        for mapping in self._maps:
            try:
                return mapping[key]
            except KeyError:
                pass
        raise KeyError(key)

    def get(self, key: str, default: Any=None) -> Any:
        return self[key] if key in self else default

    def __len__(self) -> int:
        # reuses stored hash values if possible
        return len(set().union(*self._maps))  # type: ignore

    def __iter__(self) -> Iterator[str]:
        d = {}  # type: Dict[str, Any]
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
        return 'ChainMapProxy({})'.format(content)
