"""Various helper functions"""

import asyncio
import base64
import binascii
import cgi
import datetime
import functools
import inspect
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
from urllib.parse import quote
from urllib.request import getproxies

import async_timeout
import attr
from multidict import MultiDict
from yarl import URL

from . import hdrs
from .abc import AbstractAccessLogger
from .log import client_logger


__all__ = ('BasicAuth',)

PY_36 = sys.version_info >= (3, 6)
PY_37 = sys.version_info >= (3, 7)

if not PY_37:
    import idna_ssl
    idna_ssl.patch_match_hostname()


sentinel = object()
NO_EXTENSIONS = bool(os.environ.get('AIOHTTP_NO_EXTENSIONS'))

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
old_debug = coroutines._DEBUG

# prevent "coroutine noop was never awaited" warning.
coroutines._DEBUG = False


@asyncio.coroutine
def noop(*args, **kwargs):
    return


coroutines._DEBUG = old_debug


class BasicAuth(namedtuple('BasicAuth', ['login', 'password', 'encoding'])):
    """Http basic authentication helper."""

    def __new__(cls, login, password='', encoding='latin1'):
        if login is None:
            raise ValueError('None is not allowed as login value')

        if password is None:
            raise ValueError('None is not allowed as password value')

        if ':' in login:
            raise ValueError(
                'A ":" is not allowed in login (RFC 1945#section-11.1)')

        return super().__new__(cls, login, password, encoding)

    @classmethod
    def decode(cls, auth_header, encoding='latin1'):
        """Create a BasicAuth object from an Authorization HTTP header."""
        split = auth_header.strip().split(' ')
        if len(split) == 2:
            if split[0].strip().lower() != 'basic':
                raise ValueError('Unknown authorization method %s' % split[0])
            to_decode = split[1]
        else:
            raise ValueError('Could not parse authorization header.')

        try:
            username, _, password = base64.b64decode(
                to_decode.encode('ascii')
            ).decode(encoding).partition(':')
        except binascii.Error:
            raise ValueError('Invalid base64 encoding.')

        return cls(username, password, encoding=encoding)

    @classmethod
    def from_url(cls, url, *, encoding='latin1'):
        """Create BasicAuth from url."""
        if not isinstance(url, URL):
            raise TypeError("url should be yarl.URL instance")
        if url.user is None:
            return None
        return cls(url.user, url.password or '', encoding=encoding)

    def encode(self):
        """Encode credentials."""
        creds = ('%s:%s' % (self.login, self.password)).encode(self.encoding)
        return 'Basic %s' % base64.b64encode(creds).decode(self.encoding)


def strip_auth_from_url(url):
    auth = BasicAuth.from_url(url)
    if auth is None:
        return url, None
    else:
        return url.with_user(None), auth


def netrc_from_env():
    netrc_obj = None
    netrc_path = os.environ.get('NETRC')
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
    proxy = attr.ib(type=str)
    proxy_auth = attr.ib(type=BasicAuth)


def proxies_from_env():
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
            auth_from_netrc = netrc_obj.authenticators(proxy.host)
            if auth_from_netrc is not None:
                # auth_from_netrc is a (`user`, `account`, `password`) tuple,
                # `user` and `account` both can be username,
                # if `user` is None, use `account`
                *logins, password = auth_from_netrc
                auth = BasicAuth(logins[0] if logins[0] else logins[-1],
                                 password)
        ret[proto] = ProxyInfo(proxy, auth)
    return ret


def current_task(loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()

    if PY_37:
        task = asyncio.current_task(loop=loop)
    else:
        task = asyncio.Task.current_task(loop=loop)
    if task is None:
        # this should be removed, tokio must use register_task and family API
        if hasattr(loop, 'current_task'):
            task = loop.current_task()

    return task


def isasyncgenfunction(obj):
    if hasattr(inspect, 'isasyncgenfunction'):
        return inspect.isasyncgenfunction(obj)
    return False


@attr.s(frozen=True, slots=True)
class MimeType:
    type = attr.ib(type=str)
    subtype = attr.ib(type=str)
    suffix = attr.ib(type=str)
    parameters = attr.ib(type=MultiDict)


def parse_mimetype(mimetype):
    """Parses a MIME type into its components.

    mimetype is a MIME type string.

    Returns a MimeType object.

    Example:

    >>> parse_mimetype('text/html; charset=utf-8')
    MimeType(type='text', subtype='html', suffix='',
             parameters={'charset': 'utf-8'})

    """
    if not mimetype:
        return MimeType(type='', subtype='', suffix='', parameters={})

    parts = mimetype.split(';')
    params = []
    for item in parts[1:]:
        if not item:
            continue
        key, value = item.split('=', 1) if '=' in item else (item, '')
        params.append((key.lower().strip(), value.strip(' "')))
    params = MultiDict(params)

    fulltype = parts[0].strip().lower()
    if fulltype == '*':
        fulltype = '*/*'

    mtype, stype = fulltype.split('/', 1) \
        if '/' in fulltype else (fulltype, '')
    stype, suffix = stype.split('+', 1) if '+' in stype else (stype, '')

    return MimeType(type=mtype, subtype=stype, suffix=suffix,
                    parameters=params)


def guess_filename(obj, default=None):
    name = getattr(obj, 'name', None)
    if name and isinstance(name, str) and name[0] != '<' and name[-1] != '>':
        return Path(name).name
    return default


def content_disposition_header(disptype, quote_fields=True, **params):
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
    _FORMAT_CACHE = {}

    KeyMethod = namedtuple('KeyMethod', 'key method')

    def __init__(self, logger, log_format=LOG_FORMAT):
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

    def compile_format(self, log_format):
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
                format_key = self.LOG_FORMAT_MAP[atom[0]]
                m = getattr(AccessLogger, '_format_%s' % atom[0])
            else:
                format_key = (self.LOG_FORMAT_MAP[atom[2]], atom[1])
                m = getattr(AccessLogger, '_format_%s' % atom[2])
                m = functools.partial(m, atom[1])

            methods.append(self.KeyMethod(format_key, m))

        log_format = self.FORMAT_RE.sub(r'%s', log_format)
        log_format = self.CLEANUP_RE.sub(r'%\1', log_format)
        return log_format, methods

    @staticmethod
    def _format_i(key, request, response, time):
        if request is None:
            return '(no headers)'

        # suboptimal, make istr(key) once
        return request.headers.get(key, '-')

    @staticmethod
    def _format_o(key, request, response, time):
        # suboptimal, make istr(key) once
        return response.headers.get(key, '-')

    @staticmethod
    def _format_a(request, response, time):
        if request is None:
            return '-'
        ip = request.remote
        return ip if ip is not None else '-'

    @staticmethod
    def _format_t(request, response, time):
        now = datetime.datetime.utcnow()
        start_time = now - datetime.timedelta(seconds=time)
        return start_time.strftime('[%d/%b/%Y:%H:%M:%S +0000]')

    @staticmethod
    def _format_P(request, response, time):
        return "<%s>" % os.getpid()

    @staticmethod
    def _format_r(request, response, time):
        if request is None:
            return '-'
        return '%s %s HTTP/%s.%s' % tuple((request.method,
                                           request.path_qs) + request.version)

    @staticmethod
    def _format_s(request, response, time):
        return response.status

    @staticmethod
    def _format_b(request, response, time):
        return response.body_length

    @staticmethod
    def _format_T(request, response, time):
        return round(time)

    @staticmethod
    def _format_Tf(request, response, time):
        return '%06f' % time

    @staticmethod
    def _format_D(request, response, time):
        return round(time * 1000000)

    def _format_line(self, request, response, time):
        return ((key, method(request, response, time))
                for key, method in self._methods)

    def log(self, request, response, time):
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
                    dct[k2] = value
                    extra[k1] = dct

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

    def __init__(self, wrapped):
        self.wrapped = wrapped
        try:
            self.__doc__ = wrapped.__doc__
        except Exception:  # pragma: no cover
            self.__doc__ = ""
        self.name = wrapped.__name__

    def __get__(self, inst, owner, _sentinel=sentinel):
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

    def __set__(self, inst, value):
        raise AttributeError("reified property is read-only")


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


def is_ip_address(host):
    if host is None:
        return False
    if isinstance(host, str):
        if _ipv4_regex.match(host) or _ipv6_regex.match(host):
            return True
        else:
            return False
    elif isinstance(host, (bytes, bytearray, memoryview)):
        if _ipv4_regexb.match(host) or _ipv6_regexb.match(host):
            return True
        else:
            return False
    else:
        raise TypeError("{} [{}] is not a str or bytes"
                        .format(host, type(host)))


_cached_current_datetime = None
_cached_formatted_datetime = None


def rfc822_formatted_time():
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

        year, month, day, hh, mm, ss, wd, y, z = time.gmtime(now)
        _cached_formatted_datetime = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
            _weekdayname[wd], day, _monthname[month], year, hh, mm, ss
        )
        _cached_current_datetime = now
    return _cached_formatted_datetime


def _weakref_handle(info):
    ref, name = info
    ob = ref()
    if ob is not None:
        with suppress(Exception):
            getattr(ob, name)()


def weakref_handle(ob, name, timeout, loop, ceil_timeout=True):
    if timeout is not None and timeout > 0:
        when = loop.time() + timeout
        if ceil_timeout:
            when = ceil(when)

        return loop.call_at(when, _weakref_handle, (weakref.ref(ob), name))


def call_later(cb, timeout, loop):
    if timeout is not None and timeout > 0:
        when = ceil(loop.time() + timeout)
        return loop.call_at(when, cb)


class TimeoutHandle:
    """ Timeout handle """

    def __init__(self, loop, timeout):
        self._timeout = timeout
        self._loop = loop
        self._callbacks = []

    def register(self, callback, *args, **kwargs):
        self._callbacks.append((callback, args, kwargs))

    def close(self):
        self._callbacks.clear()

    def start(self):
        if self._timeout is not None and self._timeout > 0:
            at = ceil(self._loop.time() + self._timeout)
            return self._loop.call_at(at, self.__call__)

    def timer(self):
        if self._timeout is not None and self._timeout > 0:
            timer = TimerContext(self._loop)
            self.register(timer.timeout)
        else:
            timer = TimerNoop()
        return timer

    def __call__(self):
        for cb, args, kwargs in self._callbacks:
            with suppress(Exception):
                cb(*args, **kwargs)

        self._callbacks.clear()


class TimerNoop:

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


class TimerContext:
    """ Low resolution timeout context manager """

    def __init__(self, loop):
        self._loop = loop
        self._tasks = []
        self._cancelled = False

    def __enter__(self):
        task = current_task(loop=self._loop)

        if task is None:
            raise RuntimeError('Timeout context manager should be used '
                               'inside a task')

        if self._cancelled:
            task.cancel()
            raise asyncio.TimeoutError from None

        self._tasks.append(task)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._tasks:
            self._tasks.pop()

        if exc_type is asyncio.CancelledError and self._cancelled:
            raise asyncio.TimeoutError from None

    def timeout(self):
        if not self._cancelled:
            for task in set(self._tasks):
                task.cancel()

            self._cancelled = True


class CeilTimeout(async_timeout.timeout):

    def __enter__(self):
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

    def _parse_content_type(self, raw):
        self._stored_content_type = raw
        if raw is None:
            # default value according to RFC 2616
            self._content_type = 'application/octet-stream'
            self._content_dict = {}
        else:
            self._content_type, self._content_dict = cgi.parse_header(raw)

    @property
    def content_type(self, *, _CONTENT_TYPE=hdrs.CONTENT_TYPE):
        """The value of content part for Content-Type HTTP header."""
        raw = self._headers.get(_CONTENT_TYPE)
        if self._stored_content_type != raw:
            self._parse_content_type(raw)
        return self._content_type

    @property
    def charset(self, *, _CONTENT_TYPE=hdrs.CONTENT_TYPE):
        """The value of charset part for Content-Type HTTP header."""
        raw = self._headers.get(_CONTENT_TYPE)
        if self._stored_content_type != raw:
            self._parse_content_type(raw)
        return self._content_dict.get('charset')

    @property
    def content_length(self, *, _CONTENT_LENGTH=hdrs.CONTENT_LENGTH):
        """The value of Content-Length HTTP header."""
        content_length = self._headers.get(_CONTENT_LENGTH)

        if content_length:
            return int(content_length)


def set_result(fut, result):
    if not fut.done():
        fut.set_result(result)


def set_exception(fut, exc):
    if not fut.done():
        fut.set_exception(exc)
