"""Various helper functions"""

import asyncio
import base64
import binascii
import cgi
import datetime
import functools
import os
import re
import sys
import time
import warnings
import weakref
from collections import MutableSequence, namedtuple
from functools import total_ordering
from math import ceil
from pathlib import Path
from time import gmtime
from urllib.parse import quote

from async_timeout import timeout

from . import hdrs

try:
    from asyncio import ensure_future
except ImportError:
    ensure_future = asyncio.async

PY_34 = sys.version_info < (3, 5)
PY_35 = sys.version_info >= (3, 5)
PY_352 = sys.version_info >= (3, 5, 2)

if sys.version_info >= (3, 4, 3):
    from http.cookies import SimpleCookie  # noqa
else:
    from .backport_cookies import SimpleCookie  # noqa


__all__ = ('BasicAuth', 'create_future', 'parse_mimetype',
           'Timeout', 'ensure_future', 'noop')


sentinel = object()
Timeout = timeout
NO_EXTENSIONS = bool(os.environ.get('AIOHTTP_NO_EXTENSIONS'))

CHAR = set(chr(i) for i in range(0, 128))
CTL = set(chr(i) for i in range(0, 32)) | {chr(127), }
SEPARATORS = {'(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']',
              '?', '=', '{', '}', ' ', chr(9)}
TOKEN = CHAR ^ CTL ^ SEPARATORS


if sys.version_info < (3, 5):
    noop = tuple

    coroutines = asyncio.coroutines
    old_debug = coroutines._DEBUG
    coroutines._DEBUG = False

    @asyncio.coroutine
    def deprecated_noop(message):
        warnings.warn(message, DeprecationWarning, stacklevel=3)

    coroutines._DEBUG = old_debug

else:
    coroutines = asyncio.coroutines
    old_debug = coroutines._DEBUG
    coroutines._DEBUG = False

    @asyncio.coroutine
    def noop(*args, **kwargs):
        return

    @asyncio.coroutine
    def deprecated_noop(message):
        warnings.warn(message, DeprecationWarning, stacklevel=3)

    coroutines._DEBUG = old_debug


class BasicAuth(namedtuple('BasicAuth', ['login', 'password', 'encoding'])):
    """Http basic authentication helper.

    :param str login: Login
    :param str password: Password
    :param str encoding: (optional) encoding ('latin1' by default)
    """

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
        """Create a :class:`BasicAuth` object from an ``Authorization`` HTTP
        header."""
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

    def encode(self):
        """Encode credentials."""
        creds = ('%s:%s' % (self.login, self.password)).encode(self.encoding)
        return 'Basic %s' % base64.b64encode(creds).decode(self.encoding)


if PY_352:
    def create_future(loop):
        return loop.create_future()
else:
    def create_future(loop):
        """Compatibility wrapper for the loop.create_future() call introduced in
        3.5.2."""
        return asyncio.Future(loop=loop)


def parse_mimetype(mimetype):
    """Parses a MIME type into its components.

    :param str mimetype: MIME type

    :returns: 4 element tuple for MIME type, subtype, suffix and parameters
    :rtype: tuple

    Example:

    >>> parse_mimetype('text/html; charset=utf-8')
    ('text', 'html', '', {'charset': 'utf-8'})

    """
    if not mimetype:
        return '', '', '', {}

    parts = mimetype.split(';')
    params = []
    for item in parts[1:]:
        if not item:
            continue
        key, value = item.split('=', 1) if '=' in item else (item, '')
        params.append((key.lower().strip(), value.strip(' "')))
    params = dict(params)

    fulltype = parts[0].strip().lower()
    if fulltype == '*':
        fulltype = '*/*'

    mtype, stype = fulltype.split('/', 1) \
        if '/' in fulltype else (fulltype, '')
    stype, suffix = stype.split('+', 1) if '+' in stype else (stype, '')

    return mtype, stype, suffix, params


def guess_filename(obj, default=None):
    name = getattr(obj, 'name', None)
    if name and name[0] != '<' and name[-1] != '>':
        return Path(name).name
    return default


def content_disposition_header(disptype, quote_fields=True, **params):
    """Sets ``Content-Disposition`` header.

    :param str disptype: Disposition type: inline, attachment, form-data.
                         Should be valid extension token (see RFC 2183)
    :param dict params: Disposition params
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


class AccessLogger:
    """Helper object to log access.

    Usage:
        log = logging.getLogger("spam")
        log_format = "%a %{User-Agent}i"
        access_logger = AccessLogger(log, log_format)
        access_logger.log(message, environ, response, transport, time)

    Format:
        %%  The percent sign
        %a  Remote IP-address (IP-address of proxy if using reverse proxy)
        %t  Time when the request was started to process
        %P  The process ID of the child that serviced the request
        %r  First line of request
        %s  Response status code
        %b  Size of response in bytes, excluding HTTP headers
        %O  Bytes sent, including headers
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
        't': 'request_time',
        'P': 'process_id',
        'r': 'first_request_line',
        's': 'response_status',
        'b': 'response_size',
        'O': 'bytes_sent',
        'T': 'request_time',
        'Tf': 'request_time_frac',
        'D': 'request_time_micro',
        'i': 'request_header',
        'o': 'response_header',
        'e': 'environ'
    }

    LOG_FORMAT = '%a %l %u %t "%r" %s %b "%{Referrer}i" "%{User-Agent}i"'
    FORMAT_RE = re.compile(r'%(\{([A-Za-z0-9\-_]+)\}([ioe])|[atPrsbOD]|Tf?)')
    CLEANUP_RE = re.compile(r'(%[^s])')
    _FORMAT_CACHE = {}

    KeyMethod = namedtuple('KeyMethod', 'key method')

    def __init__(self, logger, log_format=LOG_FORMAT):
        """Initialise the logger.

        :param logger: logger object to be used for logging
        :param log_format: apache compatible log format

        """
        self.logger = logger

        _compiled_format = AccessLogger._FORMAT_CACHE.get(log_format)
        if not _compiled_format:
            _compiled_format = self.compile_format(log_format)
            AccessLogger._FORMAT_CACHE[log_format] = _compiled_format

        self._log_format, self._methods = _compiled_format

    def compile_format(self, log_format):
        """Translate log_format into form usable by modulo formatting

        All known atoms will be replaced with %s
        Also methods for formatting of those atoms will be added to
        _methods in apropriate order

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

        log_format = log_format.replace("%l", "-")
        log_format = log_format.replace("%u", "-")

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
    def _format_e(key, args):
        return (args[1] or {}).get(key, '-')

    @staticmethod
    def _format_i(key, args):
        if not args[0]:
            return '(no headers)'

        # suboptimal, make istr(key) once
        return args[0].headers.get(key, '-')

    @staticmethod
    def _format_o(key, args):
        # suboptimal, make istr(key) once
        return args[2].headers.get(key, '-')

    @staticmethod
    def _format_a(args):
        if args[3] is None:
            return '-'
        peername = args[3].get_extra_info('peername')
        if isinstance(peername, (list, tuple)):
            return peername[0]
        else:
            return peername

    @staticmethod
    def _format_t(args):
        return datetime.datetime.utcnow().strftime('[%d/%b/%Y:%H:%M:%S +0000]')

    @staticmethod
    def _format_P(args):
        return "<%s>" % os.getpid()

    @staticmethod
    def _format_r(args):
        msg = args[0]
        if not msg:
            return '-'
        return '%s %s HTTP/%s.%s' % tuple((msg.method,
                                           msg.path) + msg.version)

    @staticmethod
    def _format_s(args):
        return args[2].status

    @staticmethod
    def _format_b(args):
        return args[2].body_length

    @staticmethod
    def _format_O(args):
        return args[2].body_length

    @staticmethod
    def _format_T(args):
        return round(args[4])

    @staticmethod
    def _format_Tf(args):
        return '%06f' % args[4]

    @staticmethod
    def _format_D(args):
        return round(args[4] * 1000000)

    def _format_line(self, args):
        return ((key, method(args)) for key, method in self._methods)

    def log(self, message, environ, response, transport, time):
        """Log access.

        :param message: Request object. May be None.
        :param environ: Environment dict. May be None.
        :param response: Response object.
        :param transport: Tansport object. May be None
        :param float time: Time taken to serve the request.
        """
        try:
            fmt_info = self._format_line(
                [message, environ, response, transport, time])

            values = list()
            extra = dict()
            for key, value in fmt_info:
                values.append(value)

                if key.__class__ is str:
                    extra[key] = value
                else:
                    extra[key[0]] = {key[1]: value}

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
        except:  # pragma: no cover
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


@total_ordering
class FrozenList(MutableSequence):

    __slots__ = ('_frozen', '_items')

    def __init__(self, items=None):
        self._frozen = False
        if items is not None:
            items = list(items)
        else:
            items = []
        self._items = items

    def freeze(self):
        self._frozen = True
        self._items = tuple(self._items)

    def __getitem__(self, index):
        return self._items[index]

    def __setitem__(self, index, value):
        if self._frozen:
            raise RuntimeError("Cannot modify frozen list.")
        self._items[index] = value

    def __delitem__(self, index):
        if self._frozen:
            raise RuntimeError("Cannot modify frozen list.")
        del self._items[index]

    def __len__(self):
        return self._items.__len__()

    def __iter__(self):
        return self._items.__iter__()

    def __reversed__(self):
        return self._items.__reversed__()

    def __eq__(self, other):
        return list(self) == other

    def __le__(self, other):
        return list(self) <= other

    def insert(self, pos, item):
        if self._frozen:
            raise RuntimeError("Cannot modify frozen list.")
        self._items.insert(pos, item)


class TimeService:

    def __init__(self, loop, *, interval=1.0):
        self._loop = loop
        self._interval = interval
        self._time = time.time()
        self._loop_time = loop.time()
        self._count = 0
        self._strtime = None
        self._cb = loop.call_at(self._loop_time + self._interval, self._on_cb)

    def close(self):
        if self._cb:
            self._cb.cancel()

        self._cb = None
        self._loop = None

    def _on_cb(self, reset_count=10*60):
        if self._count >= reset_count:
            # reset timer every 10 minutes
            self._count = 0
            self._time = time.time()
        else:
            self._time += self._interval

        self._strtime = None
        self._loop_time = ceil(self._loop.time())
        self._cb = self._loop.call_at(
            self._loop_time + self._interval, self._on_cb)

    def _format_date_time(self):
        # Weekday and month names for HTTP date/time formatting;
        # always English!
        # Tuples are contants stored in codeobject!
        _weekdayname = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
        _monthname = (None,  # Dummy so we can use 1-based month numbers
                      "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

        year, month, day, hh, mm, ss, wd, y, z = gmtime(self._time)
        return "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
            _weekdayname[wd], day, _monthname[month], year, hh, mm, ss
        )

    def time(self):
        return self._time

    def strtime(self):
        s = self._strtime
        if s is None:
            self._strtime = s = self._format_date_time()
        return self._strtime

    @property
    def loop_time(self):
        return self._loop_time


def _weakref_handle(info):
    ref, name = info
    ob = ref()
    if ob is not None:
        try:
            getattr(ob, name)()
        except:
            pass


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
        timer = TimerContext(self._loop)
        self.register(timer.timeout)
        return timer

    def __call__(self):
        for cb, args, kwargs in self._callbacks:
            try:
                cb(*args, **kwargs)
            except:
                pass

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
        task = asyncio.Task.current_task(loop=self._loop)
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
            task = self._tasks.pop()
        else:
            task = None

        if exc_type is asyncio.CancelledError and self._cancelled:
            for task in self._tasks:
                task.cancel()
            raise asyncio.TimeoutError from None

        if exc_type is None and self._cancelled and task is not None:
            task.cancel()

    def timeout(self):
        if not self._cancelled:
            for task in self._tasks:
                task.cancel()

            self._cancelled = True


class CeilTimeout(Timeout):

    def __enter__(self):
        if self._timeout is not None:
            self._task = asyncio.Task.current_task(loop=self._loop)
            if self._task is None:
                raise RuntimeError(
                    'Timeout context manager should be used inside a task')
            self._cancel_handler = self._loop.call_at(
                ceil(self._loop.time() + self._timeout), self._cancel_task)
        return self


class HeadersMixin:

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
        l = self._headers.get(_CONTENT_LENGTH)
        if l is None:
            return None
        else:
            return int(l)
