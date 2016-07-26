"""Various helper functions"""

import asyncio
import base64
import binascii
import datetime
import functools
import io
import os
import re

from collections import namedtuple
from http.cookies import SimpleCookie, Morsel
from math import ceil
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit

import multidict

from . import hdrs
from .abc import AbstractCookieJar
from .errors import InvalidURL
try:
    from asyncio import ensure_future
except ImportError:
    ensure_future = asyncio.async


__all__ = ('BasicAuth', 'create_future', 'FormData', 'parse_mimetype',
           'Timeout', 'CookieJar')


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


def create_future(loop):
    """Compatiblity wrapper for the loop.create_future() call introduced in
    3.5.2."""
    if hasattr(loop, 'create_future'):
        return loop.create_future()
    else:
        return asyncio.Future(loop=loop)


class FormData:
    """Helper class for multipart/form-data and
    application/x-www-form-urlencoded body generation."""

    def __init__(self, fields=()):
        from . import multipart
        self._writer = multipart.MultipartWriter('form-data')
        self._fields = []
        self._is_multipart = False

        if isinstance(fields, dict):
            fields = list(fields.items())
        elif not isinstance(fields, (list, tuple)):
            fields = (fields,)
        self.add_fields(*fields)

    @property
    def is_multipart(self):
        return self._is_multipart

    @property
    def content_type(self):
        if self._is_multipart:
            return self._writer.headers[hdrs.CONTENT_TYPE]
        else:
            return 'application/x-www-form-urlencoded'

    def add_field(self, name, value, *, content_type=None, filename=None,
                  content_transfer_encoding=None):

        if isinstance(value, io.IOBase):
            self._is_multipart = True
        elif isinstance(value, (bytes, bytearray, memoryview)):
            if filename is None and content_transfer_encoding is None:
                filename = name

        type_options = multidict.MultiDict({'name': name})
        if filename is not None and not isinstance(filename, str):
            raise TypeError('filename must be an instance of str. '
                            'Got: %s' % filename)
        if filename is None and isinstance(value, io.IOBase):
            filename = guess_filename(value, name)
        if filename is not None:
            type_options['filename'] = filename
            self._is_multipart = True

        headers = {}
        if content_type is not None:
            if not isinstance(content_type, str):
                raise TypeError('content_type must be an instance of str. '
                                'Got: %s' % content_type)
            headers[hdrs.CONTENT_TYPE] = content_type
            self._is_multipart = True
        if content_transfer_encoding is not None:
            if not isinstance(content_transfer_encoding, str):
                raise TypeError('content_transfer_encoding must be an instance'
                                ' of str. Got: %s' % content_transfer_encoding)
            headers[hdrs.CONTENT_TRANSFER_ENCODING] = content_transfer_encoding
            self._is_multipart = True

        self._fields.append((type_options, headers, value))

    def add_fields(self, *fields):
        to_add = list(fields)

        while to_add:
            rec = to_add.pop(0)

            if isinstance(rec, io.IOBase):
                k = guess_filename(rec, 'unknown')
                self.add_field(k, rec)

            elif isinstance(rec,
                            (multidict.MultiDictProxy,
                             multidict.MultiDict)):
                to_add.extend(rec.items())

            elif isinstance(rec, (list, tuple)) and len(rec) == 2:
                k, fp = rec
                self.add_field(k, fp)

            else:
                raise TypeError('Only io.IOBase, multidict and (name, file) '
                                'pairs allowed, use .add_field() for passing '
                                'more complex parameters')

    def _gen_form_urlencoded(self, encoding):
        # form data (x-www-form-urlencoded)
        data = []
        for type_options, _, value in self._fields:
            data.append((type_options['name'], value))

        data = urlencode(data, doseq=True)
        return data.encode(encoding)

    def _gen_form_data(self, *args, **kwargs):
        """Encode a list of fields using the multipart/form-data MIME format"""
        for dispparams, headers, value in self._fields:
            part = self._writer.append(value, headers)
            if dispparams:
                part.set_content_disposition('form-data', **dispparams)
                # FIXME cgi.FieldStorage doesn't likes body parts with
                # Content-Length which were sent via chunked transfer encoding
                part.headers.pop(hdrs.CONTENT_LENGTH, None)
        yield from self._writer.serialize()

    def __call__(self, encoding):
        if self._is_multipart:
            return self._gen_form_data(encoding)
        else:
            return self._gen_form_urlencoded(encoding)


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


def str_to_bytes(s, encoding='utf-8'):
    if isinstance(s, str):
        return s.encode(encoding)
    return s


def guess_filename(obj, default=None):
    name = getattr(obj, 'name', None)
    if name and name[0] != '<' and name[-1] != '>':
        return Path(name).name
    return default


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

    LOG_FORMAT = '%a %l %u %t "%r" %s %b "%{Referrer}i" "%{User-Agent}i"'
    FORMAT_RE = re.compile(r'%(\{([A-Za-z\-]+)\}([ioe])|[atPrsbOD]|Tf?)')
    CLEANUP_RE = re.compile(r'(%[^s])')
    _FORMAT_CACHE = {}

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
        methods = []

        for atom in self.FORMAT_RE.findall(log_format):
            if atom[1] == '':
                methods.append(getattr(AccessLogger, '_format_%s' % atom[0]))
            else:
                m = getattr(AccessLogger, '_format_%s' % atom[2])
                methods.append(functools.partial(m, atom[1]))
        log_format = self.FORMAT_RE.sub(r'%s', log_format)
        log_format = self.CLEANUP_RE.sub(r'%\1', log_format)
        return log_format, methods

    @staticmethod
    def _format_e(key, args):
        return (args[1] or {}).get(multidict.upstr(key), '-')

    @staticmethod
    def _format_i(key, args):
        if not args[0]:
            return '(no headers)'
        return args[0].headers.get(multidict.upstr(key), '-')

    @staticmethod
    def _format_o(key, args):
        return args[2].headers.get(multidict.upstr(key), '-')

    @staticmethod
    def _format_a(args):
        return args[3].get_extra_info('peername')[0] if args[3] is not None \
            else '-'

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
        return args[2].output_length

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
        return tuple(m(args) for m in self._methods)

    def log(self, message, environ, response, transport, time):
        """Log access.

        :param message: Request object. May be None.
        :param environ: Environment dict. May be None.
        :param response: Response object.
        :param transport: Tansport object. May be None
        :param float time: Time taken to serve the request.
        """
        try:
            self.logger.info(self._log_format % self._format_line(
                [message, environ, response, transport, time]))
        except Exception:
            self.logger.exception("Error in logging")


_marker = object()


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

    def __get__(self, inst, owner, _marker=_marker):
        if inst is None:
            return self
        val = inst.__dict__.get(self.name, _marker)
        if val is not _marker:
            return val
        val = self.wrapped(inst)
        inst.__dict__[self.name] = val
        return val

    def __set__(self, inst, value):
        raise AttributeError("reified property is read-only")


# The unreserved URI characters (RFC 3986)
UNRESERVED_SET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" +
    "0123456789-._~")


def unquote_unreserved(uri):
    """Un-escape any percent-escape sequences in a URI that are unreserved
    characters. This leaves all reserved, illegal and non-ASCII bytes encoded.
    """
    parts = uri.split('%')
    for i in range(1, len(parts)):
        h = parts[i][0:2]
        if len(h) == 2 and h.isalnum():
            try:
                c = chr(int(h, 16))
            except ValueError:
                raise InvalidURL("Invalid percent-escape sequence: '%s'" % h)

            if c in UNRESERVED_SET:
                parts[i] = c + parts[i][2:]
            else:
                parts[i] = '%' + parts[i]
        else:
            parts[i] = '%' + parts[i]
    return ''.join(parts)


def requote_uri(uri):
    """Re-quote the given URI.

    This function passes the given URI through an unquote/quote cycle to
    ensure that it is fully and consistently quoted.
    """
    safe_with_percent = "!#$%&'()*+,/:;=?@[]~"
    safe_without_percent = "!#$&'()*+,/:;=?@[]~"
    try:
        # Unquote only the unreserved characters
        # Then quote only illegal characters (do not quote reserved,
        # unreserved, or '%')
        return quote(unquote_unreserved(uri), safe=safe_with_percent)
    except InvalidURL:
        # We couldn't unquote the given URI, so let's try quoting it, but
        # there may be unquoted '%'s in the URI. We need to make sure they're
        # properly quoted so they do not cause issues elsewhere.
        return quote(uri, safe=safe_without_percent)


_ipv4_pattern = ('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                 '(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
_ipv6_pattern = (
    '^(?:(?:(?:[A-F0-9]{1,4}:){6}|(?=(?:[A-F0-9]{0,4}:){0,6}'
    '(?:[0-9]{1,3}\.){3}[0-9]{1,3}$)(([0-9A-F]{1,4}:){0,5}|:)'
    '((:[0-9A-F]{1,4}){1,5}:|:)|::(?:[A-F0-9]{1,4}:){5})'
    '(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}'
    '(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])|(?:[A-F0-9]{1,4}:){7}'
    '[A-F0-9]{1,4}|(?=(?:[A-F0-9]{0,4}:){0,7}[A-F0-9]{0,4}$)'
    '(([0-9A-F]{1,4}:){1,7}|:)((:[0-9A-F]{1,4}){1,7}|:)|(?:[A-F0-9]{1,4}:){7}'
    ':|:(:[A-F0-9]{1,4}){7})$')
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


class Timeout:
    """Timeout context manager.

    Useful in cases when you want to apply timeout logic around block
    of code or in cases when asyncio.wait_for is not suitable. For example:

    >>> with aiohttp.Timeout(0.001):
    ...     async with aiohttp.get('https://github.com') as r:
    ...         await r.text()


    :param timeout: timeout value in seconds or None to disable timeout logic
    :param loop: asyncio compatible event loop
    """
    def __init__(self, timeout, *, loop=None):
        self._timeout = timeout
        if loop is None:
            loop = asyncio.get_event_loop()
        self._loop = loop
        self._task = None
        self._cancelled = False
        self._cancel_handler = None

    def __enter__(self):
        self._task = asyncio.Task.current_task(loop=self._loop)
        if self._task is None:
            raise RuntimeError('Timeout context manager should be used '
                               'inside a task')
        if self._timeout is not None:
            self._cancel_handler = self._loop.call_later(
                self._timeout, self._cancel_task)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is asyncio.CancelledError and self._cancelled:
            self._cancel_handler = None
            self._task = None
            raise asyncio.TimeoutError from None
        if self._timeout is not None:
            self._cancel_handler.cancel()
            self._cancel_handler = None
        self._task = None

    def _cancel_task(self):
        self._cancelled = self._task.cancel()


class CookieJar(AbstractCookieJar):
    """Implements cookie storage adhering to RFC 6265."""

    DATE_TOKENS_RE = re.compile(
        "[\x09\x20-\x2F\x3B-\x40\x5B-\x60\x7B-\x7E]*"
        "(?P<token>[\x00-\x08\x0A-\x1F\d:a-zA-Z\x7F-\xFF]+)")

    DATE_HMS_TIME_RE = re.compile("(\d{1,2}):(\d{1,2}):(\d{1,2})")

    DATE_DAY_OF_MONTH_RE = re.compile("(\d{1,2})")

    DATE_MONTH_RE = re.compile(
        "(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)", re.I)

    DATE_YEAR_RE = re.compile("(\d{2,4})")

    def __init__(self, *, unsafe=False, loop=None):
        super().__init__(loop=loop)
        self._host_only_cookies = set()
        self._unsafe = unsafe

    def _expire_cookie(self, when, name, DAY=24*3600):
        now = self._loop.time()
        delta = when - now
        if delta <= 0:
            # expired
            self._cookies.pop(name, None)
        if delta > DAY:
            # Huge timeouts (more than 24 days) breaks event loop
            self._loop.call_at(ceil(now+DAY), self._expire_cookie, when, name)
        else:
            self._loop.call_at(ceil(when), self._expire_cookie, when, name)

    def update_cookies(self, cookies, response_url=None):
        """Update cookies."""
        url_parsed = urlsplit(response_url or "")
        hostname = url_parsed.hostname

        if not self._unsafe and is_ip_address(hostname):
            # Don't accept cookies from IPs
            return

        if isinstance(cookies, dict):
            cookies = cookies.items()

        for name, value in cookies:
            if isinstance(value, Morsel):

                if not self._add_morsel(name, value, hostname):
                    continue

            else:
                self._cookies[name] = value

            cookie = self._cookies[name]

            if not cookie["domain"] and hostname is not None:
                # Set the cookie's domain to the response hostname
                # and set its host-only-flag
                self._host_only_cookies.add(name)
                cookie["domain"] = hostname

            if not cookie["path"] or not cookie["path"].startswith("/"):
                # Set the cookie's path to the response path
                path = url_parsed.path
                if not path.startswith("/"):
                    path = "/"
                else:
                    # Cut everything from the last slash to the end
                    path = "/" + path[1:path.rfind("/")]
                cookie["path"] = path

            max_age = cookie["max-age"]
            if max_age:
                try:
                    delta_seconds = int(max_age)
                    self._expire_cookie(self._loop.time() + delta_seconds,
                                        name)
                except ValueError:
                    cookie["max-age"] = ""

            expires = cookie["expires"]
            if not cookie["max-age"] and expires:
                expire_time = self._parse_date(expires)
                if expire_time:
                    self._expire_cookie(expire_time.timestamp(),
                                        name)
                else:
                    cookie["expires"] = ""

        # Remove the host-only flags of nonexistent cookies
        self._host_only_cookies -= (
            self._host_only_cookies.difference(self._cookies.keys()))

    def _add_morsel(self, name, value, hostname):
        """Add a Morsel to the cookie jar."""
        cookie_domain = value["domain"]
        if cookie_domain.startswith("."):
            # Remove leading dot
            cookie_domain = cookie_domain[1:]
            value["domain"] = cookie_domain

        if not cookie_domain or not hostname:
            dict.__setitem__(self._cookies, name, value)
            return True

        if not self._is_domain_match(cookie_domain, hostname):
            # Setting cookies for different domains is not allowed
            return False

        # use dict method because SimpleCookie class modifies value
        # before Python 3.4
        dict.__setitem__(self._cookies, name, value)
        return True

    def filter_cookies(self, request_url):
        """Returns this jar's cookies filtered by their attributes."""
        url_parsed = urlsplit(request_url)
        filtered = SimpleCookie()

        for name, cookie in self._cookies.items():
            cookie_domain = cookie["domain"]

            # Send shared cookies
            if not cookie_domain:
                dict.__setitem__(filtered, name, cookie)
                continue

            hostname = url_parsed.hostname or ""

            if not self._unsafe and is_ip_address(hostname):
                continue

            if name in self._host_only_cookies:
                if cookie_domain != hostname:
                    continue
            elif not self._is_domain_match(cookie_domain, hostname):
                continue

            if not self._is_path_match(url_parsed.path, cookie["path"]):
                continue

            is_secure = url_parsed.scheme in ("https", "wss")

            if cookie["secure"] and not is_secure:
                continue

            dict.__setitem__(filtered, name, cookie)

        return filtered

    @staticmethod
    def _is_domain_match(domain, hostname):
        """Implements domain matching adhering to RFC 6265."""
        if hostname == domain:
            return True

        if not hostname.endswith(domain):
            return False

        non_matching = hostname[:-len(domain)]

        if not non_matching.endswith("."):
            return False

        return not is_ip_address(hostname)

    @staticmethod
    def _is_path_match(req_path, cookie_path):
        """Implements path matching adhering to RFC 6265."""
        if req_path == cookie_path:
            return True

        if not req_path.startswith(cookie_path):
            return False

        if cookie_path.endswith("/"):
            return True

        non_matching = req_path[len(cookie_path):]

        return non_matching.startswith("/")

    @classmethod
    def _parse_date(cls, date_str):
        """Implements date string parsing adhering to RFC 6265."""
        if not date_str:
            return

        found_time = False
        found_day_of_month = False
        found_month = False
        found_year = False

        hour = minute = second = 0
        day_of_month = 0
        month = ""
        year = 0

        for token_match in cls.DATE_TOKENS_RE.finditer(date_str):

            token = token_match.group("token")

            if not found_time:
                time_match = cls.DATE_HMS_TIME_RE.match(token)
                if time_match:
                    found_time = True
                    hour, minute, second = [
                        int(s) for s in time_match.groups()]
                    continue

            if not found_day_of_month:
                day_of_month_match = cls.DATE_DAY_OF_MONTH_RE.match(token)
                if day_of_month_match:
                    found_day_of_month = True
                    day_of_month = int(day_of_month_match.group())
                    continue

            if not found_month:
                month_match = cls.DATE_MONTH_RE.match(token)
                if month_match:
                    found_month = True
                    month = month_match.group()
                    continue

            if not found_year:
                year_match = cls.DATE_YEAR_RE.match(token)
                if year_match:
                    found_year = True
                    year = int(year_match.group())

        if 70 <= year <= 99:
            year += 1900
        elif 0 <= year <= 69:
            year += 2000

        if False in (found_day_of_month, found_month, found_year, found_time):
            return

        if not 1 <= day_of_month <= 31:
            return

        if year < 1601 or hour > 23 or minute > 59 or second > 59:
            return

        dt = datetime.datetime.strptime(
            "%s %d %d:%d:%d %d" % (
                month, day_of_month, hour, minute, second, year
            ), "%b %d %H:%M:%S %Y")

        return dt.replace(tzinfo=datetime.timezone.utc)
