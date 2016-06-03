"""Various helper functions"""

import asyncio
import base64
import binascii
import datetime
import functools
import io
import mimetypes
import os
import re
from urllib.parse import quote, urlencode
from collections import namedtuple
from pathlib import Path

import multidict

from . import hdrs
from .errors import InvalidURL
try:
    from asyncio import ensure_future
except ImportError:
    ensure_future = asyncio.async


__all__ = ('BasicAuth', 'create_future', 'FormData', 'parse_mimetype',
           'Timeout')


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
            raise asyncio.TimeoutError
        if self._timeout is not None:
            self._cancel_handler.cancel()
            self._cancel_handler = None
        self._task = None

    def _cancel_task(self):
        self._cancelled = self._task.cancel()


class FileSender:
    """"A helper that can be used to send files.
    """

    def __init__(self, resp_factory, chunk_size):
        self._response_factory = resp_factory
        self._chunk_size = chunk_size
        if bool(os.environ.get("AIOHTTP_NOSENDFILE")):
            self._sendfile = self._sendfile_fallback

    def _sendfile_cb(self, fut, out_fd, in_fd, offset,
                     count, loop, registered):
        if registered:
            loop.remove_writer(out_fd)
        try:
            n = os.sendfile(out_fd, in_fd, offset, count)
            if n == 0:  # EOF reached
                n = count
        except (BlockingIOError, InterruptedError):
            n = 0
        except Exception as exc:
            fut.set_exception(exc)
            return

        if n < count:
            loop.add_writer(out_fd, self._sendfile_cb, fut, out_fd, in_fd,
                            offset + n, count - n, loop, True)
        else:
            fut.set_result(None)

    @asyncio.coroutine
    def _sendfile_system(self, req, resp, fobj, count):
        """
        Write `count` bytes of `fobj` to `resp` starting from `offset` using
        the ``sendfile`` system call.

        `req` should be a :obj:`aiohttp.web.Request` instance.

        `resp` should be a :obj:`aiohttp.web.StreamResponse` instance.

        `fobj` should be an open file object.

        `offset` should be an integer >= 0.

        `count` should be an integer > 0.
        """
        transport = req.transport

        if transport.get_extra_info("sslcontext"):
            yield from self._sendfile_fallback(req, resp, fobj, count)
            return

        yield from resp.drain()

        loop = req.app.loop
        out_fd = transport.get_extra_info("socket").fileno()
        in_fd = fobj.fileno()
        fut = asyncio.Future(loop=loop)

        self._sendfile_cb(fut, out_fd, in_fd, 0, count, loop, False)

        yield from fut

    @asyncio.coroutine
    def _sendfile_fallback(self, req, resp, fobj, count):
        """
        Mimic the :meth:`_sendfile_system` method, but without using the
        ``sendfile`` system call. This should be used on systems that don't
        support the ``sendfile`` system call.

        To avoid blocking the event loop & to keep memory usage low, `fobj` is
        transferred in chunks controlled by the `chunk_size` argument to
        :class:`StaticRoute`.
        """
        chunk_size = self._chunk_size

        chunk = fobj.read(chunk_size)
        while chunk and count > chunk_size:
            resp.write(chunk)
            yield from resp.drain()
            count = count - chunk_size
            chunk = fobj.read(chunk_size)

        if chunk:
            resp.write(chunk[:count])
            yield from resp.drain()

    if hasattr(os, "sendfile"):  # pragma: no cover
        _sendfile = _sendfile_system
    else:  # pragma: no cover
        _sendfile = _sendfile_fallback

    @asyncio.coroutine
    def send(self, req, filepath):
        from .web_exceptions import HTTPNotModified

        st = filepath.stat()

        modsince = req.if_modified_since
        if modsince is not None and st.st_mtime <= modsince.timestamp():
            raise HTTPNotModified()

        ct, encoding = mimetypes.guess_type(str(filepath))
        if not ct:
            ct = 'application/octet-stream'

        resp = self._response_factory()
        resp.content_type = ct
        if encoding:
            resp.headers[hdrs.CONTENT_ENCODING] = encoding
        resp.last_modified = st.st_mtime

        file_size = st.st_size

        resp.content_length = file_size
        resp.set_tcp_cork(True)
        try:
            yield from resp.prepare(req)

            with filepath.open('rb') as f:
                yield from self._sendfile(req, resp, f, file_size)

        finally:
            resp.set_tcp_nodelay(True)

        return resp
