"""Various helper functions"""
import base64
import datetime
import io
import os
import re
import traceback
from urllib.parse import quote, urlencode
from collections import namedtuple

from . import hdrs, multidict
from .errors import InvalidURL

__all__ = ('BasicAuth', 'FormData', 'parse_mimetype')


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

    def encode(self):
        """Encode credentials."""
        creds = ('%s:%s' % (self.login, self.password)).encode(self.encoding)
        return 'Basic %s' % base64.b64encode(creds).decode(self.encoding)


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
        return os.path.split(name)[-1]
    return default


def parse_remote_addr(forward):
    if isinstance(forward, str):
        # we only took the last one
        # http://en.wikipedia.org/wiki/X-Forwarded-For
        if ',' in forward:
            forward = forward.rsplit(',', 1)[-1].strip()

        # find host and port on ipv6 address
        if '[' in forward and ']' in forward:
            host = forward.split(']')[0][1:].lower()
        elif ':' in forward and forward.count(':') == 1:
            host = forward.split(':')[0].lower()
        else:
            host = forward

        forward = forward.split(']')[-1]
        if ':' in forward and forward.count(':') == 1:
            port = forward.split(':', 1)[1]
        else:
            port = 80

        remote = (host, port)
    else:
        remote = forward

    return remote[0], str(remote[1])


class SafeDict(dict):
    """Return a dash instead of raising KeyError"""

    def __getitem__(self, key):
        val = dict.get(self, key.upper())
        return val or "-"


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
        %t  Time the request was received
        %P  The process ID of the child that serviced the request
        %r  First line of request
        %s  Status
        %b  Size of response in bytes, excluding HTTP headers
        %O  Bytes sent, including headers
        %T  The time taken to serve the request, in seconds
        %D  The time taken to serve the request, in microseconds
        %{Foobar}i  The contents of Foobar: header line(s) in
                    the request sent to the server
        %{Foobar}o  The contents of Foobar: header line(s) in the reply
        %{FOOBAR}e  The contents of the environment variable FOOBAR

    """

    HEADERS_RE = re.compile(r"%\{\{([a-z\-]+)\}\}(i|o|e)", re.IGNORECASE)
    ATOMS_RE = re.compile(r"%[atPlursbOTD%]")
    BRACE_RE = re.compile(r"(\{|\})")
    TIME_FORMAT = "[%d/%b/%Y:%H:%M:%S +0000]"

    def __init__(self, logger, log_format):
        """Initialize the logger.

        :param logger: logger object to be used for logging
        :param log_format: apache (almost) compatible log format

        Given log_format translated to form usable by `string.format`.

        %{FOOBAR}i -- Input headers. Translated to {i_dict[FOOBAR]}
        %{FOOBAR}o -- Iutput headers. Translated to {o_dict[FOOBAR]}
        %{FOOBAR}e -- Environment variables. Translated to {e_dict[FOOBAR]}
        %? -- One of atoms. Translated according to `atoms` dict (see below)
        """
        atoms = {
            'a': '{remote_addr}',
            't': '{datetime}',
            'P': "<%s>" % os.getpid(),
            'l': '-',
            'u': '-',
            'r': '{r}',
            's': '{response.status}',
            'b': '{response.body_length}',
            'O': '{response.output_length}',
            'T': '{time:.0f}',
            'D': '{microseconds:.0f}',
            '%': '%',  # `%%` should be converted to `%`
        }
        # replace single braces with double to avoid direct usage
        log_format = self.BRACE_RE.sub(r"\1\1", log_format)
        for atom in self.ATOMS_RE.findall(log_format):
            log_format = log_format.replace(atom, atoms[atom[1]])
        self._log_format = self.HEADERS_RE.sub(r"{\2_dict[\1]}", log_format)
        self.logger = logger

    def log(self, message, environ, response, transport, time):
        """Log access.

        :param message: Request object. May be None.
        :param environ: Environment dict. May be None.
        :param response: Response object.
        :param transport: Tansport object.
        :param float time: Time taken to serve the request.
        """
        environ = environ or {}
        if message:
            r = "%s %s HTTP/%s.%s" % tuple((message.method,
                                            message.path) + message.version)
        else:
            r = "-"
        try:
            self.logger.info(self._log_format.format(
                message=message,
                response=response,
                i_dict=SafeDict(getattr(message, "headers", {})),
                o_dict=SafeDict(getattr(response, "headers", {})),
                e_dict=SafeDict(environ),
                remote_addr=transport.get_extra_info("peername")[0],
                time=time,
                r=r,
                datetime=datetime.datetime.utcnow().strftime(self.TIME_FORMAT),
                microseconds=time*1000000,
            ))
        except:
            self.logger.error(traceback.format_exc())


_marker = object()


class reify:
    """Use as a class method decorator.  It operates almost exactly like
    the Python ``@property`` decorator, but it puts the result of the
    method it decorates into the instance dict after the first call,
    effectively replacing the function it decorates with an instance
    variable.  It is, in Python parlance, a non-data descriptor.

    """

    def __init__(self, wrapped):
        self.wrapped = wrapped
        try:
            self.__doc__ = wrapped.__doc__
        except:  # pragma: no cover
            pass
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
