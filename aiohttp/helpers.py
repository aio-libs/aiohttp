"""Various helper functions"""
import base64
import io
import os
import urllib.parse
from collections import namedtuple
from wsgiref.handlers import format_date_time

from . import hdrs, multidict

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

        data = urllib.parse.urlencode(data, doseq=True)
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


def atoms(message, environ, response, transport, request_time):
    """Gets atoms for log formatting."""
    if message:
        r = '{} {} HTTP/{}.{}'.format(
            message.method, message.path,
            message.version[0], message.version[1])
        headers = message.headers
    else:
        r = ''
        headers = {}

    if transport is not None:
        remote_addr = parse_remote_addr(
            transport.get_extra_info('addr', '127.0.0.1'))
    else:
        remote_addr = ('',)

    atoms = {
        'h': remote_addr[0],
        'l': '-',
        'u': '-',
        't': format_date_time(None),
        'r': r,
        's': str(getattr(response, 'status', '')),
        'b': str(getattr(response, 'output_length', '')),
        'f': headers.get(hdrs.REFERER, '-'),
        'a': headers.get(hdrs.USER_AGENT, '-'),
        'T': str(int(request_time)),
        'D': str(request_time).split('.', 1)[-1][:5],
        'p': "<%s>" % os.getpid()
    }

    return atoms


class SafeAtoms(dict):
    """Copy from gunicorn"""

    def __init__(self, atoms, i_headers, o_headers):
        dict.__init__(self)

        self._i_headers = i_headers
        self._o_headers = o_headers

        for key, value in atoms.items():
            self[key] = value.replace('"', '\\"')

    def __getitem__(self, k):
        if k.startswith('{'):
            if k.endswith('}i'):
                headers = self._i_headers
            elif k.endswith('}o'):
                headers = self._o_headers
            else:
                headers = None

            if headers is not None:
                return headers.get(k[1:-2], '-')

        if k in self:
            return super(SafeAtoms, self).__getitem__(k)
        else:
            return '-'


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
