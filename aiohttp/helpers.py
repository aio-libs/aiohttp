"""Various helper functions"""
__all__ = ['BasicAuth', 'FormData', 'parse_mimetype']

import base64
import io
import os
import uuid
import urllib.parse
from collections import namedtuple
from wsgiref.handlers import format_date_time

from . import multidict


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

    def __init__(self, fields):
        self._fields = []
        self._has_io = False
        self._boundary = uuid.uuid4().hex

        if isinstance(fields, dict):
            fields = list(fields.items())
        elif not isinstance(fields, (list, tuple)):
            fields = (fields,)
        self.add_fields(*fields)

    def is_form_data(self):
        return self._has_io

    @property
    def contenttype(self):
        if self._has_io:
            return 'multipart/form-data; boundary=%s' % self._boundary
        else:
            return 'application/x-www-form-urlencoded'

    def add_field(self, name, value, contenttype=None, filename=None):
        if filename is None and isinstance(value, io.IOBase):
            filename = name

        self._fields.append((name, value, contenttype, filename))

    def add_fields(self, *fields):
        to_add = list(fields)

        while to_add:
            rec = to_add.pop(0)

            if isinstance(rec, io.IOBase):
                k = guess_filename(rec, 'unknown')
                self.add_field(k, rec)
                self._has_io = True

            elif isinstance(rec, multidict.MultiDict):
                to_add.extend(rec.items(getall=True))

            elif len(rec) == 1:
                k = guess_filename(rec[0], 'unknown')
                self.add_field(k, rec[0])
                if isinstance(rec[0], io.IOBase):
                    self._has_io = True

            elif len(rec) == 2:
                k, fp = rec
                fn = guess_filename(fp)
                self.add_field(k, fp, filename=fn)
                if isinstance(fp, io.IOBase):
                    self._has_io = True

            else:
                k, fp, ft = rec
                fn = guess_filename(fp, k)
                self.add_field(k, fp, contenttype=ft, filename=fn)
                self._has_io = True

    def gen_form_urlencoded(self, encoding):
        # form data (x-www-form-urlencoded)
        data = []
        for name, value, contenttype, filename in self._fields:
            data.append((name, value))

        data = urllib.parse.urlencode(data, doseq=True)
        return data.encode(encoding)

    def gen_form_data(self, encoding='utf-8', chunk_size=8196):
        """Encode a list of fields using the multipart/form-data MIME format"""
        boundary = self._boundary.encode('latin1')

        for name, value, ctype, fname in self._fields:
            yield b'--' + boundary + b'\r\n'

            headers = []
            if fname:
                headers.append(
                    ('Content-Disposition: form-data; name="%s"; '
                     'filename="%s"\r\n' % (name, fname)).encode(encoding))
            else:
                headers.append(
                    ('Content-Disposition: form-data; name="%s"\r\n\r\n' %
                     name).encode(encoding))
            if ctype:
                headers.append(
                    ('Content-Type: %s\r\n\r\n' % ctype).encode(encoding))

            yield b''.join(headers)

            if isinstance(value, str):
                yield value.encode(encoding)
            else:
                if isinstance(value, (bytes, bytearray)):
                    value = io.BytesIO(value)

                while True:
                    chunk = value.read(chunk_size)
                    if not chunk:
                        break
                    yield str_to_bytes(chunk, encoding)

            yield b'\r\n'

        yield b'--' + boundary + b'--\r\n'

    def __call__(self, encoding):
        if self._has_io:
            return self.gen_form_data(encoding)
        else:
            return self.gen_form_urlencoded(encoding)


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


def atoms(message, environ, response, request_time):
    """Gets atoms for log formatting."""
    if message:
        r = '{} {} HTTP/{}.{}'.format(
            message.method, message.path,
            message.version[0], message.version[1])
    else:
        r = ''

    atoms = {
        'h': environ.get('REMOTE_ADDR', '-'),
        'l': '-',
        'u': '-',
        't': format_date_time(None),
        'r': r,
        's': str(response.status),
        'b': str(response.output_length),
        'f': environ.get('HTTP_REFERER', '-'),
        'a': environ.get('HTTP_USER_AGENT', '-'),
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
