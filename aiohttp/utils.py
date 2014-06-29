import os
from wsgiref.handlers import format_date_time


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
