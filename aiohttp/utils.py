import os
from wsgiref.handlers import format_date_time


def atoms(message, environ, response, request_time):
    """Gets atoms for log formating."""
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

    # add request headers
    if message:
        atoms.update(
            dict([("{%s}i" % k.lower(), v) for k, v in message.headers]))

    # add response headers
    atoms.update(
        dict([("{%s}o" % k.lower(), v) for k, v in response.headers]))

    return atoms


class SafeAtoms(dict):
    """Copy from gunicorn"""

    def __init__(self, atoms):
        dict.__init__(self)
        for key, value in atoms.items():
            self[key] = value.replace('"', '\\"')

    def __getitem__(self, k):
        if k.startswith("{"):
            kl = k.lower()
            if kl in self:
                return super(SafeAtoms, self).__getitem__(kl)
            else:
                return "-"
        if k in self:
            return super(SafeAtoms, self).__getitem__(k)
        else:
            return '-'
