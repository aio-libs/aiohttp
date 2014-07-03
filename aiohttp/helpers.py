"""Various helper functions"""


def parse_mimetype(mimetype):
    """Parses a MIME type into it components.

    :param str mimetype: MIME type

    :returns: 4 element tuple for MIME type, subtype, suffix and parameters
    :rtype: tuple

    >>> parse_mimetype('*')
    ('*', '*', '', {})

    >>> parse_mimetype('application/json')
    ('application', 'json', '', {})

    >>> parse_mimetype('application/json;  charset=utf-8')
    ('application', 'json', '', {'charset': 'utf-8'})

    >>> parse_mimetype('''application/json;
    ...                   charset=utf-8;''')
    ('application', 'json', '', {'charset': 'utf-8'})

    >>> parse_mimetype('ApPlIcAtIoN/JSON;ChaRseT="UTF-8"')
    ('application', 'json', '', {'charset': 'UTF-8'})

    >>> parse_mimetype('application/rss+xml')
    ('application', 'rss', 'xml', {})

    >>> parse_mimetype('text/plain;base64')
    ('text', 'plain', '', {'base64': ''})

    """
    if not mimetype:
        return '', '', '', {}

    parts = mimetype.split(';')
    params = []
    for item in parts[1:]:
        if not item:
            continue
        key, value = item.split('=', 2) if '=' in item else (item, '')
        params.append((key.lower().strip(), value.strip(' "')))
    params = dict(params)

    fulltype = parts[0].strip().lower()
    if fulltype == '*':
        fulltype = '*/*'
    mtype, stype = fulltype.split('/', 2) if '/' in fulltype else (fulltype, '')
    stype, suffix = stype.split('+') if '+' in stype else (stype, '')

    return mtype, stype, suffix, params
