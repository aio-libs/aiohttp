import pytest

from aiohttp import helpers
from aiohttp import MultiDict


def test_parse_mimetype_1():
    assert helpers.parse_mimetype('') == ('', '', '', {})


def test_parse_mimetype_2():
    assert helpers.parse_mimetype('*') == ('*', '*', '', {})


def test_parse_mimetype_3():
    assert (helpers.parse_mimetype('application/json') ==
            ('application', 'json', '', {}))


def test_parse_mimetype_4():
    assert (
        helpers.parse_mimetype('application/json;  charset=utf-8') ==
        ('application', 'json', '', {'charset': 'utf-8'}))


def test_parse_mimetype_5():
    assert (
        helpers.parse_mimetype('''application/json; charset=utf-8;''') ==
        ('application', 'json', '', {'charset': 'utf-8'}))


def test_parse_mimetype_6():
    assert(
        helpers.parse_mimetype('ApPlIcAtIoN/JSON;ChaRseT="UTF-8"') ==
        ('application', 'json', '', {'charset': 'UTF-8'}))


def test_parse_mimetype_7():
    assert (
        helpers.parse_mimetype('application/rss+xml') ==
        ('application', 'rss', 'xml', {}))


def test_parse_mimetype_8():
    assert (
        helpers.parse_mimetype('text/plain;base64') ==
        ('text', 'plain', '', {'base64': ''}))


def test_basic_auth1():
    # missing password here
    with pytest.raises(ValueError):
        helpers.BasicAuth(None)


def test_basic_auth2():
    with pytest.raises(ValueError):
        helpers.BasicAuth('nkim', None)


def test_basic_auth3():
    auth = helpers.BasicAuth('nkim')
    assert auth.login == 'nkim'
    assert auth.password == ''


def test_basic_auth4():
    auth = helpers.BasicAuth('nkim', 'pwd')
    assert auth.login == 'nkim'
    assert auth.password == 'pwd'
    assert auth.encode() == 'Basic bmtpbTpwd2Q='


def test_invalid_formdata_params():
    with pytest.raises(TypeError):
        helpers.FormData('asdasf')


def test_invalid_formdata_params2():
    with pytest.raises(TypeError):
        helpers.FormData('as')  # 2-char str is not allowed


def test_invalid_formdata_content_type():
    form = helpers.FormData()
    invalid_vals = [0, 0.1, {}, [], b'foo']
    for invalid_val in invalid_vals:
        with pytest.raises(TypeError):
            form.add_field('foo', 'bar', content_type=invalid_val)


def test_invalid_formdata_filename():
    form = helpers.FormData()
    invalid_vals = [0, 0.1, {}, [], b'foo']
    for invalid_val in invalid_vals:
        with pytest.raises(TypeError):
            form.add_field('foo', 'bar', filename=invalid_val)


def test_invalid_formdata_content_transfer_encoding():
    form = helpers.FormData()
    invalid_vals = [0, 0.1, {}, [], b'foo']
    for invalid_val in invalid_vals:
        with pytest.raises(TypeError):
            form.add_field('foo',
                           'bar',
                           content_transfer_encoding=invalid_val)


def test_reify():
    class A:
        @helpers.reify
        def prop(self):
            return 1

    a = A()
    assert 1 == a.prop


def test_reify_class():
    class A:
        @helpers.reify
        def prop(self):
            """Docstring."""
            return 1

    assert isinstance(A.prop, helpers.reify)
    assert 'Docstring.' == A.prop.__doc__


def test_reify_assignment():
    class A:
        @helpers.reify
        def prop(self):
            return 1

    a = A()

    with pytest.raises(AttributeError):
        a.prop = 123


def test_get_seconds_and_milliseconds():
    response = dict(status=200, output_length=1)
    request_time = 321.012345678901234

    atoms = helpers.atoms(None, None, response, None, request_time)
    assert atoms['T'] == '321'
    assert atoms['D'] == '012345'


def test_get_non_existing():
    atoms = helpers.SafeAtoms(
        {}, MultiDict(), MultiDict())
    assert atoms['unknown'] == '-'


def test_get_lower():
    i_headers = MultiDict([('test', '123')])
    o_headers = MultiDict([('TEST', '123')])

    atoms = helpers.SafeAtoms({}, i_headers, o_headers)
    assert atoms['{test}i'] == '123'
    assert atoms['{test}o'] == '-'
    assert atoms['{TEST}o'] == '123'
    assert atoms['{UNKNOWN}o'] == '-'
    assert atoms['{UNKNOWN}'] == '-'


def test_requote_uri_with_unquoted_percents():
    # Ensure we handle unquoted percent signs in redirects.
    bad_uri = 'http://example.com/fiz?buz=%ppicture'
    quoted = 'http://example.com/fiz?buz=%25ppicture'
    assert quoted == helpers.requote_uri(bad_uri)


def test_requote_uri_properly_requotes():
    # Ensure requoting doesn't break expectations.
    quoted = 'http://example.com/fiz?buz=%25ppicture'
    assert quoted == helpers.requote_uri(quoted)
