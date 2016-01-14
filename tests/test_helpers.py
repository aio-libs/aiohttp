import pytest
from unittest import mock
from aiohttp import helpers
import datetime


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


def test_access_logger_format():
    log_format = '%T {%{SPAM}e} "%{ETag}o" %X {X} %%P'
    mock_logger = mock.Mock()
    access_logger = helpers.AccessLogger(mock_logger, log_format)
    expected = '%s {%s} "%s" %%X {X} %%%s'
    assert expected == access_logger._log_format


@mock.patch("aiohttp.helpers.datetime")
@mock.patch("os.getpid")
def test_access_logger_atoms(mock_getpid, mock_datetime):
    utcnow = datetime.datetime(1843, 1, 1, 0, 0)
    mock_datetime.datetime.utcnow.return_value = utcnow
    mock_getpid.return_value = 42
    log_format = '%a %t %P %l %u %r %s %b %O %T %Tf %D'
    mock_logger = mock.Mock()
    access_logger = helpers.AccessLogger(mock_logger, log_format)
    message = mock.Mock(headers={}, method="GET", path="/path", version=(1, 1))
    environ = {}
    response = mock.Mock(headers={}, output_length=123,
                         body_length=42, status=200)
    transport = mock.Mock()
    transport.get_extra_info.return_value = ("127.0.0.2", 1234)
    access_logger.log(message, environ, response, transport, 3.1415926)
    assert not mock_logger.exception.called
    expected = ('127.0.0.2 [01/Jan/1843:00:00:00 +0000] <42> - - '
                'GET /path HTTP/1.1 200 42 123 3 3.141593 3141593')
    mock_logger.info.assert_called_with(expected)


def test_access_logger_dicts():
    log_format = '%{User-Agent}i %{Content-Length}o %{SPAM}e %{None}i'
    mock_logger = mock.Mock()
    access_logger = helpers.AccessLogger(mock_logger, log_format)
    message = mock.Mock(headers={"USER-AGENT": "Mock/1.0"}, version=(1, 1))
    environ = {"SPAM": "EGGS"}
    response = mock.Mock(headers={"CONTENT-LENGTH": 123})
    transport = mock.Mock()
    transport.get_extra_info.return_value = ("127.0.0.2", 1234)
    access_logger.log(message, environ, response, transport, 0.0)
    assert not mock_logger.error.called
    expected = 'Mock/1.0 123 EGGS -'
    mock_logger.info.assert_called_with(expected)


def test_logger_no_message_and_environ():
    mock_logger = mock.Mock()
    mock_transport = mock.Mock()
    mock_transport.get_extra_info.return_value = ("127.0.0.3", 0)
    access_logger = helpers.AccessLogger(mock_logger, "%r %{FOOBAR}e")
    access_logger.log(None, None, None, mock_transport, 0.0)
    mock_logger.info.assert_called_with("- -")


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


def test_requote_uri_with_unquoted_percents():
    # Ensure we handle unquoted percent signs in redirects.
    bad_uri = 'http://example.com/fiz?buz=%ppicture'
    quoted = 'http://example.com/fiz?buz=%25ppicture'
    assert quoted == helpers.requote_uri(bad_uri)


def test_requote_uri_properly_requotes():
    # Ensure requoting doesn't break expectations.
    quoted = 'http://example.com/fiz?buz=%25ppicture'
    assert quoted == helpers.requote_uri(quoted)
