import unittest
import unittest.mock

from aiohttp import helpers
from aiohttp import MultiDict


class TestHelpers(unittest.TestCase):

    def test_parse_mimetype(self):
        self.assertEqual(
            helpers.parse_mimetype(''), ('', '', '', {}))

        self.assertEqual(
            helpers.parse_mimetype('*'), ('*', '*', '', {}))

        self.assertEqual(
            helpers.parse_mimetype('application/json'),
            ('application', 'json', '', {}))

        self.assertEqual(
            helpers.parse_mimetype('application/json;  charset=utf-8'),
            ('application', 'json', '', {'charset': 'utf-8'}))

        self.assertEqual(
            helpers.parse_mimetype('''application/json; charset=utf-8;'''),
            ('application', 'json', '', {'charset': 'utf-8'}))

        self.assertEqual(
            helpers.parse_mimetype('ApPlIcAtIoN/JSON;ChaRseT="UTF-8"'),
            ('application', 'json', '', {'charset': 'UTF-8'}))

        self.assertEqual(
            helpers.parse_mimetype('application/rss+xml'),
            ('application', 'rss', 'xml', {}))

        self.assertEqual(
            helpers.parse_mimetype('text/plain;base64'),
            ('text', 'plain', '', {'base64': ''}))

    def test_basic_auth(self):
        # missing password here
        self.assertRaises(
            ValueError, helpers.BasicAuth, None)
        self.assertRaises(
            ValueError, helpers.BasicAuth, 'nkim', None)

        auth = helpers.BasicAuth('nkim')
        self.assertEqual(auth.login, 'nkim')
        self.assertEqual(auth.password, '')

        auth = helpers.BasicAuth('nkim', 'pwd')
        self.assertEqual(auth.login, 'nkim')
        self.assertEqual(auth.password, 'pwd')
        self.assertEqual(auth.encode(), 'Basic bmtpbTpwd2Q=')

    def test_invalid_formdata_params(self):
        with self.assertRaises(TypeError):
            helpers.FormData('asdasf')

    def test_invalid_formdata_params2(self):
        with self.assertRaises(TypeError):
            helpers.FormData('as')  # 2-char str is not allowed

    def test_invalid_formdata_content_type(self):
        form = helpers.FormData()
        invalid_vals = [0, 0.1, {}, [], b'foo']
        for invalid_val in invalid_vals:
            with self.assertRaises(TypeError):
                form.add_field('foo', 'bar', content_type=invalid_val)

    def test_invalid_formdata_filename(self):
        form = helpers.FormData()
        invalid_vals = [0, 0.1, {}, [], b'foo']
        for invalid_val in invalid_vals:
            with self.assertRaises(TypeError):
                form.add_field('foo', 'bar', filename=invalid_val)

    def test_invalid_formdata_content_transfer_encoding(self):
        form = helpers.FormData()
        invalid_vals = [0, 0.1, {}, [], b'foo']
        for invalid_val in invalid_vals:
            with self.assertRaises(TypeError):
                form.add_field('foo',
                               'bar',
                               content_transfer_encoding=invalid_val)

    def test_reify(self):
        class A:
            @helpers.reify
            def prop(self):
                return 1

        a = A()
        self.assertEqual(1, a.prop)

    def test_reify_class(self):
        class A:
            @helpers.reify
            def prop(self):
                """Docstring."""
                return 1

        self.assertIsInstance(A.prop, helpers.reify)
        self.assertEqual('Docstring.', A.prop.__doc__)

    def test_reify_assignment(self):
        class A:
            @helpers.reify
            def prop(self):
                return 1

        a = A()

        with self.assertRaises(AttributeError):
            a.prop = 123


class TestSafeAtoms(unittest.TestCase):

    def test_get_non_existing(self):
        atoms = helpers.SafeAtoms(
            {}, MultiDict(), MultiDict())
        self.assertEqual(atoms['unknown'], '-')

    def test_get_lower(self):
        i_headers = MultiDict([('test', '123')])
        o_headers = MultiDict([('TEST', '123')])

        atoms = helpers.SafeAtoms({}, i_headers, o_headers)
        self.assertEqual(atoms['{test}i'], '123')
        self.assertEqual(atoms['{test}o'], '-')
        self.assertEqual(atoms['{TEST}o'], '123')
        self.assertEqual(atoms['{UNKNOWN}o'], '-')
        self.assertEqual(atoms['{UNKNOWN}'], '-')
