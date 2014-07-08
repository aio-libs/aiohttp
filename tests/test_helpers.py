import unittest
import unittest.mock

from aiohttp import helpers


class HelpersTests(unittest.TestCase):

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
