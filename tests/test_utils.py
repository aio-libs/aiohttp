"""Tests for aiohttp/utils.py"""
import unittest
import unittest.mock

from aiohttp import utils
from aiohttp import multidict


class SafeAtomsTests(unittest.TestCase):

    def test_get_non_existing(self):
        atoms = utils.SafeAtoms(
            {}, multidict.MultiDict(), multidict.MultiDict())
        self.assertEqual(atoms['unknown'], '-')

    def test_get_lower(self):
        i_headers = multidict.MultiDict([('test', '123')])
        o_headers = multidict.MultiDict([('TEST', '123')])

        atoms = utils.SafeAtoms({}, i_headers, o_headers)
        self.assertEqual(atoms['{test}i'], '123')
        self.assertEqual(atoms['{test}o'], '-')
        self.assertEqual(atoms['{TEST}o'], '123')
        self.assertEqual(atoms['{UNKNOWN}o'], '-')
        self.assertEqual(atoms['{UNKNOWN}'], '-')
