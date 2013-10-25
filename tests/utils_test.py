"""Tests for aiohttp/utils.py"""
import unittest
import unittest.mock

from aiohttp import utils


class SafeAtomsTests(unittest.TestCase):

    def test_get_non_existing(self):
        atoms = utils.SafeAtoms({})
        self.assertEqual(atoms['unknown'], '-')

    def test_get_lower(self):
        atoms = utils.SafeAtoms({'{test}': '123'})
        self.assertEqual(atoms['{test}'], '123')
        self.assertEqual(atoms['{TEST}'], '123')
        self.assertEqual(atoms['{UNKNOWN}'], '-')
