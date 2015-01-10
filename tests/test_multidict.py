import sys
import unittest

from aiohttp.multidict import (MultiDict,
                               MutableMultiDict,
                               CaseInsensitiveMultiDict,
                               CaseInsensitiveMutableMultiDict,
                               cistr,
                               _MultiDict,
                               _MutableMultiDict,
                               _CaseInsensitiveMultiDict,
                               _CaseInsensitiveMutableMultiDict,
                               _cistr)


import aiohttp


HAS_NO_SET_OPS_FOR_VIEW = sys.version_info < (3, 4)


class _Root:

    cls = None

    def make_dict(self, *args, **kwargs):
        return self.cls(*args, **kwargs)

    def test_exposed_names(self):
        name = self.cls.__name__
        while name.startswith('_'):
            name = name[1:]
        self.assertIn(name, aiohttp.__all__)


class _BaseTest(_Root):

    def test_instantiate__empty(self):
        d = self.make_dict()
        self.assertEqual(d, {})
        self.assertEqual(len(d), 0)
        self.assertEqual(list(d.keys()), [])
        self.assertEqual(list(d.values()), [])
        self.assertEqual(list(d.values(getall=True)), [])
        self.assertEqual(list(d.items()), [])
        self.assertEqual(list(d.items(getall=True)), [])

        self.assertNotEqual(self.make_dict(), list())
        with self.assertRaisesRegex(TypeError, "\(2 given\)"):
            self.make_dict(('key1', 'value1'), ('key2', 'value2'))

    def test_instantiate__from_arg0(self):
        d = self.make_dict([('key', 'value1')])

        self.assertEqual(d, {'key': 'value1'})
        self.assertEqual(len(d), 1)
        self.assertEqual(list(d.keys()), ['key'])
        self.assertEqual(list(d.values()), ['value1'])
        self.assertEqual(list(d.values(getall=True)), ['value1'])
        self.assertEqual(list(d.items()), [('key', 'value1')])
        self.assertEqual(list(d.items(getall=True)), [('key', 'value1')])

    def test_instantiate__from_arg0_dict(self):
        d = self.make_dict({'key': 'value1'})

        self.assertEqual(d, {'key': 'value1'})
        self.assertEqual(len(d), 1)
        self.assertEqual(list(d.keys()), ['key'])
        self.assertEqual(list(d.values()), ['value1'])
        self.assertEqual(list(d.values(getall=True)), ['value1'])
        self.assertEqual(list(d.items()), [('key', 'value1')])
        self.assertEqual(list(d.items(getall=True)), [('key', 'value1')])

    def test_instantiate__with_kwargs(self):
        d = self.make_dict([('key', 'value1')], key2='value2')

        self.assertEqual(d, {'key': 'value1', 'key2': 'value2'})
        self.assertEqual(len(d), 2)
        self.assertEqual(sorted(d.keys()), ['key', 'key2'])
        self.assertEqual(sorted(d.values()), ['value1', 'value2'])
        self.assertEqual(sorted(d.items()), [('key', 'value1'),
                                             ('key2', 'value2')])

    def test_getone(self):
        d = self.make_dict([('key', 'value1')], key='value2')
        self.assertEqual(d.getone('key'), 'value1')
        self.assertEqual(d.get('key'), 'value1')
        self.assertEqual(d['key'], 'value1')

        with self.assertRaises(KeyError):
            d['key2']
        with self.assertRaises(KeyError):
            d.getone('key2')

        self.assertEqual('default', d.getone('key2', 'default'))

    def test_copy(self):
        d1 = self.make_dict(key='value', a='b')

        d2 = d1.copy()
        self.assertEqual(d1, d2)
        self.assertIsNot(d1, d2)

    def test__iter__(self):
        d = self.make_dict([('key', 'one'), ('key2', 'two'), ('key', 3)])
        self.assertEqual(['key', 'key2', 'key'], list(d))

    def test_keys__contains(self):
        d = self.make_dict([('key', 'one'), ('key2', 'two'), ('key', 3)])
        self.assertEqual(list(d.keys(getall=False)), ['key', 'key2'])
        self.assertEqual(list(d.keys(getall=True)), ['key', 'key2', 'key'])
        self.assertEqual(list(d.keys()), ['key', 'key2', 'key'])

        self.assertIn('key', d.keys(getall=False))
        self.assertIn('key2', d.keys(getall=False))

        self.assertIn('key', d.keys(getall=True))
        self.assertIn('key2', d.keys(getall=True))

        self.assertNotIn('foo', d.keys(getall=False))
        self.assertNotIn('foo', d.keys(getall=True))

    def test_values__contains(self):
        d = self.make_dict([('key', 'one'), ('key', 'two'), ('key', 3)])
        self.assertEqual(list(d.values(getall=False)), ['one'])
        self.assertEqual(list(d.values(getall=True)), ['one', 'two', 3])
        self.assertEqual(list(d.values()), ['one', 'two', 3])

        self.assertIn('one', d.values(getall=False))
        self.assertNotIn('two', d.values(getall=False))
        self.assertNotIn(3, d.values(getall=False))

        self.assertIn('one', d.values(getall=True))
        self.assertIn('two', d.values(getall=True))
        self.assertIn(3, d.values(getall=True))

        self.assertNotIn('foo', d.values(getall=False))
        self.assertNotIn('foo', d.values(getall=True))

    def test_items__contains(self):
        d = self.make_dict([('key', 'one'), ('key', 'two'), ('key', 3)])
        self.assertEqual(list(d.items(getall=False)), [('key', 'one')])
        self.assertEqual(list(d.items(getall=True)),
                         [('key', 'one'), ('key', 'two'), ('key', 3)])
        self.assertEqual(list(d.items()),
                         [('key', 'one'), ('key', 'two'), ('key', 3)])

        self.assertIn(('key', 'one'), d.items(getall=False))
        self.assertNotIn(('key', 'two'), d.items(getall=False))
        self.assertNotIn(('key', 3), d.items(getall=False))

        self.assertIn(('key', 'one'), d.items(getall=True))
        self.assertIn(('key', 'two'), d.items(getall=True))
        self.assertIn(('key', 3), d.items(getall=True))

        self.assertNotIn(('foo', 'bar'), d.items(getall=False))
        self.assertNotIn(('foo', 'bar'), d.items(getall=True))

    def test_cannot_create_from_unaccepted(self):
        with self.assertRaises(TypeError):
            self.make_dict([(1, 2, 3)])

    @unittest.skipIf(HAS_NO_SET_OPS_FOR_VIEW,
                     "Set operations on views not supported")
    def test_keys_is_set_less(self):
        d = self.make_dict([('key', 'value1')])

        self.assertLess(d.keys(), {'key', 'key2'})

    @unittest.skipIf(HAS_NO_SET_OPS_FOR_VIEW,
                     "Set operations on views not supported")
    def test_keys_is_set_less_equal(self):
        d = self.make_dict([('key', 'value1')])

        self.assertLessEqual(d.keys(), {'key'})

    @unittest.skipIf(HAS_NO_SET_OPS_FOR_VIEW,
                     "Set operations on views not supported")
    def test_keys_is_set_equal(self):
        d = self.make_dict([('key', 'value1')])

        self.assertEqual(d.keys(), {'key'})

    @unittest.skipIf(HAS_NO_SET_OPS_FOR_VIEW,
                     "Set operations on views not supported")
    def test_keys_is_set_greater(self):
        d = self.make_dict([('key', 'value1')])

        self.assertGreater({'key', 'key2'}, d.keys())

    @unittest.skipIf(HAS_NO_SET_OPS_FOR_VIEW,
                     "Set operations on views not supported")
    def test_keys_is_set_greater_equal(self):
        d = self.make_dict([('key', 'value1')])

        self.assertGreaterEqual({'key'}, d.keys())

    @unittest.skipIf(HAS_NO_SET_OPS_FOR_VIEW,
                     "Set operations on views not supported")
    def test_keys_is_set_not_equal(self):
        d = self.make_dict([('key', 'value1')])

        self.assertNotEqual(d.keys(), {'key2'})

    @unittest.skipIf(HAS_NO_SET_OPS_FOR_VIEW,
                     "Set operations on views not supported")
    def test_eq(self):
        d = self.make_dict([('key', 'value1')])
        self.assertEqual({'key': 'value1'}, d)

    @unittest.skipIf(HAS_NO_SET_OPS_FOR_VIEW,
                     "Set operations on views not supported")
    def test_and(self):
        d = self.make_dict([('key', 'value1')])
        self.assertEqual({'key'}, d.keys() & {'key', 'key2'})

    @unittest.skipIf(HAS_NO_SET_OPS_FOR_VIEW,
                     "Set operations on views not supported")
    def test_or(self):
        d = self.make_dict([('key', 'value1')])
        self.assertEqual({'key', 'key2'}, d.keys() | {'key2'})

    @unittest.skipIf(HAS_NO_SET_OPS_FOR_VIEW,
                     "Set operations on views not supported")
    def test_sub(self):
        d = self.make_dict([('key', 'value1'), ('key2', 'value2')])
        self.assertEqual({'key'}, d.keys() - {'key2'})

    @unittest.skipIf(HAS_NO_SET_OPS_FOR_VIEW,
                     "Set operations on views not supported")
    def test_xor(self):
        d = self.make_dict([('key', 'value1'), ('key2', 'value2')])
        self.assertEqual({'key', 'key3'}, d.keys() ^ {'key2', 'key3'})

    @unittest.skipIf(HAS_NO_SET_OPS_FOR_VIEW,
                     "Set operations on views not supported")
    def test_isdisjoint(self):
        d = self.make_dict([('key', 'value1')])
        self.assertTrue(d.keys().isdisjoint({'key2'}))

    @unittest.skipIf(HAS_NO_SET_OPS_FOR_VIEW,
                     "Set operations on views not supported")
    def test_isdisjoint2(self):
        d = self.make_dict([('key', 'value1')])
        self.assertFalse(d.keys().isdisjoint({'key'}))


class _MultiDictTests(_BaseTest):

    def test__repr__(self):
        d = self.make_dict()
        self.assertEqual(str(d), "<%s>\n[]" % self.cls.__name__)
        d = self.make_dict([('key', 'one'), ('key', 'two')])
        self.assertEqual(
            str(d),
            "<%s>\n[('key', 'one'), ('key', 'two')]" % self.cls.__name__)

    def test_getall(self):
        d = self.make_dict([('key', 'value1')], key='value2')

        self.assertNotEqual(d, {'key': 'value1'})
        self.assertEqual(len(d), 2)

        self.assertEqual(d.getall('key'), ['value1', 'value2'])

        with self.assertRaisesRegex(KeyError, "some_key"):
            d.getall('some_key')

        default = object()
        self.assertIs(d.getall('some_key', default), default)

    def test_preserve_stable_ordering(self):
        d = self.make_dict([('a', 1), ('b', '2'), ('a', 3)])
        s = '&'.join('{}={}'.format(k, v) for k, v in d.items(getall=True))

        self.assertEqual('a=1&b=2&a=3', s)


class _CaseInsensitiveMultiDictTests(_Root):

    def test_basics(self):
        d = self.make_dict([('KEY', 'value1')], KEY='value2')
        self.assertEqual(d.getone('key'), 'value1')
        self.assertEqual(d.get('key'), 'value1')
        self.assertEqual(d.get('key2', 'val'), 'val')
        self.assertEqual(d['key'], 'value1')
        self.assertIn('key', d)

        with self.assertRaises(KeyError):
            d['key2']
        with self.assertRaises(KeyError):
            d.getone('key2')

    def test_getall(self):
        d = self.make_dict([('KEY', 'value1')], KEY='value2')

        self.assertNotEqual(d, {'KEY': 'value1'})
        self.assertEqual(len(d), 2)

        self.assertEqual(d.getall('key'), ['value1', 'value2'])

        with self.assertRaisesRegex(KeyError, "SOME_KEY"):
            d.getall('some_key')


class _BaseMutableMultiDictTests(_BaseTest):

    def test__repr__(self):
        d = self.make_dict()
        self.assertEqual(str(d), "<%s>\n[]" % self.cls.__name__)

        d = self.make_dict([('key', 'one'), ('key', 'two')])

        self.assertEqual(
            str(d),
            "<%s>\n[('key', 'one'), ('key', 'two')]" % self.cls.__name__)

    def test_getall(self):
        d = self.make_dict([('key', 'value1')], key='value2')
        self.assertEqual(len(d), 2)

        self.assertEqual(d.getall('key'), ['value1', 'value2'])

        with self.assertRaisesRegex(KeyError, "some_key"):
            d.getall('some_key')

        default = object()
        self.assertIs(d.getall('some_key', default), default)

    def test_add(self):
        d = self.make_dict()

        self.assertEqual(d, {})
        d['key'] = 'one'
        self.assertEqual(d, {'key': 'one'})
        self.assertEqual(d.getall('key'), ['one'])

        d['key'] = 'two'
        self.assertEqual(d, {'key': 'two'})
        self.assertEqual(d.getall('key'), ['two'])

        d.add('key', 'one')
        self.assertEqual(2, len(d))
        self.assertEqual(d.getall('key'), ['two', 'one'])

        d.add('foo', 'bar')
        self.assertEqual(3, len(d))
        self.assertEqual(d.getall('foo'), ['bar'])

    def test_extend(self):
        d = self.make_dict()
        self.assertEqual(d, {})

        d.extend([('key', 'one'), ('key', 'two')], key=3, foo='bar')
        self.assertNotEqual(d, {'key': 'one', 'foo': 'bar'})
        self.assertEqual(4, len(d))
        itms = d.items(getall=True)
        # we can't guarantee order of kwargs
        self.assertTrue(('key', 'one') in itms)
        self.assertTrue(('key', 'two') in itms)
        self.assertTrue(('key', 3) in itms)
        self.assertTrue(('foo', 'bar') in itms)

        other = self.make_dict(bar='baz')
        self.assertEqual(other, {'bar': 'baz'})

        d.extend(other)
        self.assertIn(('bar', 'baz'), d.items(getall=True))

        d.extend({'foo': 'moo'})
        self.assertIn(('foo', 'moo'), d.items(getall=True))

        d.extend()
        self.assertEqual(6, len(d))

        with self.assertRaises(TypeError):
            d.extend('foo', 'bar')

    def test_clear(self):
        d = self.make_dict([('key', 'one')], key='two', foo='bar')

        d.clear()
        self.assertEqual(d, {})
        self.assertEqual(list(d.items(getall=True)), [])

    def test_del(self):
        d = self.make_dict([('key', 'one'), ('key', 'two')], foo='bar')

        del d['key']
        self.assertEqual(d, {'foo': 'bar'})
        self.assertEqual(list(d.items(getall=True)), [('foo', 'bar')])

        with self.assertRaises(KeyError):
            del d['key']

    def test_set_default(self):
        d = self.make_dict([('key', 'one'), ('key', 'two')], foo='bar')
        self.assertEqual('one', d.setdefault('key', 'three'))
        self.assertEqual('three', d.setdefault('otherkey', 'three'))
        self.assertIn('otherkey', d)
        self.assertEqual('three', d['otherkey'])

    def test_not_implemented_methods(self):
        d = self.make_dict()

        with self.assertRaises(NotImplementedError):
            d.pop('foo')
        with self.assertRaises(NotImplementedError):
            d.popitem()
        with self.assertRaises(NotImplementedError):
            d.update(bar='baz')


class _CaseInsensitiveMutableMultiDictTests(_Root):

    def test_getall(self):
        d = self.make_dict([('KEY', 'value1')], KEY='value2')

        self.assertNotEqual(d, {'KEY': 'value1'})
        self.assertEqual(len(d), 2)

        self.assertEqual(d.getall('key'), ['value1', 'value2'])

        with self.assertRaisesRegex(KeyError, "SOME_KEY"):
            d.getall('some_key')

    def test_ctor(self):
        d = self.make_dict(k1='v1')
        self.assertEqual('v1', d['K1'])

    def test_add(self):
        d = self.make_dict()
        d.add('k1', 'v1')
        self.assertEqual('v1', d['K1'])

    def test_setitem(self):
        d = self.make_dict()
        d['k1'] = 'v1'
        self.assertEqual('v1', d['K1'])

    def test_delitem(self):
        d = self.make_dict()
        d['k1'] = 'v1'
        self.assertIn('K1', d)
        del d['k1']
        self.assertNotIn('K1', d)


class PyMultiDictTests(_MultiDictTests, unittest.TestCase):

    cls = _MultiDict


class PyCaseInsensitiveMultiDictTests(_CaseInsensitiveMultiDictTests,
                                      unittest.TestCase):

    cls = _CaseInsensitiveMultiDict


class PyMutableMultiDictTests(_BaseMutableMultiDictTests, unittest.TestCase):

    cls = _MutableMultiDict


class PyCaseInsensitiveMutableMultiDictTests(
        _CaseInsensitiveMutableMultiDictTests,
        unittest.TestCase):

    cls = _CaseInsensitiveMutableMultiDict


class MultiDictTests(_MultiDictTests, unittest.TestCase):

    cls = MultiDict


class CaseInsensitiveMultiDictTests(_CaseInsensitiveMultiDictTests,
                                    unittest.TestCase):

    cls = CaseInsensitiveMultiDict


class MutableMultiDictTests(_BaseMutableMultiDictTests, unittest.TestCase):

    cls = MutableMultiDict


class CaseInsensitiveMutableMultiDictTests(
        _CaseInsensitiveMutableMultiDictTests,
        unittest.TestCase):

    cls = CaseInsensitiveMutableMultiDict


class _CaseInsensitiveStrMixin:

    cls = None

    def test_ctor(self):
        s = self.cls()
        self.assertEqual('', s)

    def test_ctor_str(self):
        s = self.cls('a')
        self.assertEqual('A', s)

    def test_ctor_str_uppercase(self):
        s = self.cls('A')
        self.assertEqual('A', s)

    def test_ctor_buffer(self):
        s = self.cls(b'a')
        self.assertEqual('A', s)

    def test_ctor_repr(self):
        s = self.cls(None)
        self.assertEqual('NONE', s)

    def test_upper(self):
        s = self.cls('a')
        self.assertIs(s, s.upper())


class PyCaseInsensitiveStr(_CaseInsensitiveStrMixin, unittest.TestCase):

    cls = _cistr


class CaseInsensitiveStr(_CaseInsensitiveStrMixin, unittest.TestCase):

    cls = cistr
