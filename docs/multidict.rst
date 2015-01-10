.. _aiohttp-multidic:

Multidicts
==========

.. highlight:: python

.. module:: aiohttp.multidict


*HTTP Headers* and *URL query string* require specific data structure:
*multidict*. It behaves mostly like a :class:`dict` but may have
several *values* for the same *key*.

:mod:`aiohttp.multidict` has four multidict classes:
:class:`MultiDict`, :class:`MutableMultiDict`, :class:`CIMultiDict`
and :class:`CIMutableMultiDict`.


Immutable (:class:`MultiDict` and :class:`CIMultiDict`) classes
doesn't allow to change *muldidict* content. They are implement
:class:`~collections.abc.Mapping` interface.

Mutable (:class:`MutableMultiDict` and :class:`CIMutableMultiDict`)
ones implement :class:`~collections.abc.MutableMapping`.


*Case insensitive* (:class:`CIMultiDict` and
:class:`CIMutableMultiDict`) ones assumes the *keys* are case
insensitive, e.g.::

   >>> dct = CIMultiDict(a='val')
   >>> 'A' in dct
   True
   >>> dct['A']
   'val'

*Keys* should be a :class:`str`.


MultiDict
---------

.. class:: MultiDict(**kwargs)
           MultiDict(mapping, **kwargs)
           MultiDict(iterable, **kwargs)

   Create a multidict instance.

   Accepted parameters are the same as for :class:`dict`.

   If the same key produced several time it will be added, e.g.::

   >>> d = MultiDict([('a', 1), ('b', 2), ('a', 3)])
   >>> print(d)

   If no arguments given, an empty multidict is created. If a
   positional argument is given and it is a mapping object, a
   dictionary is created with the same key-value pairs as the mapping
   object. Otherwise, the positional argument must be an *iterable*
   object. Each item in the iterable must itself be an iterable with
   exactly two objects. The first object of each item becomes a key in
   the new dictionary, and the second object the corresponding
   value. If a key occurs more than once, the last value for that key
   becomes the corresponding value in the new dictionary.

   If keyword arguments are given, the keyword arguments and their
   values are added to the dictionary created from the positional
   argument. If a key being added is already present, the value from the
   keyword argument replaces the value from the positional argument.

To illustrate, the following examples all return a dictionary equal to {"one": 1, "two": 2, "three": 3}:

>>>
>>> a = dict(one=1, two=2, three=3)
>>> b = {'one': 1, 'two': 2, 'three': 3}
>>> c = dict(zip(['one', 'two', 'three'], [1, 2, 3]))
>>> d = dict([('two', 2), ('one', 1), ('three', 3)])
>>> e = dict({'three': 3, 'one': 1, 'two': 2})
>>> a == b == c == d == e
True
