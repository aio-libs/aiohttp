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

   If the same key produced several times it will be added, e.g.::

      >>> d = MultiDict([('a', 1), ('b', 2), ('a', 3)])
      >>> d
      <MultiDict {'a': 1, 'b': 2, 'a': 3}>

   .. method:: len(d)

      Return number of items in multidict *d*.

   .. method:: d[key]

      Return the **first** item of *d* with key *key*.

      Raises a :exc:`KeyError` if key is not in the multidict.

   .. method:: key in d

      Return ``True`` if d has a key *key*, else ``False``.

   .. method:: key not in d

      Equivalent to ``not (key in d)``

   .. method:: iter(d)

      Return an iterator over the keys of the dictionary.
      This is a shortcut for ``iter(d.keys())``.

   .. method:: copy()

      Return a shallow copy of the dictionary.

   .. method:: getone(key[, default])

      Return the **first** value for *key* if *key* is in the
      dictionary, else *default*.

      Raises :exc:`KeyError` if *default* is not given and *key* is not found.

      ``d[key]`` is equivalent to ``d.getone(key)``.

   .. method:: getall(key[, default])

      Return a list of all values for *key* if *key* is in the
      dictionary, else *default*.

      Raises :exc:`KeyError` if *default* is not given and *key* is not found.

   .. method:: get(key[, default])

      Return the **first** value for *key* if *key* is in the
      dictionary, else *default*.

      If *default* is not given, it defaults to ``None``, so that this
      method never raises a :exc:`KeyError`.

      ``d.get(key)`` is equivalent to ``d.getone(key, None)``.

   .. method:: keys(getall=True)

      Return a new view of the dictionary's keys.

      View contains all keys if *getall* is ``True`` (default) or
      distinct set of ones otherwise.

   .. method:: keys(getall=True)

      Return a new view of the dictionary's items (``(key, value)`` pairs).

      View contains all items if *getall* is ``True`` (default) or
      only first key occurrences otherwise.

   .. method:: values(getall=True)

      Return a new view of the dictionary's values.

      View contains all values if *getall* is ``True`` (default) or
      only first key occurrences otherwise.


CIMultiDict
-----------


.. class:: CIMultiDict(**kwargs)
           CIMultiDict(mapping, **kwargs)
           CIMultiDict(iterable, **kwargs)

   Create a case insensitive multidict instance.

   The behavior is the same as of :class:`MultiDict` but key
   comparsions are case insensitive.

   E.g.::

      >>> dct = CIMultiDict(a='val')
      >>> 'A' in dct
      True
      >>> dct['A']
      'val'
      >>> dct['a']
      'val'
