.. _aiohttp-multidict:

Multidicts
==========

.. highlight:: python

.. module:: aiohttp.multidict


*HTTP Headers* and *URL query string* require specific data structure:
*multidict*. It behaves mostly like a :class:`dict` but it can have
several *values* for the same *key*.

:mod:`aiohttp.multidict` has four multidict classes:
:class:`MultiDict`, :class:`MultiDictProxy`, :class:`CIMultiDict`
and :class:`CIMultiDictProxy`.

Immutable proxies (:class:`MultiDictProxy` and
:class:`CIMultiDictProxy`) provide a dynamic view on the
proxied multidict, the view reflects the multidict changes. They
implement the :class:`~collections.abc.Mapping` interface.

Regular mutable (:class:`MultiDict` and :class:`CIMultiDict`) classes
implement :class:`~collections.abc.MutableMapping` and allows to change
their own content.


*Case insensitive* (:class:`CIMultiDict` and
:class:`CIMultiDictProxy`) ones assumes the *keys* are case
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

   Creates a mutable multidict instance.

   Accepted parameters are the same as for :class:`dict`.

   If the same key appears several times it will be added, e.g.::

      >>> d = MultiDict[('a', 1), ('b', 2), ('a', 3)])
      >>> d
      <MultiDict {'a': 1, 'b': 2, 'a': 3}>

   .. method:: len(d)

      Return the number of items in multidict *d*.

   .. method:: d[key]

      Return the **first** item of *d* with key *key*.

      Raises a :exc:`KeyError` if key is not in the multidict.

   .. method:: d[key] = value

      Set ``d[key]`` to *value*.

      Replace all items where key is equal to *key* with single item
      ``(key, value)``.

   .. method:: del d[key]

      Remove all items where key is equal to *key* from *d*.
      Raises a :exc:`KeyError` if *key* is not in the map.

   .. method:: key in d

      Return ``True`` if d has a key *key*, else ``False``.

   .. method:: key not in d

      Equivalent to ``not (key in d)``

   .. method:: iter(d)

      Return an iterator over the keys of the dictionary.
      This is a shortcut for ``iter(d.keys())``.

   .. method:: add(key, value)

      Append ``(key, value)`` pair to the dictionary.

   .. method:: clear()

      Remove all items from the dictionary.

   .. method:: copy()

      Return a shallow copy of the dictionary.

   .. method:: extend([other])

      Extend the dictionary with the key/value pairs from *other*,
      overwriting existing keys.
      Return ``None``.

      :meth:`extend` accepts either another dictionary object or an
      iterable of key/value pairs (as tuples or other iterables of
      length two). If keyword arguments are specified, the dictionary
      is then extended with those key/value pairs:
      ``d.extend(red=1, blue=2)``.

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

   .. method:: items(getall=True)

      Return a new view of the dictionary's items (``(key, value)`` pairs).

      View contains all items if *getall* is ``True`` (default) or
      only first key occurrences otherwise.

   .. method:: values(getall=True)

      Return a new view of the dictionary's values.

      View contains all values if *getall* is ``True`` (default) or
      only first key occurrences otherwise.

   .. method:: pop(key[, default])

      If *key* is in the dictionary, remove it and return its the
      **first** value, else return *default*.

      If *default* is not given and *key* is not in the dictionary, a
      :exc:`KeyError` is raised.


   .. method:: popitem()

      Remove and return an arbitrary ``(key, value)`` pair from the dictionary.

      :meth:`popitem` is useful to destructively iterate over a
      dictionary, as often used in set algorithms.

      If the dictionary is empty, calling :meth:`popitem` raises a
      :exc:`KeyError`.

   .. method:: setdefault(key[, default])

      If *key* is in the dictionary, return its the **first** value.
      If not, insert *key* with a value of *default* and return *default*.
      *default* defaults to ``None``.

   .. method:: update([other])

      Update the dictionary with the key/value pairs from *other*,
      overwriting existing keys.

      Return ``None``.

      :meth:`update` accepts either another dictionary object or an
      iterable of key/value pairs (as tuples or other iterables
      of length two). If keyword arguments are specified, the
      dictionary is then updated with those key/value pairs:
      ``d.update(red=1, blue=2)``.

   .. seealso::

      :class:`MultiDictProxy` can be used to create a read-only view
      of a :class:`MultiDict`.


CIMultiDict
-----------


.. class:: CIMultiDict(**kwargs)
           CIMultiDict(mapping, **kwargs)
           CIMultiDict(iterable, **kwargs)

   Create a case insensitive multidict instance.

   The behavior is the same as of :class:`MultiDict` but key
   comparisons are case insensitive, e.g.::

      >>> dct = CIMultiDict(a='val')
      >>> 'A' in dct
      True
      >>> dct['A']
      'val'
      >>> dct['a']
      'val'
      >>> dct['b'] = 'new val'
      >>> dct['B']
      'new val'

   The class is inherited from :class:`MultiDict`.

   .. seealso::

      :class:`CIMultiDictProxy` can be used to create a read-only view
      of a :class:`CIMultiDict`.


MultiDictProxy
---------------

.. class:: MultiDictProxy(multidict)

   Create an immutable multidict proxy.

   It provides a dynamic view on
   the multidict’s entries, which means that when the multidict changes,
   the view reflects these changes.

   Raises :exc:`TypeError` is *multidict* is not :class:`MultiDict` instance.

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

      Return a shallow copy of the underlying multidict.

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

CIMultiDictProxy
----------------

.. class:: CIMultiDictProxy(multidict)

   Case insensitive version of :class:`MultiDictProxy`.

   Raises :exc:`TypeError` is *multidict* is not :class:`CIMultiDict` instance.

   The class is inherited from :class:`MultiDict`.


upstr
-----

:class:`CIMultiDict` accepts :class:`str` as *key* argument for dict
lookups but converts it to upper case internally.

For more effective processing it should know if the *key* is already upper cased.

To skip the :meth:`~str.upper()` call you may want to create upper cased strings by
hand, e.g::

   >>> key = upstr('Key')
   >>> key
   'KEY'
   >>> mdict = CIMultiDict(key='value')
   >>> key in mdict
   True
   >>> mdict[key]
   'value'

For performance you should create :class:`upstr` strings once and
store them globally, like :mod:`aiohttp.hdrs` does.

.. class:: upstr(object='')
           upstr(bytes_or_buffer[, encoding[, errors]])

      Create a new **upper cased** string object from the given
      *object*. If *encoding* or *errors* are specified, then the
      object must expose a data buffer that will be decoded using the
      given encoding and error handler.

      Otherwise, returns the result of ``object.__str__()`` (if defined)
      or ``repr(object)``.

      *encoding* defaults to ``sys.getdefaultencoding()``.

      *errors* defaults to ``'strict'``.

      The class is inherited from :class:`str` and has all regular
      string methods.
