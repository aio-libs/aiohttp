.. _aiohttp-structures:


Common data structures
======================

.. module:: aiohttp

.. currentmodule:: aiohttp


Common data structures used by *aiohttp* internally.


FrozenList
----------

A list-like structure which implements
:class:`collections.abc.MutableSequence`.

The list is *mutable* unless :meth:`FrozenList.freeze` is called,
after that the list modification raises :exc:`RuntimeError`.


.. class:: FrozenList(items)

   Construct a new *non-frozen* list from *items* iterable.

   The list implements all :class:`collections.abc.MutableSequence`
   methods plus two additional APIs.

   .. attribute:: frozen

      A read-only property, ``True`` is the list is *frozen*
      (modifications are forbidden).

   .. method:: freeze()

      Freeze the list. There is no way to *thaw* it back.


ChainMapProxy
-------------

An *immutable* version of :class:`collections.ChainMap`.  Internally
the proxy is a list of mappings (dictionaries), if the requested key
is not present in the first mapping the second is looked up and so on.

The class supports :class:`collections.abc.Mapping` interface.

.. class:: ChainMapProxy(maps)

   Create a new chained mapping proxy from a list of mappings (*maps*).

   .. versionadded:: 3.2
