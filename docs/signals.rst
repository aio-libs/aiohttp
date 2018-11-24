Signals
=======

.. currentmodule:: aiohttp

Signal is a list of registered asynchronous callbacks.

The signal's life-cycle has two stages: after creation its content
could be filled by using standard list operations: ``sig.append()``
etc.

After ``sig.freeze()`` call the signal is *frozen*: adding, removing
and dropping callbacks are forbidden.

The only available operation is calling previously registered
callbacks by ``await sig.send(data)``.

For concrete usage examples see :ref:`signals in aiohttp.web
<aiohttp-web-signals>` chapter.

.. versionchanged:: 3.0

   ``sig.send()`` call is forbidden for non-frozen signal.

   Support for regular (non-async) callbacks is dropped. All callbacks
   should be async functions.


.. class:: Signal

   The signal, implements :class:`collections.abc.MutableSequence`
   interface.

   .. comethod:: send(*args, **kwargs)

      Call all registered callbacks one by one starting from the begin
      of list.

   .. attribute:: frozen

      ``True`` if :meth:`freeze` was called, read-only property.

   .. method:: freeze()

      Freeze the list. After the call any content modification is forbidden.
