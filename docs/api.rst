.. _aiohttp-api:

Helpers API
===========

All public names from submodules ``errors``, ``multipart``,
``parsers``, ``protocol``, ``utils``, and ``wsgi`` are exported into
``aiohttp`` namespace.

WebSocket utilities
-------------------

.. module:: aiohttp
.. currentmodule:: aiohttp

.. class:: WSCloseCode

    An :class:`~enum.IntEnum` for keeping close message code.

    .. attribute:: ok

       A normal closure, meaning that the purpose for
       which the connection was established has been fulfilled.

    .. attribute:: going_away

       An endpoint is "going away", such as a server
       going down or a browser having navigated away from a page.

    .. attribute:: protocol_error

       An endpoint is terminating the connection due
       to a protocol error.

    .. attribute:: unsupported_data

       An endpoint is terminating the connection
       because it has received a type of data it cannot accept (e.g., an
       endpoint that understands only text data MAY send this if it
       receives a binary message).

    .. attribute:: invalid_text

       An endpoint is terminating the connection
       because it has received data within a message that was not
       consistent with the type of the message (e.g., non-UTF-8 :rfc:`3629`
       data within a text message).

    .. attribute:: policy_violation

       An endpoint is terminating the connection because it has
       received a message that violates its policy.  This is a generic
       status code that can be returned when there is no other more
       suitable status code (e.g.,
       :attr:`~WSCloseCode.unsupported_data` or
       :attr:`~WSCloseCode.message_too_big`) or if there is a need to
       hide specific details about the policy.

    .. attribute:: message_too_big

       An endpoint is terminating the connection
       because it has received a message that is too big for it to
       process.

    .. attribute:: mandatory_extension

       An endpoint (client) is terminating the
       connection because it has expected the server to negotiate one or
       more extension, but the server didn't return them in the response
       message of the WebSocket handshake.  The list of extensions that
       are needed should appear in the /reason/ part of the Close frame.
       Note that this status code is not used by the server, because it
       can fail the WebSocket handshake instead.

    .. attribute:: internal_error

       A server is terminating the connection because
       it encountered an unexpected condition that prevented it from
       fulfilling the request.

    .. attribute:: service_restart

       The service is restarted. a client may reconnect, and if it
       choses to do, should reconnect using a randomized delay of 5-30s.

    .. attribute:: try_again_later

       The service is experiencing overload. A client should only
       connect to a different IP (when there are multiple for the
       target) or reconnect to the same IP upon user action.


.. class:: WSMsgType

   An :class:`~enum.IntEnum` for describing :class:`WSMessage` type.

   .. attribute:: continuation

      A mark for continuation frame, user will never get the message
      with this type.

   .. attribute:: text

      Text messsage, the value has :class:`str` type.

   .. attribute:: binary

      Binary messsage, the value has :class:`bytes` type.

   .. attribute:: ping

      Ping frame (sent by client peer).

   .. attribute:: pong

      Pong frame, answer on ping. Sent by server peer.

   .. attribute:: close

      Close frame.

   .. attribute:: closed frame

      Actually not frame but a flag indicating that websocket was
      closed.

   .. attribute:: error

      Actually not frame but a flag indicating that websocket was
      received an error.


aiohttp.errors module
---------------------

.. automodule:: aiohttp.errors
    :members:
    :undoc-members:
    :show-inheritance:

aiohttp.helpers module
----------------------

.. automodule:: aiohttp.helpers
    :members:
    :undoc-members:
    :exclude-members: BasicAuth
    :show-inheritance:

aiohttp.multipart module
------------------------

.. automodule:: aiohttp.multipart
    :members:
    :undoc-members:
    :show-inheritance:

aiohttp.parsers module
----------------------

.. automodule:: aiohttp.parsers
    :members:
    :undoc-members:
    :show-inheritance:

aiohttp.signals module
----------------------

.. automodule:: aiohttp.signals
    :members:
    :undoc-members:
    :show-inheritance:

aiohttp.streams module
----------------------

.. automodule:: aiohttp.streams
    :members:
    :undoc-members:
    :show-inheritance:


aiohttp.wsgi module
-------------------

.. automodule:: aiohttp.wsgi
    :members:
    :undoc-members:
    :show-inheritance:


.. disqus::
