.. _aiohttp-api:

Helpers API
===========

All public names from submodules ``client``, ``multipart``,
``protocol`` and ``utils`` are exported into
``aiohttp`` namespace.

WebSocket utilities
-------------------

.. module:: aiohttp
.. currentmodule:: aiohttp

.. class:: WSCloseCode

    An :class:`~enum.IntEnum` for keeping close message code.

    .. attribute:: OK

       A normal closure, meaning that the purpose for
       which the connection was established has been fulfilled.

    .. attribute:: GOING_AWAY

       An endpoint is "going away", such as a server
       going down or a browser having navigated away from a page.

    .. attribute:: PROTOCOL_ERROR

       An endpoint is terminating the connection due
       to a protocol error.

    .. attribute:: UNSUPPORTED_DATA

       An endpoint is terminating the connection
       because it has received a type of data it cannot accept (e.g., an
       endpoint that understands only text data MAY send this if it
       receives a binary message).

    .. attribute:: INVALID_TEXT

       An endpoint is terminating the connection
       because it has received data within a message that was not
       consistent with the type of the message (e.g., non-UTF-8 :rfc:`3629`
       data within a text message).

    .. attribute:: POLICY_VIOLATION

       An endpoint is terminating the connection because it has
       received a message that violates its policy.  This is a generic
       status code that can be returned when there is no other more
       suitable status code (e.g.,
       :attr:`~WSCloseCode.unsupported_data` or
       :attr:`~WSCloseCode.message_too_big`) or if there is a need to
       hide specific details about the policy.

    .. attribute:: MESSAGE_TOO_BIG

       An endpoint is terminating the connection
       because it has received a message that is too big for it to
       process.

    .. attribute:: MANDATORY_EXTENSION

       An endpoint (client) is terminating the
       connection because it has expected the server to negotiate one or
       more extension, but the server did not return them in the response
       message of the WebSocket handshake.  The list of extensions that
       are needed should appear in the /reason/ part of the Close frame.
       Note that this status code is not used by the server, because it
       can fail the WebSocket handshake instead.

    .. attribute:: INTERNAL_ERROR

       A server is terminating the connection because
       it encountered an unexpected condition that prevented it from
       fulfilling the request.

    .. attribute:: SERVICE_RESTART

       The service is restarted. a client may reconnect, and if it
       chooses to do, should reconnect using a randomized delay of 5-30s.

    .. attribute:: TRY_AGAIN_LATER

       The service is experiencing overload. A client should only
       connect to a different IP (when there are multiple for the
       target) or reconnect to the same IP upon user action.


.. class:: WSMsgType

   An :class:`~enum.IntEnum` for describing :class:`WSMessage` type.

   .. attribute:: CONTINUATION

      A mark for continuation frame, user will never get the message
      with this type.

   .. attribute:: TEXT

      Text message, the value has :class:`str` type.

   .. attribute:: BINARY

      Binary message, the value has :class:`bytes` type.

   .. attribute:: PING

      Ping frame (sent by client peer).

   .. attribute:: PONG

      Pong frame, answer on ping. Sent by server peer.

   .. attribute:: CLOSE

      Close frame.

   .. attribute:: CLOSED FRAME

      Actually not frame but a flag indicating that websocket was
      closed.

   .. attribute:: ERROR

      Actually not frame but a flag indicating that websocket was
      received an error.


.. class:: WSMessage

   Websocket message, returned by ``.receive()`` calls.

   .. attribute:: type

      Message type, :class:`WSMsgType` instance.

   .. attribute:: data

      Message payload.

      1. :class:`str` for :attr:`WSMsgType.TEXT` messages.

      2. :class:`bytes` for :attr:`WSMsgType.BINARY` messages.

      3. :class:`WSCloseCode` for :attr:`WSMsgType.CLOSE` messages.

      4. :class:`bytes` for :attr:`WSMsgType.PING` messages.

      5. :class:`bytes` for :attr:`WSMsgType.PONG` messages.

   .. attribute:: extra

      Additional info, :class:`str`.

      Makes sense only for :attr:`WSMsgType.CLOSE` messages, contains
      optional message description.

   .. method:: json(*, loads=json.loads)

      Returns parsed JSON data.

      .. versionadded:: 0.22

      :param loads: optional JSON decoder function.

   .. attribute:: tp

      Deprecated alias for :attr:`type`.

      .. deprecated:: 1.0


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

aiohttp.signals module
----------------------

.. automodule:: aiohttp.signals
    :members:
    :undoc-members:
    :show-inheritance:


.. disqus::
  :title: aiohttp helpers api
