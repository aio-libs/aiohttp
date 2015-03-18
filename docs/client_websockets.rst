.. _aiohttp-client-websockets:

WebScokets Client
=================

.. highlight:: python

.. module:: aiohttp.websocket_client

.. versionadded:: 0.15


:mod:`aiohttp` works with client websockets out-of-the-box.

You have to use :func:`aiohttp.ws_connect()` function for client
websocket connection. It accepts *url* as a first parameter and returns
:class:`ClientWebSocketResponse`, with that object you can communicate with
websocket server using response's methods:

.. code-block:: python

   ws = yield from aiohttp.ws_connect('http://webscoket-server.org/endpoint')

   while True:
       try:
          msg = yield from ws.receive()
       except aiohttp.WSServerDisconnectedError as exc:
          print(exc.code, exc.message)
          break

       if msg.tp == aiohttp.MSG_TEXT:
           if msg.data == 'close':
              ws.close()
           else:
              ws.send_str(data + '/answer')
       elif msg.tp == aiohttp.MSG_CLOSE:
           break

You can have the only websocket reader task (which can call ``yield
from ws.receive()``) and multiple writer tasks which can only send
data asynchronously (by ``yield from ws.send_str('data')`` for example).


ClientWebSocketResponse
-----------------------

To connect to websocket server you have to use `aiohttp.ws_connect()` function,
do not create instance of class :class:`ClientWebSocketResponse` manually.

.. py:function:: ws_connect(url, protocols=(), connector=None, autoclose=True, autoping=True, loop=None)

   This function creates websocket connection, checks response and
   returns :class:`ClientWebSocketResponse` object. It may raise
   :exc:`~aiohttp.errors.WSServerHandshakeError` exception.

   :param str url: websocket server url

   :param tuple protocols: websocket protocols

   :param obj connector: object :class:`TCPConnector`

   :param bool autoclose: automatically close websocket connection
                          on close message from server. if `autoclose` is
                          False them close procedure has to be handled manually

   :param bool autoping: automatically send `pong` on `ping` message from server
                   
   :param loop: :ref:`event loop<asyncio-event-loop>` used
                for processing HTTP requests.

                If param is ``None`` :func:`asyncio.get_event_loop`
                used for getting default event loop, but we strongly
                recommend to use explicit loops everywhere.

   
.. class:: ClientWebSocketResponse()

   Class for handling client-side websockets.

   .. attribute:: closed

      Read-only property, ``True`` if :meth:`close` has been called of
      :const:`~aiohttp.websocket.MSG_CLOSE` message has been received from peer.

   .. attribute:: protocol

      Websocket *subprotocol* chosen after :meth:`start` call.

      May be ``None`` if server and client protocols are
      not overlapping.

   .. method:: ping(message=b'')

      Send :const:`~aiohttp.websocket.MSG_PING` to peer.

      :param message: optional payload of *ping* message,
                      :class:`str` (converted to *UTF-8* encoded bytes)
                      or :class:`bytes`.

   .. method:: send_str(data)

      Send *data* to peer as :const:`~aiohttp.websocket.MSG_TEXT` message.

      :param str data: data to send.

      :raise TypeError: if data is not :class:`str`

   .. method:: send_bytes(data)

      Send *data* to peer as :const:`~aiohttp.websocket.MSG_BINARY` message.

      :param data: data to send.

      :raise TypeError: if data is not :class:`bytes`,
                        :class:`bytearray` or :class:`memoryview`.

   .. method:: close(*, code=1000, message=b'')

      A :ref:`coroutine<coroutine>` that initiates closing handshake by sending
      :const:`~aiohttp.websocket.MSG_CLOSE` message. It waits for
      close response from server. It add timeout to `close()` call just wrap
      call with `asyncio.wait()` or `asyncio.wait_for()`.

      :param int code: closing code

      :param message: optional payload of *pong* message,
                      :class:`str` (converted to *UTF-8* encoded bytes)
                      or :class:`bytes`.

   .. method:: close_exception()

      Returns close exception if any occurs or returns None.
                      
   .. method:: receive()

      A :ref:`coroutine<coroutine>` that waits upcoming *data*
      message from peer and returns it.

      The coroutine implicitly handles
      :const:`~aiohttp.websocket.MSG_PING`,
      :const:`~aiohttp.websocket.MSG_PONG` and
      :const:`~aiohttp.websocket.MSG_CLOSE` without returning the
      message.

      It process *ping-pong game* and performs *closing handshake* internally.

      After websocket closing raises
      :exc:`~aiohttp.errors.WSServerDisconnectedError` with
      connection closing data.

      :return: :class:`~aiohttp.websocket.Message`

      :raise: :exc:`~aiohttp.errors.WSServerDisconnectedError` on closing.

   .. method:: receive_str()

      A :ref:`coroutine<coroutine>` that calls :meth:`receive_mgs` but
      also asserts the message type is
      :const:`~aiohttp.websocket.MSG_TEXT`.

      :return str: peer's message content.

      :raise TypeError: if message is :const:`~aiohttp.websocket.MSG_BINARY`.

   .. method:: receive_bytes()

      A :ref:`coroutine<coroutine>` that calls :meth:`receive_mgs` but
      also asserts the message type is
      :const:`~aiohttp.websocket.MSG_BINARY`.

      :return bytes: peer's message content.

      :raise TypeError: if message is :const:`~aiohttp.websocket.MSG_TEXT`.
