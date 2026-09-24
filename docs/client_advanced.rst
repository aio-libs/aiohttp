.. currentmodule:: aiohttp

.. _aiohttp-client-advanced:

Advanced Client Usage
=====================

.. _aiohttp-client-session:

Client Session
--------------

:class:`ClientSession` is the heart and the main entry point for all
client API operations.

Create the session first, use the instance for performing HTTP
requests and initiating WebSocket connections.

The session contains a cookie storage and connection pool, thus
cookies and connections are shared between HTTP requests sent by the
same session.

Custom Request Headers
----------------------

If you need to add HTTP headers to a request, pass them in a
:class:`dict` to the *headers* parameter.

For example, if you want to specify the content-type directly::

    url = 'http://example.com/image'
    payload = b'GIF89a\u005cx01\u005cx00\u005cx01\u005cx00\u005cx00\u005cxff\u005cx00,\u005cx00\u005cx00'
              b'\u005cx00\u005cx00\u005cx01\u005cx00\u005cx01\u005cx00\u005cx00\u005cx02\u005cx00;'
    headers = {'content-type': 'image/gif'}

    await session.post(url,
                       data=payload,
                       headers=headers)

You also can set default headers for all session requests::

    headers={"Authorization": "Basic bG9naW46cGFzcw=="}
    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.get("http://httpbin.org/headers") as r:
            json_body = await r.json()
            assert json_body['headers']['Authorization'] == \u005c
                'Basic bG9naW46cGFzcw=='

Typical use case is sending JSON body. You can specify content type
directly as shown above, but it is more convenient to use special keyword
``json``::

    await session.post(url, json={'example': 'text'})

For ``text/plain``::

    await session.post(url, data='\u041f\u0440\u0438\u0432\u0435\u0442, \u041c\u0438\u0440!')

Authentication
--------------

PLACEHOLDER_WILL_FAIL_IF_USED