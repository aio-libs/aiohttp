

.. _aiohttp-request-lifecycle:


The aiohttp Request Lifecycle
=============================


Why is aiohttp client API that way?
--------------------------------------


The first time you use aiohttp, you'll notice that a simple HTTP request is performed not with one, but with up to three steps:


.. code-block:: python


    async with aiohttp.ClientSession() as session:
        async with session.get('http://python.org') as response:
            print(await response.text())


It's especially unexpected when coming from other libraries such as the very popular :term:`requests`, where the "hello world" looks like this:


.. code-block:: python


    response = requests.get('http://python.org')
    print(response.text)


So why is the aiohttp snippet so verbose?


Because aiohttp is asynchronous, its API is designed to make the most out of non-blocking network operations. In code like this, requests will block three times, and does it transparently, while aiohttp gives the event loop three opportunities to switch context:


- When doing the ``.get()``, both libraries send a GET request to the remote server. For aiohttp, this means asynchronous I/O, which is marked here with an ``async with`` that gives you the guarantee that not only it doesn't block, but that it's cleanly finalized.
- When doing ``response.text`` in requests, you just read an attribute. The call to ``.get()`` already preloaded and decoded the entire response payload, in a blocking manner. aiohttp loads only the headers when ``.get()`` is executed, letting you decide to pay the cost of loading the body afterward, in a second asynchronous operation. Hence the ``await response.text()``.
- ``async with aiohttp.ClientSession()`` does not perform I/O when entering the block, but at the end of it, it will ensure all remaining resources are closed correctly. Again, this is done asynchronously and must be marked as such. The session is also a performance tool, as it manages a pool of connections for you, allowing you to reuse them instead of opening and closing a new one at each request. You can even `manage the pool size by passing a connector object <client_advanced.html#limiting-connection-pool-size>`_.

Using a session as a best practice
-----------------------------------

The requests library does in fact also provides a session system. Indeed, it lets you do:

.. code-block:: python

    with requests.Session() as session:
        response = session.get('http://python.org')
        print(response.text)

It's just not the default behavior, nor is it advertised early in the documentation. Because of this, most users take a hit in performance, but can quickly start hacking. And for requests, it's an understandable trade-off, since its goal is to be "HTTP for humans" and simplicity has always been more important than performance in this context.

However, if one uses aiohttp, one chooses asynchronous programming, a paradigm that makes the opposite trade-off: more verbosity for better performance. And so the library default behavior reflects this, encouraging you to use performant best practices from the start.

How to use the ClientSession ?
-------------------------------

By default the :class:`aiohttp.ClientSession` object will hold a connector with a maximum of 100 connections, putting the rest in a queue. This is quite a big number, this means you must be connected to a hundred different servers (not pages!) concurrently before even having to consider if your task needs resource adjustment.

In fact, you can picture the session object as a user starting and closing a browser: it wouldn't make sense to do that every time you want to load a new tab.

So you are expected to reuse a session object and make many requests from it. For most scripts and average-sized software, this means you can create a single session, and reuse it for the entire execution of the program. You can even pass the session around as a parameter in functions. For example, the typical "hello world":

.. code-block:: python

    import aiohttp
    import asyncio

    async def main():
        async with aiohttp.ClientSession() as session:
            async with session.get('http://python.org') as response:
                html = await response.text()
                print(html)

    asyncio.run(main())


Can become this:


.. code-block:: python

    import aiohttp
    import asyncio

    async def fetch(session, url):
        async with session.get(url) as response:
            return await response.text()

    async def main():
        async with aiohttp.ClientSession() as session:
            html = await fetch(session, 'http://python.org')
            print(html)

    asyncio.run(main())

On more complex code bases, you can even create a central registry to hold the session object from anywhere in the code, or a higher level ``Client`` class that holds a reference to it.

When to create more than one session object then? It arises when you want more granularity with your resources management:

- you want to group connections by a common configuration. e.g: sessions can set cookies, headers, timeout values, etc. that are shared for all connections they hold.
- you need several threads and want to avoid sharing a mutable object between them.
- you want several connection pools to benefit from different queues and assign priorities. e.g: one session never uses the queue and is for high priority requests, the other one has a small concurrency limit and a very long queue, for non important requests.
