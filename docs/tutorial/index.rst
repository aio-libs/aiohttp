Tutorial
========

.. contents::
   :local:


Purpose of Tutorial
-------------------


`@Arfey <https://github.com/Arfey>`_ 
`wrote <https://github.com/aio-libs/aiohttp/issues/4137#issuecomment-538248544>`_ :

..

    Tutorial is story about show how may looks project on aiohttp and how u need 
    to design it. The main documentation is about how work and why.



Why does Aiohttp choose sharing settings?
-----------------------------------------

There are `discussion <https://github.com/aio-libs/aiohttp/issues/2689>`_ 
(and `this <https://github.com/aio-libs/aiohttp/issues/2412>`_ ) on 
configurations for nested applictation (subapplication). Subapplications can be 
separated entities, having their own configurations, for e.g. database or 
cache purposes.

Web developers want the main applictation to control the subapplications, 
this requires a mechanism for the app to access the context.

Centralization of configurations has the benefits listed as the following:

1. **Easy management**

In the case of subapplications exist, communication between main app and 
subapplications is common. Aiohttp choose to set the configurations in 
main app's context. Subapplications hence can access the settings at the 
stage of initialization.

This mechanism is similar to the implementation of Flask offering a 'g' variable.

More details can be found `here <https://github.com/aio-libs/aiohttp/issues/2689>`_ .

2. **Keep it simple**

Keeping a list of db connection instances at runtime can achieve it. But it 
comes up ordering problems, like managing the lifecycle of things like a 
database connection, scheduler, etc.

Conclusion
^^^^^^^^^^

Making use of ``request.config_dict`` 
(`#2949 <https://github.com/aio-libs/aiohttp/pull/2949>`_ feature) is the way 
out.

An typical way to setup an app:

.. code-block:: python

    async def init_pg(app):
        conf = app['config']['postgres']
        engine = await aiopg.sa.create_engine(
            database=conf['database'],
            user=conf['user'],
            password=conf['password'],
            host=conf['host'],
            port=conf['port'],
            minsize=conf['minsize'],
            maxsize=conf['maxsize'],
        )
        app['db'] = engine

Further discussion
^^^^^^^^^^^^^^^^^^

`cleanup_ctx` is the mechanism to handle a subapplication starting up and 
cleaning up. The discussion is ongoing ` (issue 
`#3876 <https://github.com/aio-libs/aiohttp/issues/3876>`_). 
`@mrasband <https://github.com/mrasband>`_ suggested to push subapplication 
configurations to one of the key in the ``app`` mapping.
