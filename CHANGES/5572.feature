Always create a new event loop in ``aiohttp.web.run_app()``.
This adds better compatibility with ``asyncio.run()`` or if trying to run multiple apps in sequence.
