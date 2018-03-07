Install a test event loop as default by
``asyncio.set_event_loop()``. The change affects aiohttp test utils
but backward compatibility is not broken for 99.99% of use cases.