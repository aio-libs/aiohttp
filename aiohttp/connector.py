__all__ = ['DefaultConnector']

import asyncio


class DefaultConnector(object):

    def create_connection(self, protocol_factory, host, port, *,
                          loop=None, **kwargs):
        """Create connection. Has same keyword arguments
        as BaseEventLoop.create_connection
        """
        if loop is None:
            loop = asyncio.get_event_loop()
        conn = yield from loop.create_connection(
            protocol_factory, host, port, **kwargs)
        return conn
