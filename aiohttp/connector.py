import asyncio


__all__ = ['DefaultConnector']


class DefaultConnector(object):

    def create_connection(self, proto, host, port, *, loop=None, **kwargs):
        """Create connection. Has same keyword arguments
        as BaseEventLoop.create_connection
        """
        if loop is None:
            loop = asyncio.get_event_loop()
        conn = yield from loop.create_connection(proto, host, port, **kwargs)
        return conn

