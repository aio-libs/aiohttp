from typing import Optional

import attr


@attr.s(frozen=True, slots=True)
class ClientTimeout:
    total = attr.ib(type=Optional[float], default=None)
    connect = attr.ib(type=Optional[float], default=None)
    sock_read = attr.ib(type=Optional[float], default=None)
    sock_connect = attr.ib(type=Optional[float], default=None)
    sock_close = attr.ib(type=Optional[float], default=None)

    # pool_queue_timeout = attr.ib(type=float, default=None)
    # dns_resolution_timeout = attr.ib(type=float, default=None)
    # socket_connect_timeout = attr.ib(type=float, default=None)
    # connection_acquiring_timeout = attr.ib(type=float, default=None)
    # new_connection_timeout = attr.ib(type=float, default=None)
    # http_header_timeout = attr.ib(type=float, default=None)
    # response_body_timeout = attr.ib(type=float, default=None)

    # to create a timeout specific for a single request, either
    # - create a completely new one to overwrite the default
    # - or use http://www.attrs.org/en/stable/api.html#attr.evolve
    # to overwrite the defaults


# 5 Minute default read timeout
DEFAULT_TIMEOUT = ClientTimeout(total=5*60)

# for web socket the default timeouts are 10 sec
DEFAULT_WS_CLIENT_TIMEOUT = ClientTimeout(sock_read=10.0, sock_close=10.0)
