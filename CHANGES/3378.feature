Add method argument to ``session.ws_connect()``.

Sometimes server API requires a different HTTP method for WebSocket connection establishment.

For example, ``Docker exec`` needs POST.
