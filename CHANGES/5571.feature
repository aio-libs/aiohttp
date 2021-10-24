Don't send secure cookies by insecure transports.

By default, the transport is secure if https or wss scheme is used.
Use `CookieJar(treat_as_secure_origin="http://127.0.0.1")` to override the default security checker.
