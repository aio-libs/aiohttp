Add default logging handler to web.run_app

If the `Application.debug` flag is set and the default logger `aiohttp.access` is used, access logs will now be output using a `stderr` `StreamHandler` if no handlers are attached. Furthermore, if the default logger has no log level set, the log level will be set to `DEBUG`.
