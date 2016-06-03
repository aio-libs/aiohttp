import asyncio
import aiohttp
import collections
import logging
import pytest
import re
import sys
import warnings
from aiohttp import web
from aiohttp.test_utils import (
    loop_context, unused_port
)


class _AssertWarnsContext:
    """A context manager used to implement TestCase.assertWarns* methods."""

    def __init__(self, expected, expected_regex=None):
        self.expected = expected
        if expected_regex is not None:
            expected_regex = re.compile(expected_regex)
        self.expected_regex = expected_regex
        self.obj_name = None

    def __enter__(self):
        # The __warningregistry__'s need to be in a pristine state for tests
        # to work properly.
        for v in sys.modules.values():
            if getattr(v, '__warningregistry__', None):
                v.__warningregistry__ = {}
        self.warnings_manager = warnings.catch_warnings(record=True)
        self.warnings = self.warnings_manager.__enter__()
        warnings.simplefilter("always", self.expected)
        return self

    def __exit__(self, exc_type, exc_value, tb):
        self.warnings_manager.__exit__(exc_type, exc_value, tb)
        if exc_type is not None:
            # let unexpected exceptions pass through
            return
        try:
            exc_name = self.expected.__name__
        except AttributeError:
            exc_name = str(self.expected)
        first_matching = None
        for m in self.warnings:
            w = m.message
            if not isinstance(w, self.expected):
                continue
            if first_matching is None:
                first_matching = w
            if (self.expected_regex is not None and
                    not self.expected_regex.search(str(w))):
                continue
            # store warning for later retrieval
            self.warning = w
            self.filename = m.filename
            self.lineno = m.lineno
            return
        # Now we simply try to choose a helpful failure message
        if first_matching is not None:
            __tracebackhide__ = True
            assert 0, '"{}" does not match "{}"'.format(
                self.expected_regex.pattern, str(first_matching))
        if self.obj_name:
            __tracebackhide__ = True
            assert 0, "{} not triggered by {}".format(exc_name,
                                                      self.obj_name)
        else:
            __tracebackhide__ = True
            assert 0, "{} not triggered".format(exc_name)


_LoggingWatcher = collections.namedtuple("_LoggingWatcher",
                                         ["records", "output"])


class _CapturingHandler(logging.Handler):
    """
    A logging handler capturing all (raw and formatted) logging output.
    """

    def __init__(self):
        logging.Handler.__init__(self)
        self.watcher = _LoggingWatcher([], [])

    def flush(self):
        pass

    def emit(self, record):
        self.watcher.records.append(record)
        msg = self.format(record)
        self.watcher.output.append(msg)


class _AssertLogsContext:
    """A context manager used to implement TestCase.assertLogs()."""

    LOGGING_FORMAT = "%(levelname)s:%(name)s:%(message)s"

    def __init__(self, logger_name=None, level=None):
        self.logger_name = logger_name
        if level:
            self.level = logging._nameToLevel.get(level, level)
        else:
            self.level = logging.INFO
        self.msg = None

    def __enter__(self):
        if isinstance(self.logger_name, logging.Logger):
            logger = self.logger = self.logger_name
        else:
            logger = self.logger = logging.getLogger(self.logger_name)
        formatter = logging.Formatter(self.LOGGING_FORMAT)
        handler = _CapturingHandler()
        handler.setFormatter(formatter)
        self.watcher = handler.watcher
        self.old_handlers = logger.handlers[:]
        self.old_level = logger.level
        self.old_propagate = logger.propagate
        logger.handlers = [handler]
        logger.setLevel(self.level)
        logger.propagate = False
        return handler.watcher

    def __exit__(self, exc_type, exc_value, tb):
        self.logger.handlers = self.old_handlers
        self.logger.propagate = self.old_propagate
        self.logger.setLevel(self.old_level)
        if exc_type is not None:
            # let unexpected exceptions pass through
            return False
        if len(self.watcher.records) == 0:
            __tracebackhide__ = True
            assert 0, ("no logs of level {} or higher triggered on {}"
                       .format(logging.getLevelName(self.level),
                               self.logger.name))


@pytest.yield_fixture
def warning():
    yield _AssertWarnsContext


@pytest.yield_fixture
def log():
    yield _AssertLogsContext


# add the unused_port and loop fixtures
pytest.fixture(unused_port)


@pytest.yield_fixture
def loop():
    with loop_context() as loop:
        yield loop


@pytest.yield_fixture
def create_server(loop):
    app = handler = srv = None

    @asyncio.coroutine
    def create(*, debug=False, ssl_ctx=None, proto='http'):
        nonlocal app, handler, srv
        app = web.Application(loop=loop)
        port = unused_port()
        handler = app.make_handler(debug=debug, keep_alive_on=False)
        srv = yield from loop.create_server(handler, '127.0.0.1', port,
                                            ssl=ssl_ctx)
        if ssl_ctx:
            proto += 's'
        url = "{}://127.0.0.1:{}".format(proto, port)
        return app, url

    yield create

    @asyncio.coroutine
    def finish():
        yield from handler.finish_connections()
        yield from app.finish()
        srv.close()
        yield from srv.wait_closed()

    loop.run_until_complete(finish())


class Client:
    def __init__(self, session, url):
        self._session = session
        if not url.endswith('/'):
            url += '/'
        self._url = url

    def close(self):
        self._session.close()

    def get(self, path, **kwargs):
        while path.startswith('/'):
            path = path[1:]
        url = self._url + path
        return self._session.get(url, **kwargs)

    def post(self, path, **kwargs):
        while path.startswith('/'):
            path = path[1:]
        url = self._url + path
        return self._session.post(url, **kwargs)

    def delete(self, path, **kwargs):
        while path.startswith('/'):
            path = path[1:]
        url = self._url + path
        return self._session.delete(url)

    def ws_connect(self, path, **kwargs):
        while path.startswith('/'):
            path = path[1:]
        url = self._url + path
        return self._session.ws_connect(url, **kwargs)


@pytest.yield_fixture
def create_app_and_client(create_server, loop):
    client = None

    @asyncio.coroutine
    def maker(*, server_params=None, client_params=None):
        nonlocal client
        if server_params is None:
            server_params = {}
        server_params.setdefault('debug', False)
        server_params.setdefault('ssl_ctx', None)
        app, url = yield from create_server(**server_params)
        if client_params is None:
            client_params = {}
        client = Client(aiohttp.ClientSession(loop=loop, **client_params), url)
        return app, client

    yield maker
    client.close()


@pytest.mark.tryfirst
def pytest_pycollect_makeitem(collector, name, obj):
    if collector.funcnamefilter(name):
        if not callable(obj):
            return
        item = pytest.Function(name, parent=collector)
        if 'run_loop' in item.keywords:
            return list(collector._genfunctions(name, obj))


@pytest.mark.tryfirst
def pytest_pyfunc_call(pyfuncitem):
    """
    Run asyncio marked test functions in an event loop instead of a normal
    function call.
    """
    if 'run_loop' in pyfuncitem.keywords:
        funcargs = pyfuncitem.funcargs
        loop = funcargs['loop']
        testargs = {arg: funcargs[arg]
                    for arg in pyfuncitem._fixtureinfo.argnames}
        loop.run_until_complete(pyfuncitem.obj(**testargs))
        return True


def pytest_runtest_setup(item):
    if 'run_loop' in item.keywords and 'loop' not in item.fixturenames:
        # inject an event loop fixture for all async tests
        item.fixturenames.append('loop')


def pytest_ignore_collect(path, config):
    if 'test_py35' in str(path):
        if sys.version_info < (3, 5, 0):
            return True
