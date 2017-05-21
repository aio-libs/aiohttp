import collections
import logging
import sys

import pytest


pytest_plugins = 'aiohttp.pytest_plugin'


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
def log():
    yield _AssertLogsContext


def pytest_ignore_collect(path, config):
    if 'test_py35' in str(path):
        if sys.version_info < (3, 5, 0):
            return True
