"""
Autoreload aiohttp server.
Adopted from https://github.com/anti1869/aiohttp_autoreload

Code is taken from tornado.autoreload module.

call_periodic module is taken from akaIDIOT's gist
 https://gist.github.com/akaIDIOT/48c2474bd606cd2422ca

"""

import sys
import os
import types
import weakref
import subprocess
import asyncio
import functools

try:
    import signal
except ImportError:
    signal = None

from .log import web_logger


_has_execv = sys.platform != 'win32'
_watched_files = set()
_reload_hooks = []
_reload_attempted = False
_io_loops = weakref.WeakKeyDictionary()


def start(io_loop=None, check_time=0.5):

    """Begins watching source files for changes.

    .. versionchanged:: 4.1
       The ``io_loop`` argument is deprecated.
    """
    io_loop = io_loop or asyncio.get_event_loop()
    if io_loop in _io_loops:
        return
    _io_loops[io_loop] = True
    if len(_io_loops) > 1:
        web_logger.warning(
            "aiohttp_autoreload started more than once in the same process")
    # if _has_execv:
    #     add_reload_hook(functools.partial(io_loop.close, all_fds=True))
    modify_times = {}
    callback = functools.partial(_reload_on_update, modify_times)
    web_logger.debug("Starting periodic checks for code changes")
    call_periodic(check_time, callback, loop=io_loop)


def add_reload_hook(fn):
    """Add a function to be called before reloading the process.

    Note that for open file and socket handles it is generally
    preferable to set the ``FD_CLOEXEC`` flag (using `fcntl` or
    ``tornado.platform.auto.set_close_exec``) instead
    of using a reload hook to close them.

    """
    _reload_hooks.append(fn)


# https://gist.github.com/akaIDIOT/48c2474bd606cd2422ca
def call_periodic(interval, callback, *args, **kwargs):
    # get loop as a kwarg or take the default one
    loop = kwargs.get('loop') or asyncio.get_event_loop()
    # record the loop's time when call_periodic was called
    started = loop.time()
    # web_logger.debug(started)
    # import time
    # time.sleep(2)
    # web_logger.debug(loop.time())

    def run(handle):
        # XXX: we could record before = loop.time() and warn when
        # callback(*args) took longer than interval
        # call callback now (possibly blocks run)
        callback(*args)
        # reschedule run at the soonest time n * interval from start
        # re-assign delegate to the new handle

        handle.delegate = loop.call_later(
            interval - ((loop.time() - started) % interval),
            run,
            handle
        )

    # not extending Handle, needs a lot of
    # arguments that make no sense here
    class PeriodicHandle:
        def __init__(self):
            self.delegate = None

        def cancel(self):
            assert isinstance(self.delegate, asyncio.Handle), (
                'no delegate handle to cancel')
            self.delegate.cancel()

    # can't pass result of loop.call_at here,
    # it needs periodic as an arg to run
    periodic = PeriodicHandle()
    # set the delegate to be the Handle for call_at,
    # causes periodic.cancel() to cancel the call to run
    periodic.delegate = loop.call_at(started + interval, run, periodic)
    # return the 'wrapper'
    return periodic


def _check_file(modify_times, path):
    try:
        modified = os.stat(path).st_mtime
    except Exception:
        return
    if path not in modify_times:
        modify_times[path] = modified
        return
    if modify_times[path] != modified:
        web_logger.info("%s modified; restarting server", path)
        _reload()


def _reload_on_update(modify_times):
    if _reload_attempted:
        # We already tried to reload and it didn't work, so don't try again.
        return
    for module in list(sys.modules.values()):
        # Some modules play games with sys.modules (e.g. email/__init__.py
        # in the standard library), and occasionally this can cause strange
        # failures in getattr.  Just ignore anything that's not an ordinary
        # module.
        if not isinstance(module, types.ModuleType):
            continue
        path = getattr(module, "__file__", None)
        if not path:
            continue
        if path.endswith(".pyc") or path.endswith(".pyo"):
            path = path[:-1]
        _check_file(modify_times, path)
    for path in _watched_files:
        _check_file(modify_times, path)


def _reload():
    global _reload_attempted
    _reload_attempted = True
    for fn in _reload_hooks:
        fn()
    if hasattr(signal, "setitimer"):
        # Clear the alarm signal set by
        # ioloop.set_blocking_log_threshold so it doesn't fire
        # after the exec.
        signal.setitimer(signal.ITIMER_REAL, 0, 0)
    # sys.path fixes: see comments at top of file.  If sys.path[0] is an empty
    # string, we were (probably) invoked with -m and the effective path
    # is about to change on re-exec.  Add the current directory to $PYTHONPATH
    # to ensure that the new process sees the same path we did.
    path_prefix = '.' + os.pathsep
    if (sys.path[0] == '' and
            not os.environ.get("PYTHONPATH", "").startswith(path_prefix)):
        os.environ["PYTHONPATH"] = (
            path_prefix + os.environ.get("PYTHONPATH", "")
        )

    if not _has_execv:
        subprocess.Popen([sys.executable] + sys.argv)
        sys.exit(0)
    else:
        try:
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except OSError:
            # Mac OS X versions prior to 10.6 do not support execv in
            # a process that contains multiple threads.  Instead of
            # re-executing in the current process, start a new one
            # and cause the current process to exit.  This isn't
            # ideal since the new process is detached from the parent
            # terminal and thus cannot easily be killed with ctrl-C,
            # but it's better than not being able to autoreload at
            # all.
            # Unfortunately the errno returned in this case does not
            # appear to be consistent, so we can't easily check for
            # this error specifically.
            os.spawnv(os.P_NOWAIT, sys.executable,
                      [sys.executable] + sys.argv)
            # At this point the IOLoop has been closed and finally
            # blocks will experience errors if we allow the stack to
            # unwind, so just exit uncleanly.
            os._exit(0)
