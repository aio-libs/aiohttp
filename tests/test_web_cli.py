import pytest


from aiohttp import web
from unittest import mock


@mock.patch("aiohttp.web.ArgumentParser.error", side_effect=SystemExit)
def test_entry_func_empty(error):
    argv = [""]

    with pytest.raises(SystemExit):
        web.main(argv)

    error.assert_called_with(
        "'entry-func' not in 'module:function' syntax"
    )


@mock.patch("aiohttp.web.ArgumentParser.error", side_effect=SystemExit)
def test_entry_func_only_module(error):
    argv = ["test"]

    with pytest.raises(SystemExit):
        web.main(argv)

    error.assert_called_with(
        "'entry-func' not in 'module:function' syntax"
    )


@mock.patch("aiohttp.web.ArgumentParser.error", side_effect=SystemExit)
def test_entry_func_only_function(error):
    argv = [":test"]

    with pytest.raises(SystemExit):
        web.main(argv)

    error.assert_called_with(
        "'entry-func' not in 'module:function' syntax"
    )


@mock.patch("aiohttp.web.ArgumentParser.error", side_effect=SystemExit)
def test_entry_func_only_seperator(error):
    argv = [":"]

    with pytest.raises(SystemExit):
        web.main(argv)

    error.assert_called_with(
        "'entry-func' not in 'module:function' syntax"
    )


@mock.patch("aiohttp.web.ArgumentParser.error", side_effect=SystemExit)
def test_entry_func_relative_module(error):
    argv = [".a.b:c"]

    with pytest.raises(SystemExit):
        web.main(argv)

    error.assert_called_with("relative module names not supported")


@mock.patch("aiohttp.web.import_module", side_effect=ImportError)
@mock.patch("aiohttp.web.ArgumentParser.error", side_effect=SystemExit)
def test_entry_func_non_existent_module(error, import_module):
    argv = ["alpha.beta:func"]

    with pytest.raises(SystemExit):
        web.main(argv)

    error.assert_called_with("module %r not found" % "alpha.beta")


@mock.patch("aiohttp.web.import_module")
@mock.patch("aiohttp.web.ArgumentParser.error", side_effect=SystemExit)
def test_entry_func_non_existent_attribute(error, import_module):
    argv = ["alpha.beta:func"]
    module = import_module("alpha.beta")
    del module.func

    with pytest.raises(SystemExit):
        web.main(argv)

    error.assert_called_with(
        "module %r has no attribute %r" % ("alpha.beta", "func")
    )


@mock.patch("aiohttp.web.run_app")
@mock.patch("aiohttp.web.import_module")
def test_entry_func_call(import_module, run_app):
    argv = ("-H testhost -P 6666 --extra-optional-eins alpha.beta:func "
            "--extra-optional-zwei extra positional args").split()
    module = import_module("alpha.beta")

    with pytest.raises(SystemExit):
        web.main(argv)

    module.func.assert_called_with(
        ("--extra-optional-eins --extra-optional-zwei extra positional "
         "args").split()
    )


@mock.patch("aiohttp.web.run_app")
@mock.patch("aiohttp.web.import_module")
@mock.patch("aiohttp.web.ArgumentParser.exit", side_effect=SystemExit)
def test_running_application(exit, import_module, run_app):
    argv = ("-H testhost -P 6666 --extra-optional-eins alpha.beta:func "
            "--extra-optional-zwei extra positional args").split()
    module = import_module("alpha.beta")
    app = module.func()

    with pytest.raises(SystemExit):
        web.main(argv)

    run_app.assert_called_with(app, host="testhost", port=6666)
    exit.assert_called_with(message="Stopped\n")
