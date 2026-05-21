import sys
from unittest import mock

import pytest
from pytest_mock import MockerFixture

from aiohttp import web


def test_entry_func_empty(mocker: MockerFixture) -> None:
    error = mocker.patch("aiohttp.web.ArgumentParser.error", side_effect=SystemExit)
    argv = [""]

    with pytest.raises(SystemExit):
        web.main(argv)

    error.assert_called_with("'entry-func' not in 'module:function' syntax")


def test_entry_func_only_module(mocker: MockerFixture) -> None:
    argv = ["test"]
    error = mocker.patch("aiohttp.web.ArgumentParser.error", side_effect=SystemExit)

    with pytest.raises(SystemExit):
        web.main(argv)

    error.assert_called_with("'entry-func' not in 'module:function' syntax")


def test_entry_func_only_function(mocker: MockerFixture) -> None:
    argv = [":test"]
    error = mocker.patch("aiohttp.web.ArgumentParser.error", side_effect=SystemExit)

    with pytest.raises(SystemExit):
        web.main(argv)

    error.assert_called_with("'entry-func' not in 'module:function' syntax")


def test_entry_func_only_separator(mocker: MockerFixture) -> None:
    argv = [":"]
    error = mocker.patch("aiohttp.web.ArgumentParser.error", side_effect=SystemExit)

    with pytest.raises(SystemExit):
        web.main(argv)

    error.assert_called_with("'entry-func' not in 'module:function' syntax")


def test_entry_func_relative_module(mocker: MockerFixture) -> None:
    argv = [".a.b:c"]

    error = mocker.patch("aiohttp.web.ArgumentParser.error", side_effect=SystemExit)
    with pytest.raises(SystemExit):
        web.main(argv)

    error.assert_called_with("relative module names not supported")


def test_entry_func_non_existent_module(mocker: MockerFixture) -> None:
    argv = ["alpha.beta:func"]

    mocker.patch("aiohttp.web.import_module", side_effect=ImportError("Test Error"))
    error = mocker.patch("aiohttp.web.ArgumentParser.error", side_effect=SystemExit)

    with pytest.raises(SystemExit):
        web.main(argv)

    error.assert_called_with("unable to import alpha.beta: Test Error")


def test_entry_func_non_existent_attribute(mocker: MockerFixture) -> None:
    argv = ["alpha.beta:func"]
    import_module = mocker.patch("aiohttp.web.import_module")
    error = mocker.patch("aiohttp.web.ArgumentParser.error", side_effect=SystemExit)
    module = import_module("alpha.beta")
    del module.func

    with pytest.raises(SystemExit):
        web.main(argv)

    error.assert_called_with(
        "module {!r} has no attribute {!r}".format("alpha.beta", "func")
    )


@pytest.mark.skipif(sys.platform.startswith("win32"), reason="Windows not Unix")
def test_path_no_host(mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    argv = "--path=test_path.sock alpha.beta:func".split()
    mocker.patch("aiohttp.web.import_module")

    run_app = mocker.patch("aiohttp.web.run_app")
    with pytest.raises(SystemExit):
        web.main(argv)

    run_app.assert_called_with(mock.ANY, path="test_path.sock", host=None, port=None)


@pytest.mark.skipif(sys.platform.startswith("win32"), reason="Windows not Unix")
def test_path_and_host(mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    argv = "--path=test_path.sock --host=localhost --port=8000 alpha.beta:func".split()
    mocker.patch("aiohttp.web.import_module")

    run_app = mocker.patch("aiohttp.web.run_app")
    with pytest.raises(SystemExit):
        web.main(argv)

    run_app.assert_called_with(
        mock.ANY, path="test_path.sock", host="localhost", port=8000
    )


def test_path_when_unsupported(
    mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    argv = "--path=test_path.sock alpha.beta:func".split()
    mocker.patch("aiohttp.web.import_module")
    monkeypatch.delattr("socket.AF_UNIX", raising=False)

    error = mocker.patch("aiohttp.web.ArgumentParser.error", side_effect=SystemExit)
    with pytest.raises(SystemExit):
        web.main(argv)

    error.assert_called_with(
        "file system paths not supported by your operating environment"
    )


def test_entry_func_call(mocker: MockerFixture) -> None:
    mocker.patch("aiohttp.web.run_app")
    import_module = mocker.patch("aiohttp.web.import_module")
    argv = (
        "-H testhost -P 6666 --extra-optional-eins alpha.beta:func "
        "--extra-optional-zwei extra positional args"
    ).split()
    module = import_module("alpha.beta")

    with pytest.raises(SystemExit):
        web.main(argv)

    module.func.assert_called_with(
        ("--extra-optional-eins --extra-optional-zwei extra positional args").split()
    )


def test_running_application(mocker: MockerFixture) -> None:
    run_app = mocker.patch("aiohttp.web.run_app")
    import_module = mocker.patch("aiohttp.web.import_module")
    exit = mocker.patch("aiohttp.web.ArgumentParser.exit", side_effect=SystemExit)
    argv = (
        "-H testhost -P 6666 --extra-optional-eins alpha.beta:func "
        "--extra-optional-zwei extra positional args"
    ).split()
    module = import_module("alpha.beta")
    app = module.func()

    with pytest.raises(SystemExit):
        web.main(argv)

    run_app.assert_called_with(app, host="testhost", port=6666, path=None)
    exit.assert_called_with(message="Stopped\n")
