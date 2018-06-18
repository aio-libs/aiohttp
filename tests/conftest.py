import pathlib
import shutil
import tempfile

import pytest


pytest_plugins = ['aiohttp.pytest_plugin', 'pytester']


@pytest.fixture
def shorttmpdir():
    """Provides a temporary directory with a shorter file system path than the
    tmpdir fixture.
    """
    tmpdir = pathlib.Path(tempfile.mkdtemp())
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)
