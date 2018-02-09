import tempfile

import pytest
from py import path


pytest_plugins = ['aiohttp.pytest_plugin', 'pytester']


@pytest.fixture
def shorttmpdir():
    """Provides a temporary directory with a shorter file system path than the
    tmpdir fixture.
    """
    tmpdir = path.local(tempfile.mkdtemp())
    yield tmpdir
    tmpdir.remove(rec=1)
