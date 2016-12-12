import pathlib
import subprocess

import pytest

from aiohttpdemo_polls.main import init


@pytest.fixture
def config():
    pass


@pytest.fixture
def config_path(config):
    pass


@pytest.fixture
def create_app(loop, config_path):
    app = init(loop, ['-c', config_path])
    return app


BASE_DIR = pathlib.Path(__file__).parent.parent


@pytest.fixture
def app_db():
    subprocess.call(
        [(BASE_DIR / 'sql' / 'install.sh').as_posix()],
        shell=True,
        cwd=BASE_DIR.as_posix()
    )
