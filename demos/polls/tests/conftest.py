import pathlib
import subprocess

import pytest

from aiohttpdemo_polls.main import init

BASE_DIR = pathlib.Path(__file__).parent.parent


@pytest.fixture
def config_path():
    path = BASE_DIR / 'config' / 'polls.yaml'
    return path.as_posix()


@pytest.fixture
def create_app(event_loop, config_path):
    app = init(event_loop, ['-c', config_path])
    return app


@pytest.fixture
def app_db():
    subprocess.call(
        [(BASE_DIR / 'sql' / 'install.sh').as_posix()],
        shell=True,
        cwd=BASE_DIR.as_posix()
    )
