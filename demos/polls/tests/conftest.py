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
def cli(loop, test_client, config_path):
    app = init(loop, ['-c', config_path])
    return loop.run_until_complete(test_client(app))


@pytest.fixture
def app_db():
    subprocess.call(
        [(BASE_DIR / 'sql' / 'install.sh').as_posix()],
        shell=True,
        cwd=BASE_DIR.as_posix()
    )
