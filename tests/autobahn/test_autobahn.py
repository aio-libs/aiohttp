import os
import shutil

import pytest
from python_on_whales import DockerClient


@pytest.fixture(scope="session", autouse=True)
def create_report_directory():
    path = "reports"
    if os.path.isdir(path):
        shutil.rmtree(path)
    os.mkdir(path)


@pytest.fixture(scope="session", autouse=True)
def build_aiohttp_docker_image():
    docker = DockerClient(compose_files=["docker-compose.yml"])
    yield docker.compose.build()
    docker.compose.rm()


def test_client():
    docker = DockerClient(compose_files=["client/docker-compose.yml"])
    docker.compose.up(abort_on_container_exit=True)
    docker.compose.down()


def test_server():
    docker = DockerClient(compose_files=["server/docker-compose.yml"])
    docker.compose.up(abort_on_container_exit=True)
    docker.compose.down()
