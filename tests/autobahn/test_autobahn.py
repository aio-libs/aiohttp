import shutil
from pathlib import Path

import pytest
from python_on_whales import DockerClient


@pytest.fixture(scope="session", autouse=True)
def create_report_directory():
    path = Path("tests/autobahn/reports")
    if path.is_dir():
        shutil.rmtree(path)
    path.mkdir()


@pytest.fixture(scope="session", autouse=True)
def build_aiohttp_docker_image():
    docker = DockerClient()
    docker.buildx.build(
        context_path=".", file="tests/autobahn/Dockerfile.aiohttp", tags=["aiohttp"]
    )
    try:
        yield
    finally:
        docker.buildx.remove("default")


def test_client():
    docker = DockerClient(compose_files=["tests/autobahn/client/docker-compose.yml"])
    docker.compose.up(abort_on_container_exit=True)
    docker.compose.down()


def test_server():
    docker = DockerClient(compose_files=["tests/autobahn/server/docker-compose.yml"])
    docker.compose.up(abort_on_container_exit=True)
    docker.compose.down()
