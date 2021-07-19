import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.fixture(scope="function", autouse=True)
def create_report_directory(request):
    path = Path(f"{request.fspath.dirname}/reports")
    if path.is_dir():
        shutil.rmtree(path)
    path.mkdir()


@pytest.fixture(scope="session", autouse=True)
def build_aiohttp_docker_image():
    subprocess.run(
        [
            "docker",
            "build",
            "-f",
            "tests/autobahn/Dockerfile.aiohttp",
            "-t",
            "aiohttp",
            ".",
        ]
    )


def test_client():
    subprocess.run(
        [
            "docker-compose",
            "-f",
            "tests/autobahn/client/docker-compose.yml",
            "up",
            "--abort-on-container-exit",
        ]
    )

    subprocess.run(
        ["docker-compose", "-f", "tests/autobahn/client/docker-compose.yml", "down"]
    )


def test_server():
    subprocess.run(
        [
            "docker-compose",
            "-f",
            "tests/autobahn/server/docker-compose.yml",
            "up",
            "--abort-on-container-exit",
        ]
    )

    subprocess.run(
        ["docker-compose", "-f", "tests/autobahn/server/docker-compose.yml", "down"]
    )
