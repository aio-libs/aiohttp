import json
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from pytest import TempPathFactory

if TYPE_CHECKING:
    from python_on_whales import DockerException, docker
else:
    python_on_whales = pytest.importorskip("python_on_whales")
    DockerException = python_on_whales.DockerException
    docker = python_on_whales.docker


@pytest.fixture(scope="module")
def report_dir(tmp_path_factory: TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("reports")


@pytest.fixture(scope="module", autouse=True)
def build_autobahn_testsuite() -> Iterator[None]:
    docker.build(
        file="tests/autobahn/Dockerfile.autobahn",
        tags=["autobahn-testsuite"],
        context_path=".",
    )

    try:
        yield
    finally:
        docker.image.remove(x="autobahn-testsuite")


def get_test_results(path: Path, name: str) -> list[dict[str, Any]]:
    result_summary = json.loads((path / "index.json").read_text())[name]
    print(result_summary)
    return result_summary
    failed_messages = []
    PASS = {"OK", "INFORMATIONAL"}
    entry_fields = {"case", "description", "expectation", "expected", "received"}
    for results in result_summary.values():
        if results["behavior"] in PASS and results["behaviorClose"] in PASS:
            continue
        report = json.loads((path / results["reportfile"]).read_text())
        failed_messages.append({field: report[field] for field in entry_fields})
    return failed_messages


def test_client(report_dir: Path, request: pytest.FixtureRequest) -> None:
    try:
        print("Starting autobahn-testsuite server")
        autobahn_container = docker.run(
            detach=True,
            image="autobahn-testsuite",
            name="autobahn",
            publish=[(9001, 9001)],
            remove=True,
            volumes=[
                (request.path.parent / "client", "/config"),
                (report_dir, "/reports"),
            ],
        )
        print("Running aiohttp test client")
        client = subprocess.Popen(
            ["wait-for-it", "-s", "localhost:9001", "--"]
            + [sys.executable]
            + ["tests/autobahn/client/client.py"]
        )
        client.wait()
    finally:
        print("Stopping client and server")
        client.terminate()
        client.wait()
        autobahn_container.stop()

    failed_messages = get_failed_tests(report_dir / "clients", "aiohttp")

    assert not failed_messages, "\n".join(
        "\n\t".join(
            f"{field}: {msg[field]}"
            for field in ("case", "description", "expectation", "expected", "received")
        )
        for msg in failed_messages
    )


def pytest_generate_tests(metafunc):
    if "server_result" in metafunc.fixturenames:
        metafunc.parametrize("server_result", ["d1", "d2"], indirect=True)


@pytest.fixture
def run_server_tests(report_dir: Path, request: pytest.FixtureRequest, metafunc) -> None:
    try:
        server = subprocess.Popen((sys.executable, "tests/autobahn/server/server.py"))
        docker.run(
            image="autobahn-testsuite",
            name="autobahn",
            remove=True,
            volumes=[
                (request.path.parent / "server", "/config"),
                (report_dir, "/reports"),
            ],
            networks=("host",),
            command=(
                "wait-for-it",
                "-s",
                "localhost:9001",
                "--",
                "wstest",
                "--mode",
                "fuzzingclient",
                "--spec",
                "/config/fuzzingclient.json",
            ),
        )
    finally:
        server.terminate()
        server.wait()

    return get_test_results(report_dir / "servers", "AutobahnServer")


def test_server(server_result) -> None:
    
