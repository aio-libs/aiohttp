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

# Test number, test status, error message
Result = tuple[str, str, str | None]


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


def get_err(path: Path, result) -> str | None:
    if r["behaviorClose"] == "OK":
        return None
    return json.loads((path / result["reportfile"]).read_text())


def get_test_results(path: Path, name: str) -> tuple[Result, ...]:
    results = json.loads((path / "index.json").read_text())[name]
    print(results)
    return tuple((k, r["behaviorClose"], get_err(path, r)) for k, r in results.items())
    failed_messages = []
    PASS = {"OK", "INFORMATIONAL"}
    entry_fields = {"case", "description", "expectation", "expected", "received"}
    for results in result_summary.values():
        if results["behavior"] in PASS and results["behaviorClose"] in PASS:
            continue
        report = json.loads((path / results["reportfile"]).read_text())
        failed_messages.append({field: report[field] for field in entry_fields})
    return failed_messages


@pytest.mark.autobahn
def test_client(report_dir: Path, request: pytest.FixtureRequest) -> None:
    try:
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
        client = subprocess.Popen(
            ["wait-for-it", "-s", "localhost:9001", "--"]
            + [sys.executable]
            + ["tests/autobahn/client/client.py"]
        )
        client.wait()
    finally:
        client.terminate()
        client.wait()
        autobahn_container.stop()

    results = get_test_results(report_dir / "clients", "aiohttp")

    assert results = {}


@pytest.mark.autobahn
def test_server(report_dir: Path, request: pytest.FixtureRequest) -> None:
    server = subprocess.Popen((sys.executable, "tests/autobahn/server/server.py"))
    try:
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

    results = get_test_results(report_dir / "servers", "AutobahnServer")
    assert results == {}
