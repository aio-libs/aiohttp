import json
import subprocess
import sys
import tempfile
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

AUTOBAHN_PATH = Path(__file__).parent

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


def pytest_generate_tests(metafunc):
    if "client_result" in metafunc.fixturenames:
        with tempfile.TemporaryDirectory("reports") as tmp_dir:
            docker.build(
                file="tests/autobahn/Dockerfile.autobahn",
                tags=["autobahn-testsuite"],
                context_path=".",
            )
            try:
                test_results = run_client_tests(Path(tmp_dir))
            finally:
                docker.image.remove(x="autobahn-testsuite")
        metafunc.parametrize("client_result", test_results)
    if "server_result" in metafunc.fixturenames:
        with tempfile.TemporaryDirectory("reports") as tmp_dir:
            docker.build(
                file="tests/autobahn/Dockerfile.autobahn",
                tags=["autobahn-testsuite"],
                context_path=".",
            )
            try:
                test_results = run_server_tests(Path(tmp_dir))
            finally:
                docker.image.remove(x="autobahn-testsuite")
        metafunc.parametrize("server_result", test_results)


def run_client_tests(report_dir: Path) -> None:
    try:
        autobahn_container = docker.run(
            detach=True,
            image="autobahn-testsuite",
            name="autobahn",
            publish=[(9001, 9001)],
            remove=True,
            volumes=[
                (AUTOBAHN_PATH / "client", "/config"),
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

    return get_test_results(report_dir / "clients", "aiohttp")


def run_server_tests(report_dir: Path) -> None:
    try:
        server = subprocess.Popen((sys.executable, "tests/autobahn/server/server.py"))
        docker.run(
            image="autobahn-testsuite",
            name="autobahn",
            remove=True,
            volumes=[
                (AUTOBAHN_PATH / "server", "/config"),
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


@pytest.mark.autobahn
def test_client(client_result: Result) -> None:
    assert client_result[1] == "OK"


@pytest.mark.autobahn
def test_server(server_result: Result) -> None:
    assert server_result[1] == "OK"
