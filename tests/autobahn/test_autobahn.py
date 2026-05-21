import json
import pprint
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from pytest import TempPathFactory

if TYPE_CHECKING:
    from python_on_whales import DockerException, docker
else:
    python_on_whales = pytest.importorskip("python_on_whales")
    DockerException = python_on_whales.DockerException
    docker = python_on_whales.docker

# (Test number, test status, test report)
Result = tuple[str, str, dict[str, object] | None]


@pytest.fixture(scope="session")
def report_dir(tmp_path_factory: TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("reports")


@pytest.fixture(scope="session", autouse=True)
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


def get_report(path: Path, result: dict[str, str]) -> dict[str, object] | None:
    if result["behaviorClose"] == "OK":
        return None
    return json.loads((path / result["reportfile"]).read_text())  # type: ignore[no-any-return]


def get_test_results(path: Path, name: str) -> tuple[Result, ...]:
    results = json.loads((path / "index.json").read_text())[name]
    return tuple(
        (k, r["behaviorClose"], get_report(path, r)) for k, r in results.items()
    )


def process_xfail(
    results: tuple[Result, ...], xfail: dict[str, str]
) -> list[dict[str, object]]:
    failed = []
    for number, status, details in results:
        if number in xfail:
            assert status not in {"OK", "INFORMATIONAL"}  # Strict xfail
            assert details is not None
            if details["result"] == xfail[number]:
                continue
        if status not in {"OK", "INFORMATIONAL"}:  # pragma: no cover
            assert details is not None
            pprint.pprint(details)
            failed.append(details)
    return failed


@pytest.mark.autobahn
def test_client(report_dir: Path, request: pytest.FixtureRequest) -> None:
    client = subprocess.Popen(
        (
            "wait-for-it",
            "-s",
            "localhost:9001",
            "--",
            "coverage",
            "run",
            "-a",
            "tests/autobahn/client/client.py",
        )
    )
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
        client.wait()
    finally:
        client.terminate()
        client.wait()
        autobahn_container.stop()

    results = get_test_results(report_dir / "clients", "aiohttp")
    xfail = {
        "3.4": "Actual events match at least one expected.",
        "7.9.5": "The close code should have been 1002 or empty",
        "9.1.4": "Did not receive message within 100 seconds.",
        "9.1.5": "Did not receive message within 100 seconds.",
        "9.1.6": "Did not receive message within 100 seconds.",
        "9.2.4": "Did not receive message within 10 seconds.",
        "9.2.5": "Did not receive message within 100 seconds.",
        "9.2.6": "Did not receive message within 100 seconds.",
        "9.3.1": "Did not receive message within 100 seconds.",
        "9.3.2": "Did not receive message within 100 seconds.",
        "9.3.3": "Did not receive message within 100 seconds.",
        "9.3.4": "Did not receive message within 100 seconds.",
        "9.3.5": "Did not receive message within 100 seconds.",
        "9.3.6": "Did not receive message within 100 seconds.",
        "9.3.7": "Did not receive message within 100 seconds.",
        "9.3.8": "Did not receive message within 100 seconds.",
        "9.3.9": "Did not receive message within 100 seconds.",
        "9.4.1": "Did not receive message within 100 seconds.",
        "9.4.2": "Did not receive message within 100 seconds.",
        "9.4.3": "Did not receive message within 100 seconds.",
        "9.4.4": "Did not receive message within 100 seconds.",
        "9.4.5": "Did not receive message within 100 seconds.",
        "9.4.6": "Did not receive message within 100 seconds.",
        "9.4.7": "Did not receive message within 100 seconds.",
        "9.4.8": "Did not receive message within 100 seconds.",
        "9.4.9": "Did not receive message within 100 seconds.",
    }
    assert not process_xfail(results, xfail)


@pytest.mark.autobahn
def test_server(report_dir: Path, request: pytest.FixtureRequest) -> None:
    server = subprocess.Popen(
        ("coverage", "run", "-a", "tests/autobahn/server/server.py")
    )
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
    xfail = {
        "7.9.5": "The close code should have been 1002 or empty",
        "9.1.4": "Did not receive message within 100 seconds.",
        "9.1.5": "Did not receive message within 100 seconds.",
        "9.1.6": "Did not receive message within 100 seconds.",
        "9.2.4": "Did not receive message within 10 seconds.",
        "9.2.5": "Did not receive message within 100 seconds.",
        "9.2.6": "Did not receive message within 100 seconds.",
        "9.3.1": "Did not receive message within 100 seconds.",
        "9.3.2": "Did not receive message within 100 seconds.",
        "9.3.3": "Did not receive message within 100 seconds.",
        "9.3.4": "Did not receive message within 100 seconds.",
        "9.3.5": "Did not receive message within 100 seconds.",
        "9.3.6": "Did not receive message within 100 seconds.",
        "9.3.7": "Did not receive message within 100 seconds.",
        "9.3.8": "Did not receive message within 100 seconds.",
        "9.3.9": "Did not receive message within 100 seconds.",
        "9.4.1": "Did not receive message within 100 seconds.",
        "9.4.2": "Did not receive message within 100 seconds.",
        "9.4.3": "Did not receive message within 100 seconds.",
        "9.4.4": "Did not receive message within 100 seconds.",
        "9.4.5": "Did not receive message within 100 seconds.",
        "9.4.6": "Did not receive message within 100 seconds.",
        "9.4.7": "Did not receive message within 100 seconds.",
        "9.4.8": "Did not receive message within 100 seconds.",
        "9.4.9": "Did not receive message within 100 seconds.",
    }
    assert not process_xfail(results, xfail)
