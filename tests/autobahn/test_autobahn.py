import json
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Generator, List

import pytest
from pytest import TempPathFactory

if TYPE_CHECKING:
    from python_on_whales import DockerException, docker
else:
    python_on_whales = pytest.importorskip("python_on_whales")
    DockerException = python_on_whales.DockerException
    docker = python_on_whales.docker


@pytest.fixture(scope="session")
def report_dir(tmp_path_factory: TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("reports")


@pytest.fixture(scope="session", autouse=True)
def build_autobahn_testsuite() -> Generator[None, None, None]:
    try:
        docker.build(
            file="tests/autobahn/Dockerfile.autobahn",
            tags=["autobahn-testsuite"],
            context_path=".",
        )
    except DockerException:
        pytest.skip("The docker daemon is not running.")

    try:
        yield
    finally:
        docker.image.remove(x="autobahn-testsuite")


def get_failed_tests(report_path: str, name: str) -> List[Dict[str, Any]]:
    path = Path(report_path)
    result_summary = json.loads((path / "index.json").read_text())[name]
    failed_messages = []
    PASS = {"OK", "INFORMATIONAL"}
    entry_fields = {"case", "description", "expectation", "expected", "received"}
    for results in result_summary.values():
        if results["behavior"] in PASS and results["behaviorClose"] in PASS:
            continue
        report = json.loads((path / results["reportfile"]).read_text())
        failed_messages.append({field: report[field] for field in entry_fields})
    return failed_messages


@pytest.mark.skipif(sys.platform == "darwin", reason="Don't run on macOS")
@pytest.mark.xfail
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
                (f"{request.path.parent}/client", "/config"),
                (f"{report_dir}", "/reports"),
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
        # https://github.com/gabrieldemarmiesse/python-on-whales/pull/580
        autobahn_container.stop()  # type: ignore[union-attr]

    failed_messages = get_failed_tests(f"{report_dir}/clients", "aiohttp")

    assert not failed_messages, "\n".join(
        "\n\t".join(
            f"{field}: {msg[field]}"
            for field in ("case", "description", "expectation", "expected", "received")
        )
        for msg in failed_messages
    )


@pytest.mark.skipif(sys.platform == "darwin", reason="Don't run on macOS")
@pytest.mark.xfail
def test_server(report_dir: Path, request: pytest.FixtureRequest) -> None:
    try:
        print("Starting aiohttp test server")
        server = subprocess.Popen(
            [sys.executable] + ["tests/autobahn/server/server.py"]
        )
        print("Starting autobahn-testsuite client")
        docker.run(
            image="autobahn-testsuite",
            name="autobahn",
            remove=True,
            volumes=[
                (f"{request.path.parent}/server", "/config"),
                (f"{report_dir}", "/reports"),
            ],
            networks=["host"],
            command=[
                "wait-for-it",
                "-s",
                "localhost:9001",
                "--",
                "wstest",
                "--mode",
                "fuzzingclient",
                "--spec",
                "/config/fuzzingclient.json",
            ],
        )
    finally:
        print("Stopping client and server")
        server.terminate()
        server.wait()

    failed_messages = get_failed_tests(f"{report_dir}/servers", "AutobahnServer")

    assert not failed_messages, "\n".join(
        "\n\t".join(
            f"{field}: {msg[field]}"
            for field in ("case", "description", "expectation", "expected", "received")
        )
        for msg in failed_messages
    )
