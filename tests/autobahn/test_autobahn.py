import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Generator, List

import pytest
from python_on_whales import docker


@pytest.fixture(scope="module", autouse=True)
def create_report_directory(request: Any) -> None:
    path = Path(request.fspath.dirname) / "reports"
    if path.is_dir():
        shutil.rmtree(path)
    path.mkdir()


@pytest.fixture(scope="session", autouse=True)
def build_autobahn_testsuite() -> Generator[None, None, None]:
    docker.build(
        file="tests/autobahn/Dockerfile.autobahn",
        tags=["autobahn-testsuite"],
        context_path=".",
    )
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


@pytest.mark.skipif(sys.platform != "linux", reason="run only on Linux")
def test_client(request: Any) -> None:
    try:
        print("Starting autobahn-testsuite server")
        autobahn_container = docker.run(
            detach=True,
            image="autobahn-testsuite",
            name="autobahn",
            publish=[(9001, 9001)],
            remove=True,
            volumes=[
                (f"{request.fspath.dirname}/client", "/config"),
                (f"{request.fspath.dirname}/reports", "/reports"),
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

    failed_messages = get_failed_tests("tests/autobahn/reports/clients", "aiohttp")

    assert not failed_messages, "\n".join(
        "\n\t".join(
            f"{field}: {msg[field]}"
            for field in ("case", "description", "expectation", "expected", "received")
        )
        for msg in failed_messages
    )


@pytest.mark.skipif(sys.platform != "linux", reason="run only on Linux")
def test_server(request: Any) -> None:
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
                (f"{request.fspath.dirname}/server", "/config"),
                (f"{request.fspath.dirname}/reports", "/reports"),
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

    failed_messages = get_failed_tests(
        "tests/autobahn/reports/servers", "AutobahnServer"
    )

    assert not failed_messages, "\n".join(
        "\n\t".join(
            f"{field}: {msg[field]}"
            for field in ("case", "description", "expectation", "expected", "received")
        )
        for msg in failed_messages
    )
