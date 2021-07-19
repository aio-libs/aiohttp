import json
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


def get_failed_tests(report_path: str, name) -> list[dict]:
    with open(Path(f"{report_path}/index.json")) as f:
        result_summary = json.load(f)[name]
    failed_messages = []
    PASS = {"OK", "INFORMATIONAL"}
    for results in result_summary.values():
        if results["behavior"] not in PASS or results["behaviorClose"] not in PASS:
            with open(Path(f"{report_path}/{results['reportfile']}")) as f:
                report = json.load(f)
                failed_messages.append(
                    {
                        "case": report["case"],
                        "description": report["description"],
                        "expectation": report["expectation"],
                        "expected": report["expected"],
                        "received": report["received"],
                    }
                )
    return failed_messages


def test_client() -> None:
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

    failed_messages = get_failed_tests("tests/autobahn/reports/clients", "aiohttp")

    if failed_messages:
        pytest.fail(
            "\n".join(
                [
                    f"case: {msg['case']}"
                    f"\ndescription: {msg['description']}"
                    f"\nexpectation: {msg['expectation']}"
                    f"\nexpected: {msg['expected']}"
                    f"\nreceived: {msg['received']}"
                    for msg in failed_messages
                ]
            ),
            pytrace=False,
        )


def test_server() -> None:
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

    failed_messages = get_failed_tests(
        "tests/autobahn/reports/servers", "AutobahnServer"
    )

    if failed_messages:
        pytest.fail(
            "\n".join(
                [
                    f"case: {msg['case']}"
                    f"\ndescription: {msg['description']}"
                    f"\nexpectation: {msg['expectation']}"
                    f"\nexpected: {msg['expected']}"
                    f"\nreceived: {msg['received']}"
                    for msg in failed_messages
                ]
            ),
            pytrace=False,
        )
