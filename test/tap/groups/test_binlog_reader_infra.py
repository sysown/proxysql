#!/usr/bin/env python3

import re
import shlex
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
INFRA_NAMES = (
    "infra-dbdeployer-mysql84-binlog",
    "infra-dbdeployer-mysql90-binlog",
    "infra-dbdeployer-mysql95-binlog",
)
READER_IMAGE = "ghcr.io/sysown/proxysql-mysqlbinlog:2.4.0-ubuntu22"
READER_BINARY = "/bin/proxysql_binlog_reader"


def docker_stage_image(dockerfile: str, stage: str) -> str:
    for line in dockerfile.splitlines():
        fields = line.split()
        if len(fields) == 4 and fields[0].upper() == "FROM" and fields[2].upper() == "AS":
            if fields[3] == stage:
                return fields[1]
    raise AssertionError(f"Docker stage {stage!r} not found")


def copied_reader_source(dockerfile: str) -> str:
    pattern = re.compile(
        r"^COPY\s+--from=binlog-reader\s+(\S*proxysql_binlog_reader)\s+"
        r"/usr/local/bin/proxysql_binlog_reader\s*$",
        re.MULTILINE,
    )
    match = pattern.search(dockerfile)
    if match is None:
        raise AssertionError("binlog reader COPY instruction not found")
    return match.group(1)


def reader_command_tokens(entrypoint: str) -> list[str]:
    pattern = re.compile(
        r"^\s*proxysql_binlog_reader\s+\\\n(?P<arguments>.*?)"
        r"\s*>>\s*/var/log/mysqlbinlog/reader_\$\{MYSQL_PORT\}\.log",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(entrypoint)
    if match is None:
        raise AssertionError("binlog reader command not found")
    command = "proxysql_binlog_reader " + match.group("arguments").replace("\\\n", " ")
    return shlex.split(command)


class BinlogReaderInfraContractTest(unittest.TestCase):
    def test_all_modern_binlog_infras_use_v240_with_ci_tls_policy(self) -> None:
        for infra_name in INFRA_NAMES:
            with self.subTest(infra=infra_name):
                docker_dir = REPO_ROOT / "test" / "infra" / infra_name / "docker"
                dockerfile = (docker_dir / "Dockerfile").read_text(encoding="utf-8")
                entrypoint = (docker_dir / "entrypoint.sh").read_text(encoding="utf-8")

                self.assertEqual(
                    docker_stage_image(dockerfile, "binlog-reader"),
                    READER_IMAGE,
                )
                self.assertEqual(copied_reader_source(dockerfile), READER_BINARY)

                tokens = reader_command_tokens(entrypoint)
                self.assertIn("--ssl-mode=REQUIRED", tokens)
                self.assertIn("--ssl-verify-server-cert=0", tokens)


if __name__ == "__main__":
    unittest.main()
