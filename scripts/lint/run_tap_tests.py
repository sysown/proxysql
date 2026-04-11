#!/usr/bin/env python3

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence

from clang_tidy_utils import (
    build_header_filter,
    get_repo_root,
    normalize_clang_tidy_content,
)


ALLOWED_ROOTS: tuple[str, ...] = (
    "include",
    "lib",
    "test/tap/tests",
    "test/tap/tests/unit",
)


def discover_test_sources(repo_root: str | Path) -> list[Path]:
    root = Path(repo_root)
    candidates: list[Path] = []
    base = root / "test/tap/tests"
    if base.exists():
        for path in sorted(base.glob("*-t.cpp")):
            if path.is_file():
                candidates.append(path)

    unit = root / "test/tap/tests/unit"
    if unit.exists():
        for path in sorted(unit.glob("*-t.cpp")):
            if path.is_file():
                candidates.append(path)
    return candidates


def select_test_sources(repo_root: Path, args: Sequence[str]) -> list[Path]:
    if not args:
        return discover_test_sources(repo_root)

    selected: list[Path] = []
    for item in args:
        path = Path(item)
        if not path.is_absolute():
            path = (repo_root / path).resolve()
        if path.is_file() and path.name.endswith("-t.cpp"):
            selected.append(path)
    return selected


def run_clang_tidy_for_file(
    clang_tidy_bin: str,
    repo_root: Path,
    compile_db_dir: Path,
    source_file: Path,
    header_filter: str,
) -> list[str]:
    proc = subprocess.run(
        [
            clang_tidy_bin,
            "-p",
            str(compile_db_dir),
            f"--header-filter={header_filter}",
            str(source_file),
        ],
        cwd=str(repo_root),
        text=True,
        capture_output=True,
        check=False,
    )
    return normalize_clang_tidy_content(
        proc.stdout + proc.stderr,
        repo_root=repo_root,
        allowed_roots=ALLOWED_ROOTS,
    )


def _include_args(repo_root: Path) -> list[str]:
    paths = [
        "test/tap/tap",
        "include",
        "test/tap/test_helpers",
        "deps/re2/re2",
        "deps/jemalloc/jemalloc/include",
        "deps/libconfig/libconfig/lib",
        "deps/mariadb-client-library/mariadb_client/include",
        "deps/libdaemon/libdaemon",
        "deps/libmicrohttpd/libmicrohttpd",
        "deps/libhttpserver/libhttpserver/src",
        "deps/curl/curl/include",
        "deps/libev/libev",
        "deps/prometheus-cpp/prometheus-cpp/pull/include",
        "deps/prometheus-cpp/prometheus-cpp/core/include",
        "deps/json",
        "deps/sqlite3/sqlite3",
        "deps/postgresql/postgresql/src/include",
        "deps/postgresql/postgresql/src/interfaces/libpq",
        "deps/libscram/include",
        "deps/libusual/libusual",
        "deps/clickhouse-cpp/clickhouse-cpp",
        "deps/clickhouse-cpp/clickhouse-cpp/contrib/absl",
        "deps/lz4/lz4/lib",
        "deps/zstd/zstd/lib",
    ]
    return [f"-I{repo_root / rel}" for rel in paths]


def build_compile_database(repo_root: Path, sources: Sequence[Path]) -> Path:
    lint_dir = repo_root / "lint"
    lint_dir.mkdir(exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix="tap-clang-tidy-", dir=str(lint_dir)))
    compile_commands = []
    for source in sources:
        compile_commands.append(
            {
                "directory": str(repo_root),
                "file": str(source),
                "arguments": [
                    "clang++",
                    "-std=c++17",
                    "-O0",
                    "-g",
                    *(_include_args(repo_root)),
                    "-x",
                    "c++",
                    "-c",
                    str(source),
                ],
            }
        )
    (temp_dir / "compile_commands.json").write_text(json.dumps(compile_commands, indent=2) + "\n")
    return temp_dir


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    repo_root = get_repo_root()
    clang_tidy_bin = "clang-tidy"
    lint_dir = repo_root / "lint"
    lint_dir.mkdir(exist_ok=True)
    output_file = lint_dir / "clang-tidy-tests.txt"

    sources = select_test_sources(repo_root, argv)
    if not sources:
        output_file.write_text("")
        print("TAP test clang-tidy lint: OK (0 files)")
        return 0

    db_dir = build_compile_database(repo_root, sources)
    try:
        header_filter = build_header_filter(repo_root, ALLOWED_ROOTS)
        diagnostics: list[str] = []
        for source_file in sources:
            diagnostics.extend(
                run_clang_tidy_for_file(
                    clang_tidy_bin,
                    repo_root,
                    db_dir,
                    source_file,
                    header_filter,
                )
            )

        diagnostics = sorted(set(diagnostics))
        output_file.write_text("\n".join(diagnostics) + ("\n" if diagnostics else ""))

        if diagnostics:
            for line in diagnostics:
                print(line)
            return 1

        print(f"TAP test clang-tidy lint: OK ({len(sources)} files)")
        return 0
    finally:
        shutil.rmtree(db_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
