#!/usr/bin/env python3

"""Shared helpers for clang-tidy normalization."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

import yaml


DEFAULT_ALLOWED_ROOTS: tuple[str, ...] = ("include", "lib")


def get_repo_root(start: str | Path | None = None) -> Path:
    base = Path(start or os.getcwd())
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(base),
            stderr=subprocess.DEVNULL,
        )
        return Path(out.decode().strip()).resolve()
    except Exception:
        return base.resolve()


def canonical_path(path: str | None, repo_root: str | Path) -> Path | None:
    if not path:
        return None
    if path.startswith("<") and path.endswith(">"):
        return None

    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path(repo_root) / candidate
    return candidate.resolve()


def _allowed_root_paths(repo_root: str | Path, allowed_roots: Sequence[str]) -> list[Path]:
    root = Path(repo_root).resolve()
    resolved: list[Path] = []
    for item in allowed_roots:
        candidate = Path(item)
        if not candidate.is_absolute():
            candidate = root / candidate
        resolved.append(candidate.resolve())
    return resolved


def path_within_allowed_roots(
    cpath: Path | None,
    repo_root: str | Path,
    allowed_roots: Sequence[str],
) -> bool:
    if cpath is None:
        return False

    for root in _allowed_root_paths(repo_root, allowed_roots):
        try:
            if os.path.commonpath([str(cpath), str(root)]) == str(root):
                return True
        except ValueError:
            continue
    return False


def _offset_to_line(path: Path, offset: int) -> int:
    try:
        data = path.read_bytes()
    except Exception:
        return 0
    return data[:offset].count(b"\n") + 1


def _normalize_yaml_diagnostics(
    data: dict,
    repo_root: str | Path,
    allowed_roots: Sequence[str],
) -> list[str]:
    diagnostics: set[str] = set()
    for diag in data.get("Diagnostics", []):
        msg = diag.get("DiagnosticMessage", {}) or {}
        cpath = canonical_path(msg.get("FilePath"), repo_root)
        if not path_within_allowed_roots(cpath, repo_root, allowed_roots):
            continue

        line_no = msg.get("FileLine") or 0
        offset = msg.get("FileOffset")
        if (not line_no) and offset is not None and cpath is not None:
            line_no = _offset_to_line(cpath, int(offset))

        check = diag.get("CheckName") or diag.get("DiagnosticName") or ""
        message = (msg.get("Message") or "").strip()
        diagnostics.add(f"{cpath}:{line_no}: {check} - {message}")
    return sorted(diagnostics)


_TEXT_DIAG_RE = re.compile(
    r"^(?P<file>[^:]+):(?P<line>\d+):(\d+:)?\s*(?P<kind>warning|error|note):?\s*(?P<msg>.*)\s*\[(?P<check>[^\]]+)\]$"
)


def _normalize_text_diagnostics(
    content: str,
    repo_root: str | Path,
    allowed_roots: Sequence[str],
) -> list[str]:
    diagnostics: set[str] = set()
    for line in content.splitlines():
        match = _TEXT_DIAG_RE.match(line)
        if not match:
            continue

        cpath = canonical_path(match.group("file"), repo_root)
        if not path_within_allowed_roots(cpath, repo_root, allowed_roots):
            continue

        diagnostics.add(
            f"{cpath}:{match.group('line')}: {match.group('check')} - {match.group('msg').strip()}"
        )
    return sorted(diagnostics)


def normalize_clang_tidy_content(
    content: str,
    repo_root: str | Path | None = None,
    allowed_roots: Sequence[str] | None = None,
) -> list[str]:
    repo_root = repo_root or get_repo_root()
    allowed_roots = tuple(allowed_roots or DEFAULT_ALLOWED_ROOTS)

    try:
        data = yaml.safe_load(content)
    except Exception:
        data = None

    if isinstance(data, dict) and "Diagnostics" in data:
        return _normalize_yaml_diagnostics(data, repo_root, allowed_roots)

    return _normalize_text_diagnostics(content, repo_root, allowed_roots)


def normalize_clang_tidy_file(
    path: str | Path,
    repo_root: str | Path | None = None,
    allowed_roots: Sequence[str] | None = None,
) -> list[str]:
    file_path = Path(path)
    if not file_path.exists():
        return []
    return normalize_clang_tidy_content(
        file_path.read_text(errors="ignore"),
        repo_root=repo_root,
        allowed_roots=allowed_roots,
    )


def build_header_filter(repo_root: str | Path, allowed_roots: Sequence[str]) -> str:
    roots = _allowed_root_paths(repo_root, allowed_roots)
    parts = [re.escape(str(root)) for root in roots]
    return rf"^({'|'.join(parts)})/"
