#!/usr/bin/env python3
"""Read and verify the coordinator-provided Engine source readiness manifest.

The manifest is JSON.  Accepted shapes:

  ["/abs/or/rel/config.cpp", ...]
  {"sources": ["..."]}
  {"engine_sources": [{"path": "...", "sha256": "..."}, ...]}
  {"files": [...]}

Each item may be a string path or an object with ``path``/``file``/``source``
and optional ``sha256``/``hash``.  Paths are resolved against the manifest
directory, then the repository root, then this tests directory.  No wildcard
or directory expansion is performed: the manifest is the explicit source list.

For a clean checkout without the coordinator's private marker, generate an
explicit local-source manifest (two Engine units + public/private headers):

  python3 readiness.py --create-local-manifest /tmp/test-local-manifest.json

Then point the harness at it explicitly, e.g.
``READY_MARKER=/tmp/test-local-manifest.json make -f Makefile.integration ...``.
The generated document is labelled ``local-source`` and is not an approval.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parents[2]
DEFAULT_MARKER = "/tmp/native-tcp-proxy/test-engine-sources-ready.json"

# Explicit reviewed Engine source list.  Never replace this with a wildcard:
# Admin/plugin sources in the tree are unrelated to this standalone Engine.
# The four-table change retires the standalone selection/health implementation;
# only config.cpp and engine.cpp remain translation units.
LOCAL_ENGINE_SOURCES = (
    "plugins/tcp_proxy/src/config.cpp",
    "plugins/tcp_proxy/src/engine.cpp",
    "plugins/tcp_proxy/include/tcp_proxy.h",
    "plugins/tcp_proxy/src/engine_internal.h",
)


def create_local_manifest(path: Path, root: Path = REPO_ROOT) -> dict:
    """Write an explicit local-source manifest with computed SHA256 hashes.

    This is a reproducibility convenience for a clean checkout.  It labels the
    manifest ``local-source`` and makes no coordinator-approval claim.
    """
    engine_sources = []
    sha256 = {}
    problems = []
    for relative in LOCAL_ENGINE_SOURCES:
        candidate = root / relative
        if not candidate.is_file():
            problems.append(f"source missing: {relative} -> {candidate}")
            continue
        digest = sha256_file(candidate)
        engine_sources.append({"path": relative, "sha256": digest})
        sha256[relative] = digest
    if problems:
        raise ValueError("; ".join(problems))
    document = {
        "status": "LOCAL-SOURCE MANIFEST (generated from this checkout; "
                  "not coordinator approval)",
        "generation": "local-source",
        "source_root": str(root),
        "engine_sources": engine_sources,
        "sha256": sha256,
        "note": "Explicit reviewed Engine sources only: two implementation "
                "units (config.cpp, engine.cpp) plus the public and private "
                "headers. Admin/plugin sources are never wildcarded. Use this "
                "path explicitly as READY_MARKER for a clean-checkout local run; "
                "it does not replace the coordinator readiness gate during "
                "active work.",
    }
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return document



def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_items(document) -> list:
    if isinstance(document, list):
        return document
    if not isinstance(document, dict):
        raise ValueError("manifest must be a JSON array or object")
    for key in ("sources", "engine_sources", "files", "paths", "approved_sources"):
        value = document.get(key)
        if isinstance(value, list):
            return value
    raise ValueError("manifest has no sources/engine_sources/files/paths array")


def item_path(item) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        for key in ("path", "file", "source", "name"):
            value = item.get(key)
            if isinstance(value, str) and value:
                return value
    raise ValueError(f"manifest item has no path: {item!r}")


def item_hash(item) -> str:
    if isinstance(item, dict):
        for key in ("sha256", "hash", "digest"):
            value = item.get(key)
            if isinstance(value, str) and value:
                return value.lower()
    return ""


def resolve(path_text: str, marker: Path) -> Path:
    candidate = Path(path_text).expanduser()
    if candidate.is_absolute():
        return candidate
    search = [marker.parent, REPO_ROOT, TESTS_DIR, Path.cwd()]
    for base in search:
        path = base / candidate
        if path.exists():
            return path
    return marker.parent / candidate


def load(marker: Path) -> tuple[list[dict], list[str]]:
    document = json.loads(marker.read_text(encoding="utf-8"))
    sources = []
    problems = []
    for item in extract_items(document):
        raw = item_path(item)
        if any(char in raw for char in "*?["):
            problems.append(f"wildcard source not allowed: {raw}")
            continue
        path = resolve(raw, marker)
        if not path.is_file():
            problems.append(f"source missing: {raw} -> {path}")
            continue
        expected = item_hash(item)
        actual = sha256_file(path)
        if expected and expected != actual:
            problems.append(f"sha256 mismatch for {path}: expected {expected}, got {actual}")
        sources.append({"path": str(path), "sha256": actual,
                        "expected_sha256": expected, "exists": True})
    if not sources and not problems:
        problems.append("manifest contains no sources")
    return sources, problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--marker", default=os.environ.get("TCP_PROXY_ENGINE_READY",
                                                           DEFAULT_MARKER))
    parser.add_argument("--check", action="store_true",
                        help="verify marker, files and hashes; exit nonzero on failure")
    parser.add_argument("--emit-srcs", action="store_true",
                        help="print space-separated resolved source paths")
    parser.add_argument("--json", action="store_true", help="print a JSON summary")
    parser.add_argument("--create-local-manifest", metavar="PATH",
                        help="write an explicit local-source manifest with "
                             "computed hashes (does not read the readiness "
                             "marker or claim coordinator approval)")
    args = parser.parse_args(argv)

    if args.create_local_manifest:
        try:
            document = create_local_manifest(Path(args.create_local_manifest))
        except (OSError, ValueError) as exc:
            print(f"local manifest generation failed: {exc}", file=sys.stderr)
            return 2
        print(f"local manifest written: {args.create_local_manifest} "
              f"({len(document['engine_sources'])} explicit sources, "
              "generation=local-source)")
        return 0

    marker = Path(args.marker)
    if not marker.is_file():
        print(f"readiness marker absent: {marker}", file=sys.stderr)
        return 2
    try:
        sources, problems = load(marker)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"invalid readiness marker {marker}: {exc}", file=sys.stderr)
        return 2

    if args.emit_srcs and not problems:
        # Local manifests hash headers too; only implementation units are
        # compiler inputs, so headers cannot become extra translation units.
        print(" ".join(source["path"] for source in sources
                       if Path(source["path"]).suffix == ".cpp"))
        return 0
    if args.json:
        print(json.dumps({"marker": str(marker), "sources": sources,
                          "problems": problems}, indent=2))
    if problems:
        for problem in problems:
            print(f"readiness error: {problem}", file=sys.stderr)
        return 1
    if args.check:
        total = sum(os.path.getsize(source["path"]) for source in sources)
        print(f"readiness OK: {len(sources)} source(s), {total} bytes, marker {marker}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
