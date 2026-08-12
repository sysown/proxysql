#!/usr/bin/env python3
"""Validate configuration and PostgreSQL role-verifier snapshots.

The module deliberately has no third-party imports at module load time.  The
database adapters used by later stages import their drivers only when they are
called.
"""

import argparse
import base64
import configparser
import os
import re
import stat
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path


class SyncError(RuntimeError):
    """An expected, safe-to-report synchronizer error."""


@dataclass(frozen=True)
class CLIOverrides:
    default_hostgroup: int | None = None
    missing_role_action: str | None = None
    save_to_disk: bool | None = None


@dataclass(frozen=True)
class SourceConfig:
    host: str
    port: int
    database: str
    username: str
    password: str = field(repr=False)
    connect_timeout: int = 10
    function_schema: str = "proxysql_auth"
    function_name: str = "export_login_roles"


@dataclass(frozen=True)
class ProxySQLConfig:
    host: str
    port: int
    username: str
    password: str = field(repr=False)
    connect_timeout: int = 10


@dataclass(frozen=True)
class SyncSettings:
    profile: str
    default_hostgroup: int = 0
    missing_role_action: str = "disable"
    adopt_existing_users: bool = False
    allow_empty_snapshot: bool = False
    save_to_disk: bool = True
    lock_file: Path = Path("/run/lock/proxysql-pgsql-user-sync.lock")


@dataclass(frozen=True)
class AppConfig:
    source: SourceConfig
    proxysql: ProxySQLConfig
    sync: SyncSettings


@dataclass(frozen=True)
class SourceRole:
    username: str
    password: str = field(repr=False)


PROFILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
MD5_RE = re.compile(r"md5[0-9a-f]{32}\Z")
SCRAM_RE = re.compile(
    r"SCRAM-SHA-256\$(?P<iterations>[0-9]+):(?P<salt>[^$]+)\$"
    r"(?P<stored>[^:]+):(?P<server>[^:]+)\Z"
)


def _error(message: str) -> SyncError:
    return SyncError(message)


def _required(section: configparser.SectionProxy, name: str) -> str:
    try:
        value = section[name].strip()
    except KeyError:
        raise _error(f"missing required configuration field {name!r}") from None
    if not value:
        raise _error(f"configuration field {name!r} must not be empty")
    return value


def _int_value(section: configparser.SectionProxy, name: str, default: int | None = None) -> int:
    if name not in section:
        if default is None:
            raise _error(f"missing required configuration field {name!r}")
        return default
    raw = section[name].strip()
    try:
        return int(raw, 10)
    except (TypeError, ValueError):
        raise _error(f"configuration field {name!r} must be an integer") from None


def _boolean_value(
    section: configparser.SectionProxy, name: str, default: bool | None = None
) -> bool:
    if name not in section:
        if default is None:
            raise _error(f"missing required configuration field {name!r}")
        return default
    raw = section[name].strip().lower()
    if raw == "true":
        return True
    if raw == "false":
        return False
    raise _error(f"configuration field {name!r} must be true or false")


def _section(parser: configparser.ConfigParser, name: str) -> configparser.SectionProxy:
    if not parser.has_section(name):
        raise _error(f"missing required configuration section [{name}]")
    return parser[name]


def _validate_endpoint(section: configparser.SectionProxy, section_name: str) -> tuple[str, int]:
    host = _required(section, "host")
    port = _int_value(section, "port")
    if not 1 <= port <= 65535:
        raise _error(f"[{section_name}].port must be between 1 and 65535")
    return host, port


def _validate_timeout(section: configparser.SectionProxy, name: str = "connect_timeout") -> int:
    timeout = _int_value(section, name, 10)
    if timeout <= 0:
        raise _error(f"configuration field {name!r} must be positive")
    return timeout


def _validate_file(path: Path) -> Path:
    try:
        info = path.stat()
    except OSError:
        raise _error("configuration file cannot be read") from None
    if not stat.S_ISREG(info.st_mode):
        raise _error("configuration file must be a regular file")
    if not os.access(path, os.R_OK):
        raise _error("configuration file is not readable")
    # Owner permissions are unrestricted.  Group read is permitted (0640),
    # while group write/execute and every other-user permission are rejected.
    if info.st_mode & 0o037:
        raise _error("configuration file has unsafe permissions")
    return path


def load_config(path: Path, overrides: CLIOverrides) -> AppConfig:
    """Read and validate a protected INI configuration file."""

    if not isinstance(path, Path):
        path = Path(path)
    path = _validate_file(path)
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with path.open("r", encoding="utf-8") as stream:
            parser.read_file(stream)
    except (OSError, UnicodeError, configparser.Error):
        raise _error("configuration file cannot be parsed") from None

    source_section = _section(parser, "source")
    proxy_section = _section(parser, "proxysql")
    sync_section = _section(parser, "sync")

    source_host, source_port = _validate_endpoint(source_section, "source")
    proxy_host, proxy_port = _validate_endpoint(proxy_section, "proxysql")
    source_function = source_section.get("function", "proxysql_auth.export_login_roles").strip()
    function_parts = source_function.split(".", 1)
    if len(function_parts) != 2 or not all(IDENTIFIER_RE.fullmatch(part) for part in function_parts):
        raise _error("[source].function must be a schema-qualified identifier pair")

    profile = _required(sync_section, "profile")
    if PROFILE_RE.fullmatch(profile) is None:
        raise _error("[sync].profile has invalid syntax")

    default_hostgroup = _int_value(sync_section, "default_hostgroup", 0)
    if default_hostgroup < 0:
        raise _error("[sync].default_hostgroup must be non-negative")
    missing_role_action = sync_section.get("missing_role_action", "disable").strip().lower()
    if missing_role_action not in {"disable", "keep"}:
        raise _error("[sync].missing_role_action must be disable or keep")
    adopt_existing_users = _boolean_value(sync_section, "adopt_existing_users", False)
    allow_empty_snapshot = _boolean_value(sync_section, "allow_empty_snapshot", False)
    save_to_disk = _boolean_value(sync_section, "save_to_disk", True)
    lock_file_value = sync_section.get("lock_file", str(SyncSettings.lock_file)).strip()
    if not lock_file_value:
        raise _error("[sync].lock_file must not be empty")
    lock_file = Path(lock_file_value)

    if overrides.default_hostgroup is not None:
        if not isinstance(overrides.default_hostgroup, int) or overrides.default_hostgroup < 0:
            raise _error("default_hostgroup override must be non-negative")
        default_hostgroup = overrides.default_hostgroup
    if overrides.missing_role_action is not None:
        missing_role_action = overrides.missing_role_action.strip().lower()
        if missing_role_action not in {"disable", "keep"}:
            raise _error("missing_role_action override must be disable or keep")
    if overrides.save_to_disk is not None:
        if not isinstance(overrides.save_to_disk, bool):
            raise _error("save_to_disk override must be boolean")
        save_to_disk = overrides.save_to_disk

    return AppConfig(
        source=SourceConfig(
            host=source_host,
            port=source_port,
            database=_required(source_section, "database"),
            username=_required(source_section, "username"),
            password=_required(source_section, "password"),
            connect_timeout=_validate_timeout(source_section),
            function_schema=function_parts[0],
            function_name=function_parts[1],
        ),
        proxysql=ProxySQLConfig(
            host=proxy_host,
            port=proxy_port,
            username=_required(proxy_section, "username"),
            password=_required(proxy_section, "password"),
            connect_timeout=_validate_timeout(proxy_section),
        ),
        sync=SyncSettings(
            profile=profile,
            default_hostgroup=default_hostgroup,
            missing_role_action=missing_role_action,
            adopt_existing_users=adopt_existing_users,
            allow_empty_snapshot=allow_empty_snapshot,
            save_to_disk=save_to_disk,
            lock_file=lock_file,
        ),
    )


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--default-hostgroup", type=int, default=None)
    parser.add_argument("--missing-role-action", choices=("disable", "keep"), default=None)
    save_group = parser.add_mutually_exclusive_group()
    save_group.add_argument("--save-to-disk", dest="save_to_disk", action="store_true")
    save_group.add_argument("--no-save-to-disk", dest="save_to_disk", action="store_false")
    parser.set_defaults(save_to_disk=None)
    parser.add_argument("--dry-run", action="store_true", default=False)
    parser.add_argument("--verbose", action="store_true", default=False)
    return parser.parse_args(argv)


def _decode_base64(value: str) -> bytes | None:
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError):
        return None
    # Reject alternate/non-canonical encodings in addition to non-alphabet
    # characters.  PostgreSQL emits standard padded base64 in SCRAM values.
    if base64.b64encode(decoded).decode("ascii") != value:
        return None
    return decoded


def validate_verifier(value: str) -> None:
    """Validate a PostgreSQL MD5 or SCRAM-SHA-256 verifier.

    Error messages intentionally describe only the class of failure and never
    include the credential verifier.
    """

    if not isinstance(value, str):
        raise _error("password verifier must be a string")
    if MD5_RE.fullmatch(value):
        return
    match = SCRAM_RE.fullmatch(value)
    if match is None:
        raise _error("invalid password verifier syntax")
    try:
        iterations = int(match.group("iterations"), 10)
    except ValueError:
        raise _error("invalid SCRAM iteration count") from None
    if not 1 <= iterations <= 2_147_483_647:
        raise _error("invalid SCRAM iteration count")
    salt = _decode_base64(match.group("salt"))
    stored = _decode_base64(match.group("stored"))
    server = _decode_base64(match.group("server"))
    if not salt:
        raise _error("invalid SCRAM salt")
    if stored is None or server is None or len(stored) != 32 or len(server) != 32:
        raise _error("invalid SCRAM key length")


def validate_snapshot(rows: Iterable[Sequence[object]], allow_empty: bool) -> dict[str, SourceRole]:
    """Validate a complete two-column role snapshot and return it sorted."""

    result: dict[str, SourceRole] = {}
    count = 0
    try:
        iterator = iter(rows)
    except TypeError:
        raise _error("snapshot must be iterable") from None
    for row in iterator:
        count += 1
        if isinstance(row, (str, bytes, bytearray)) or not isinstance(row, Sequence):
            raise _error("snapshot row must contain exactly two columns")
        if len(row) != 2:
            raise _error("snapshot row must contain exactly two columns")
        username, password = row
        if not isinstance(username, str) or not isinstance(password, str):
            raise _error("snapshot username and password must be strings")
        if not username:
            raise _error("snapshot username must not be empty")
        if "\x00" in username:
            raise _error("snapshot username must not contain NUL")
        try:
            username_bytes = username.encode("utf-8")
        except UnicodeEncodeError:
            raise _error("snapshot username must be valid UTF-8") from None
        if len(username_bytes) > 63:
            raise _error("snapshot username exceeds 63 UTF-8 bytes")
        if username in result:
            raise _error("snapshot contains duplicate username")
        validate_verifier(password)
        result[username] = SourceRole(username=username, password=password)
    if count == 0 and not allow_empty:
        raise _error("snapshot is empty")
    return dict(sorted(result.items()))


__all__ = [
    "AppConfig",
    "CLIOverrides",
    "PROFILE_RE",
    "IDENTIFIER_RE",
    "ProxySQLConfig",
    "SourceConfig",
    "SourceRole",
    "SyncError",
    "SyncSettings",
    "load_config",
    "parse_args",
    "validate_snapshot",
    "validate_verifier",
]
