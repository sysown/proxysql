#!/usr/bin/env python3
"""Validate configuration and PostgreSQL role-verifier snapshots.

The module deliberately has no third-party imports at module load time.  The
database adapters used by later stages import their drivers only when they are
called.
"""

import argparse
import base64
import configparser
import fcntl
import json
import os
import re
import stat
import sys
import time
from collections.abc import Iterable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Protocol


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
    lock_file: Path = Path("/var/lib/proxysql/proxysql-pgsql-user-sync.lock")


@dataclass(frozen=True)
class AppConfig:
    source: SourceConfig
    proxysql: ProxySQLConfig
    sync: SyncSettings


@dataclass(frozen=True)
class SourceRole:
    username: str
    password: str = field(repr=False)


@dataclass(frozen=True)
class ProxySQLUser:
    username: str
    password: str | None = field(repr=False)
    active: int
    use_ssl: int
    default_hostgroup: int
    transaction_persistent: int
    fast_forward: int
    backend: int
    frontend: int
    max_connections: int
    attributes: str
    comment: str


class ActionKind(Enum):
    CREATE = "create"
    UPDATE = "update"
    DISABLE = "disable"


@dataclass(frozen=True)
class SyncAction:
    kind: ActionKind
    before: ProxySQLUser | None
    after: ProxySQLUser


@dataclass(frozen=True)
class SyncPlan:
    actions: tuple[SyncAction, ...]
    requires_load: bool
    counts: Mapping[str, int]


PROFILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z_]\w*\Z", re.ASCII)
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


def _validate_file(info: os.stat_result) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise _error("configuration file must be a regular file")
    if info.st_uid not in (0, os.geteuid()):
        raise _error("configuration file has an unsafe owner")
    # Group read is a supported deployment mode only for a root-owned file
    # (typically 0640 with a dedicated service group).  Non-root-owned files
    # must be owner-only.  Group write/execute and every other-user permission
    # are rejected in all cases.
    group_permissions = info.st_mode & 0o070
    other_permissions = info.st_mode & 0o007
    if (
        other_permissions
        or group_permissions & 0o030
        or (group_permissions & 0o040 and info.st_uid != 0)
    ):
        raise _error("configuration file has unsafe permissions")


def _open_config_file(path: Path):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd: int | None = None
    try:
        fd = os.open(path, flags)
        _validate_file(os.fstat(fd))
        # os.fdopen() owns its descriptor even when stream construction fails.
        # Clear fd first so the error path cannot close a reused descriptor.
        stream_fd, fd = fd, None
        stream = os.fdopen(stream_fd, "r", encoding="utf-8")
    except SyncError:
        if fd is not None:
            os.close(fd)
        raise
    except OSError:
        if fd is not None:
            os.close(fd)
        raise _error("configuration file cannot be read") from None
    return stream


def _read_config(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with _open_config_file(path) as stream:
            parser.read_file(stream)
    except (OSError, UnicodeError, configparser.Error):
        raise _error("configuration file cannot be parsed") from None
    return parser


def _source_function_parts(section: configparser.SectionProxy) -> tuple[str, str]:
    source_function = section.get("function", "proxysql_auth.export_login_roles").strip()
    function_parts = source_function.split(".", 1)
    if len(function_parts) != 2 or not all(IDENTIFIER_RE.fullmatch(part) for part in function_parts):
        raise _error("[source].function must be a schema-qualified identifier pair")
    return function_parts[0], function_parts[1]


def _source_config(section: configparser.SectionProxy) -> SourceConfig:
    host, port = _validate_endpoint(section, "source")
    schema, function = _source_function_parts(section)
    return SourceConfig(
        host=host,
        port=port,
        database=_required(section, "database"),
        username=_required(section, "username"),
        password=_required(section, "password"),
        connect_timeout=_validate_timeout(section),
        function_schema=schema,
        function_name=function,
    )


def _proxysql_config(section: configparser.SectionProxy) -> ProxySQLConfig:
    host, port = _validate_endpoint(section, "proxysql")
    return ProxySQLConfig(
        host=host,
        port=port,
        username=_required(section, "username"),
        password=_required(section, "password"),
        connect_timeout=_validate_timeout(section),
    )


def _sync_overrides(
    default_hostgroup: int, missing_role_action: str, save_to_disk: bool, overrides: CLIOverrides
) -> tuple[int, str, bool]:
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
    return default_hostgroup, missing_role_action, save_to_disk


def _sync_settings(section: configparser.SectionProxy, overrides: CLIOverrides) -> SyncSettings:
    profile = _required(section, "profile")
    if PROFILE_RE.fullmatch(profile) is None:
        raise _error("[sync].profile has invalid syntax")
    default_hostgroup = _int_value(section, "default_hostgroup", 0)
    if default_hostgroup < 0:
        raise _error("[sync].default_hostgroup must be non-negative")
    missing_role_action = section.get("missing_role_action", "disable").strip().lower()
    if missing_role_action not in {"disable", "keep"}:
        raise _error("[sync].missing_role_action must be disable or keep")
    lock_file_value = section.get("lock_file", str(SyncSettings.lock_file)).strip()
    if not lock_file_value:
        raise _error("[sync].lock_file must not be empty")
    default_hostgroup, missing_role_action, save_to_disk = _sync_overrides(
        default_hostgroup,
        missing_role_action,
        _boolean_value(section, "save_to_disk", True),
        overrides,
    )
    return SyncSettings(
        profile=profile,
        default_hostgroup=default_hostgroup,
        missing_role_action=missing_role_action,
        adopt_existing_users=_boolean_value(section, "adopt_existing_users", False),
        allow_empty_snapshot=_boolean_value(section, "allow_empty_snapshot", False),
        save_to_disk=save_to_disk,
        lock_file=Path(lock_file_value),
    )


def load_config(path: Path, overrides: CLIOverrides) -> AppConfig:
    """Read and validate a protected INI configuration file."""

    if not isinstance(path, Path):
        path = Path(path)
    parser = _read_config(path)

    source_section = _section(parser, "source")
    proxy_section = _section(parser, "proxysql")
    sync_section = _section(parser, "sync")
    return AppConfig(
        source=_source_config(source_section),
        proxysql=_proxysql_config(proxy_section),
        sync=_sync_settings(sync_section, overrides),
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
    except ValueError:
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


def _snapshot_columns(row: object) -> tuple[str, str]:
    if isinstance(row, (str, bytes, bytearray)) or not isinstance(row, Sequence):
        raise _error("snapshot row must contain exactly two columns")
    if len(row) != 2:
        raise _error("snapshot row must contain exactly two columns")
    username, password = row
    if not isinstance(username, str) or not isinstance(password, str):
        raise _error("snapshot username and password must be strings")
    return username, password


def _validate_snapshot_username(username: str) -> None:
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


def _snapshot_role(row: object) -> SourceRole:
    username, password = _snapshot_columns(row)
    _validate_snapshot_username(username)
    validate_verifier(password)
    return SourceRole(username=username, password=password)


def validate_snapshot(rows: Iterable[Sequence[object]], allow_empty: bool) -> dict[str, SourceRole]:
    """Validate a complete two-column role snapshot and return it sorted."""

    result: dict[str, SourceRole] = {}
    try:
        iterator = iter(rows)
    except TypeError:
        raise _error("snapshot must be iterable") from None
    for row in iterator:
        role = _snapshot_role(row)
        if role.username in result:
            raise _error("snapshot contains duplicate username")
        result[role.username] = role
    if not result and not allow_empty:
        raise _error("snapshot is empty")
    return dict(sorted(result.items()))


_OWNERSHIP_KEY = "proxysql_pgsql_user_sync"


def _ownership_document(attributes: str) -> dict[str, object]:
    if not isinstance(attributes, str):
        raise _error("ProxySQL user attributes must be a JSON object")
    if attributes == "":
        return {}
    try:
        document = json.loads(attributes)
    except (TypeError, ValueError):
        raise _error("ProxySQL user attributes must be valid JSON") from None
    if not isinstance(document, dict):
        raise _error("ProxySQL user attributes must be a JSON object")
    return document


def decode_ownership(attributes: str) -> str | None:
    """Return the managed profile in attributes, rejecting malformed markers."""

    document = _ownership_document(attributes)
    if _OWNERSHIP_KEY not in document:
        return None
    marker = document[_OWNERSHIP_KEY]
    if not isinstance(marker, dict):
        raise _error("malformed PostgreSQL user ownership marker")
    profile = marker.get("profile")
    if not isinstance(profile, str) or PROFILE_RE.fullmatch(profile) is None:
        raise _error("malformed PostgreSQL user ownership marker")
    return profile


def with_ownership(attributes: str, profile: str) -> str:
    """Return attributes marked for profile using deterministic JSON."""

    if not isinstance(profile, str) or PROFILE_RE.fullmatch(profile) is None:
        raise _error("invalid ownership profile")
    document = _ownership_document(attributes)
    current = decode_ownership(attributes)
    if current is not None and current != profile:
        raise _error("user is owned by another profile")
    marker = document.get(_OWNERSHIP_KEY)
    if isinstance(marker, dict) and marker.get("profile") == profile:
        # Ownership is unchanged; preserve operator formatting and unrelated data.
        return attributes
    document[_OWNERSHIP_KEY] = {"profile": profile}
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def _user_index(rows: Iterable[ProxySQLUser], table: str) -> dict[str, ProxySQLUser]:
    result: dict[str, ProxySQLUser] = {}
    try:
        iterator = iter(rows)
    except TypeError:
        raise _error(f"{table} users must be iterable") from None
    for row in iterator:
        if not isinstance(row, ProxySQLUser):
            raise _error(f"{table} users contain an invalid row")
        # Validate ownership on both snapshots, even when a row is not managed.
        decode_ownership(row.attributes)
        if row.username in result:
            raise _error(f"{table} users contain multiple rows for {row.username!r}")
        result[row.username] = row
    return result


def _managed(row: ProxySQLUser, settings: SyncSettings) -> bool:
    return decode_ownership(row.attributes) == settings.profile


def _new_user(role: SourceRole, settings: SyncSettings) -> ProxySQLUser:
    return ProxySQLUser(
        username=role.username,
        password=role.password,
        active=1,
        use_ssl=0,
        default_hostgroup=settings.default_hostgroup,
        transaction_persistent=1,
        fast_forward=0,
        backend=1,
        frontend=1,
        max_connections=10000,
        attributes=with_ownership("", settings.profile),
        comment="",
    )


def _runtime_matches(main_row: ProxySQLUser, runtime_row: ProxySQLUser | None) -> bool:
    """Compare the backend half of main and runtime user rows."""

    if runtime_row is None:
        return False
    # ProxySQL materializes a combined main user as separate backend and
    # frontend runtime rows. The backend half always has frontend=0.
    return replace(main_row, frontend=0) == replace(runtime_row, frontend=0)


_UNMANAGED_RUNTIME_DRIFT = "unmanaged main/runtime drift"


def _source_names(source: Mapping[str, SourceRole]) -> set[str]:
    if not isinstance(source, Mapping):
        raise _error("source snapshot must be a username mapping")
    names = set(source)
    for username, role in source.items():
        if not isinstance(username, str) or not isinstance(role, SourceRole):
            raise _error("source snapshot contains an invalid role")
        if role.username != username:
            raise _error("source snapshot username does not match role")
    return names


def _main_runtime_drift(main_row: ProxySQLUser, runtime_row: ProxySQLUser | None) -> bool:
    return not _runtime_matches(main_row, runtime_row) if main_row.active else runtime_row is not None


def _managed_runtime_drift(
    main_by_name: Mapping[str, ProxySQLUser],
    runtime_by_name: Mapping[str, ProxySQLUser],
    settings: SyncSettings,
) -> bool:
    managed_drift = False
    for username, main_row in main_by_name.items():
        if not _main_runtime_drift(main_row, runtime_by_name.get(username)):
            continue
        if not _managed(main_row, settings):
            raise _error(_UNMANAGED_RUNTIME_DRIFT)
        managed_drift = True
    for username, runtime_row in runtime_by_name.items():
        if username in main_by_name:
            continue
        if _managed(runtime_row, settings):
            managed_drift = True
        elif runtime_row.active:
            raise _error(_UNMANAGED_RUNTIME_DRIFT)
    return managed_drift


def _plan_counts(source: Mapping[str, SourceRole]) -> dict[str, int]:
    return {
        "discovered": len(source),
        "created": 0,
        "updated": 0,
        "reactivated": 0,
        "disabled": 0,
        "unchanged": 0,
        "conflicted": 0,
    }


def _source_actions(
    source: Mapping[str, SourceRole],
    main_by_name: Mapping[str, ProxySQLUser],
    settings: SyncSettings,
    counts: dict[str, int],
) -> list[SyncAction]:
    actions: list[SyncAction] = []
    for username in sorted(source):
        role = source[username]
        existing = main_by_name.get(username)
        if existing is None:
            actions.append(SyncAction(ActionKind.CREATE, None, _new_user(role, settings)))
            counts["created"] += 1
            continue
        owner = decode_ownership(existing.attributes)
        if owner is not None and owner != settings.profile:
            counts["conflicted"] += 1
            raise _error("user is owned by another profile")
        if owner is None and not settings.adopt_existing_users:
            counts["conflicted"] += 1
            raise _error("unmanaged user conflicts with source role")
        after = replace(
            existing,
            password=role.password,
            active=1,
            attributes=with_ownership(existing.attributes, settings.profile),
        )
        if after == existing:
            counts["unchanged"] += 1
            continue
        actions.append(SyncAction(ActionKind.UPDATE, existing, after))
        counts["updated"] += 1
        if not existing.active:
            counts["reactivated"] += 1
    return actions


def _missing_role_actions(
    source_names: set[str],
    main_by_name: Mapping[str, ProxySQLUser],
    settings: SyncSettings,
    counts: dict[str, int],
) -> list[SyncAction]:
    if settings.missing_role_action == "keep":
        return []
    if settings.missing_role_action != "disable":
        raise _error("missing_role_action must be disable or keep")
    actions = []
    for username in sorted(set(main_by_name) - source_names):
        existing = main_by_name[username]
        if _managed(existing, settings) and existing.active:
            actions.append(SyncAction(ActionKind.DISABLE, existing, replace(existing, active=0)))
            counts["disabled"] += 1
    return actions


def build_plan(
    source: Mapping[str, SourceRole],
    main: Iterable[ProxySQLUser],
    runtime: Iterable[ProxySQLUser],
    settings: SyncSettings,
) -> SyncPlan:
    """Build a deterministic, side-effect-free reconciliation plan."""

    source_names = _source_names(source)
    main_by_name = _user_index(main, "main")
    runtime_by_name = _user_index(runtime, "runtime")
    managed_runtime_drift = _managed_runtime_drift(main_by_name, runtime_by_name, settings)
    counts = _plan_counts(source)
    actions = _source_actions(source, main_by_name, settings, counts)
    actions.extend(_missing_role_actions(source_names, main_by_name, settings, counts))
    actions.sort(key=lambda action: action.after.username)
    return SyncPlan(
        actions=tuple(actions),
        requires_load=bool(actions) or managed_runtime_drift,
        counts=MappingProxyType(counts),
    )


class SourceAdapter(Protocol):
    def fetch_snapshot(self) -> list[tuple[str, str]]: ...


class AdminAdapter(Protocol):
    def fetch_main_users(self) -> list[ProxySQLUser]: ...

    def fetch_runtime_users(self) -> list[ProxySQLUser]: ...

    def apply_actions(self, actions: Sequence[SyncAction]) -> None: ...

    def load_runtime(self) -> None: ...

    def save_to_disk(self) -> None: ...


@dataclass(frozen=True)
class RunSummary:
    outcome: str
    counts: Mapping[str, int]
    loaded: bool
    saved: bool
    duration_seconds: float


def _close_connection(connection: object) -> None:
    try:
        connection.close()
    except Exception:
        pass


class PostgreSQLSource:
    """Fetch the authoritative PostgreSQL role verifier snapshot."""

    def __init__(
        self,
        config: AppConfig,
        *,
        connect: Callable[..., object] | None = None,
        sql_module: object | None = None,
    ) -> None:
        self.config = config
        self._connect = connect
        self._sql_module = sql_module

    def _driver(self) -> tuple[Callable[..., object], object]:
        if self._connect is not None and self._sql_module is not None:
            return self._connect, self._sql_module
        try:
            import psycopg
            from psycopg import sql
        except ImportError:
            raise _error("PostgreSQL driver is not installed") from None
        return self._connect or psycopg.connect, self._sql_module or sql

    def fetch_snapshot(self) -> list[tuple[str, str]]:
        try:
            connect, sql = self._driver()
            source = self.config.source
            connection = connect(
                host=source.host,
                port=source.port,
                dbname=source.database,
                user=source.username,
                password=source.password,
                connect_timeout=source.connect_timeout,
            )
            try:
                cursor = connection.cursor()
                query = sql.SQL("SELECT username::text, password FROM {}.{}()").format(
                    sql.Identifier(source.function_schema), sql.Identifier(source.function_name)
                )
                cursor.execute(query)
                return list(cursor.fetchall())
            finally:
                _close_connection(connection)
        except SyncError:
            raise
        except Exception:
            raise _error("unable to fetch PostgreSQL role snapshot") from None


_USER_COLUMNS = (
    "username,password,active,use_ssl,default_hostgroup,transaction_persistent,"
    "fast_forward,backend,frontend,max_connections,attributes,comment"
)
_USER_FIELDS = (
    "username", "password", "active", "use_ssl", "default_hostgroup", "transaction_persistent",
    "fast_forward", "backend", "frontend", "max_connections", "attributes", "comment",
)
_USER_INTEGER_FIELD_INDEXES = (2, 3, 4, 5, 6, 7, 8, 9)


class ProxySQLAdmin:
    """Execute the small, explicit ProxySQL admin command set used by sync."""

    def __init__(self, config: AppConfig, *, connect: Callable[..., object] | None = None) -> None:
        self.config = config
        self._connect = connect

    def _connection(self) -> object:
        connect = self._connect
        connect_options: dict[str, object] = {}
        if connect is None:
            try:
                import psycopg
                from psycopg import ClientCursor
            except ImportError:
                raise _error("ProxySQL admin driver is not installed") from None
            connect = psycopg.connect
            # ProxySQL's PostgreSQL Admin interface supports the simple query
            # protocol. ClientCursor still quotes parameters safely, but does
            # the interpolation client-side before sending the statement.
            connect_options["cursor_factory"] = ClientCursor
        proxy = self.config.proxysql
        try:
            return connect(
                host=proxy.host,
                port=proxy.port,
                user=proxy.username,
                password=proxy.password,
                dbname="main",
                connect_timeout=proxy.connect_timeout,
                autocommit=True,
                **connect_options,
            )
        except Exception:
            raise _error("unable to connect to ProxySQL admin interface") from None

    @staticmethod
    def _user_values(user: ProxySQLUser) -> tuple[object, ...]:
        return tuple(getattr(user, field) for field in _USER_FIELDS)

    def _fetch_users(self, table: str) -> list[ProxySQLUser]:
        connection = self._connection()
        try:
            cursor = connection.cursor()
            # ProxySQL splits a combined backend/frontend user into two rows in
            # runtime. Reconcile the backend half, which is also the row keyed
            # by apply_actions(), so one username has one deterministic record.
            cursor.execute(f"SELECT {_USER_COLUMNS} FROM {table} WHERE backend=1")
            users = []
            for row in cursor.fetchall():
                values = list(row)
                # The PostgreSQL Admin interface sends these SQLite integer
                # columns as text. Normalizing them prevents false updates on
                # every scheduler invocation.
                for index in _USER_INTEGER_FIELD_INDEXES:
                    values[index] = int(values[index])
                users.append(ProxySQLUser(*values))
            return users
        except Exception:
            raise _error("unable to fetch ProxySQL users") from None
        finally:
            _close_connection(connection)

    def fetch_main_users(self) -> list[ProxySQLUser]:
        return self._fetch_users("pgsql_users")

    def fetch_runtime_users(self) -> list[ProxySQLUser]:
        return self._fetch_users("runtime_pgsql_users")

    def apply_actions(self, actions: Sequence[SyncAction]) -> None:
        connection = self._connection()
        try:
            cursor = connection.cursor()
            for action in actions:
                user = action.after
                if action.kind is ActionKind.CREATE:
                    placeholders = ",".join(["%s"] * len(_USER_FIELDS))
                    cursor.execute(
                        f"INSERT INTO pgsql_users ({_USER_COLUMNS}) VALUES ({placeholders})",
                        self._user_values(user),
                    )
                elif action.kind is ActionKind.UPDATE:
                    assignments = ",".join(f"{field}=%s" for field in _USER_FIELDS[1:])
                    cursor.execute(
                        f"UPDATE pgsql_users SET {assignments} WHERE username=%s AND backend=%s",
                        self._user_values(user)[1:] + (user.username, user.backend),
                    )
                elif action.kind is ActionKind.DISABLE:
                    cursor.execute(
                        "UPDATE pgsql_users SET active=%s WHERE username=%s AND backend=%s",
                        (user.active, user.username, user.backend),
                    )
                else:
                    raise _error("sync plan contains an unknown action")
        except SyncError:
            raise
        except Exception:
            raise _error("unable to apply ProxySQL user changes") from None
        finally:
            _close_connection(connection)

    def _execute_command(self, command: str, failure_message: str) -> None:
        connection = self._connection()
        try:
            connection.cursor().execute(command)
        except Exception:
            raise _error(failure_message) from None
        finally:
            _close_connection(connection)

    def load_runtime(self) -> None:
        self._execute_command("LOAD PGSQL USERS TO RUNTIME", "unable to load ProxySQL users to runtime")

    def save_to_disk(self) -> None:
        self._execute_command("SAVE PGSQL USERS TO DISK", "unable to save ProxySQL users to disk")


def _source_snapshot(source: SourceAdapter, allow_empty: bool) -> dict[str, SourceRole]:
    try:
        raw_snapshot = source.fetch_snapshot()
    except Exception:
        raise _error("unable to fetch source role snapshot") from None
    return validate_snapshot(raw_snapshot, allow_empty)


def _admin_snapshots(admin: AdminAdapter) -> tuple[list[ProxySQLUser], list[ProxySQLUser]]:
    try:
        return admin.fetch_main_users(), admin.fetch_runtime_users()
    except Exception:
        raise _error("unable to fetch ProxySQL user snapshots") from None


def _apply_plan(plan: SyncPlan, admin: AdminAdapter, settings: SyncSettings) -> tuple[bool, bool, bool]:
    if plan.actions:
        try:
            admin.apply_actions(plan.actions)
        except Exception:
            raise _error("unable to apply ProxySQL user changes") from None
    if not plan.requires_load:
        return False, False, False
    try:
        admin.load_runtime()
    except Exception:
        raise _error("unable to load ProxySQL users to runtime") from None
    if not settings.save_to_disk:
        return True, False, False
    try:
        admin.save_to_disk()
    except Exception:
        return True, False, True
    return True, True, False


def _sync_outcome(dry_run: bool, partial: bool) -> str:
    if dry_run:
        return "dry-run"
    if partial:
        return "partial"
    return "success"


def run_sync(
    config: AppConfig,
    source: SourceAdapter,
    admin: AdminAdapter,
    *,
    dry_run: bool,
    verbose: bool,
) -> RunSummary:
    """Read, plan, and optionally reconcile one complete role snapshot."""

    started = time.monotonic()
    snapshot = _source_snapshot(source, config.sync.allow_empty_snapshot)
    main_users, runtime_users = _admin_snapshots(admin)
    plan = build_plan(snapshot, main_users, runtime_users, config.sync)
    if verbose:
        for action in plan.actions:
            print(f"plan: {action.kind.value} username={action.after.username}")

    loaded = False
    saved = False
    partial = False
    if not dry_run:
        loaded, saved, partial = _apply_plan(plan, admin, config.sync)
    return RunSummary(
        outcome=_sync_outcome(dry_run, partial),
        counts=MappingProxyType(dict(plan.counts)),
        loaded=loaded,
        saved=saved,
        duration_seconds=time.monotonic() - started,
    )


@contextmanager
def exclusive_lock(path: Path):
    """Yield whether the process acquired the non-blocking synchronizer lock."""

    try:
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    except OSError:
        raise _error("unable to open synchronizer lock file") from None
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _summary_line(summary: RunSummary) -> str:
    counts = " ".join(f"{name}={value}" for name, value in sorted(summary.counts.items()))
    return (
        f"sync {summary.outcome}: {counts} loaded={str(summary.loaded).lower()} "
        f"saved={str(summary.saved).lower()} duration={summary.duration_seconds:.3f}s"
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line synchronizer without importing database drivers for --help."""

    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        config = load_config(args.config, CLIOverrides(
            default_hostgroup=args.default_hostgroup,
            missing_role_action=args.missing_role_action,
            save_to_disk=args.save_to_disk,
        ))
        with exclusive_lock(config.sync.lock_file) as acquired:
            if not acquired:
                print("sync already running; exiting")
                return 0
            summary = run_sync(
                config,
                PostgreSQLSource(config),
                ProxySQLAdmin(config),
                dry_run=args.dry_run,
                verbose=args.verbose,
            )
        print(_summary_line(summary))
        return 1 if summary.outcome == "partial" else 0
    except SyncError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


__all__ = [
    "AppConfig",
    "CLIOverrides",
    "PROFILE_RE",
    "IDENTIFIER_RE",
    "ProxySQLConfig",
    "ProxySQLUser",
    "SourceConfig",
    "SourceRole",
    "SyncError",
    "SyncAction",
    "SyncPlan",
    "SyncSettings",
    "ActionKind",
    "AdminAdapter",
    "PostgreSQLSource",
    "ProxySQLAdmin",
    "RunSummary",
    "SourceAdapter",
    "build_plan",
    "decode_ownership",
    "load_config",
    "parse_args",
    "run_sync",
    "exclusive_lock",
    "main",
    "with_ownership",
    "validate_snapshot",
    "validate_verifier",
]


if __name__ == "__main__":
    raise SystemExit(main())
