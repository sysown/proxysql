# MariaDB GTID Causal Reads Design

## Goal

Causal reads today assume MySQL `uuid:seq` end-to-end. MariaDB GTIDs use
`domain_id-server_id-sequence`. This change adds MariaDB support across the
binlog reader and ProxySQL without a new wire protocol or a flavor flag.

A replica is ready for MariaDB GTID `0-1-100` when domain `0` has sequence
`>= 100`, even if it reports `0-2-105`.

## Scope

In scope:

- Auto-detect MySQL vs MariaDB GTID strings.
- Reuse `GTID_Set` with MariaDB key = decimal `domain_id`, value = sequence.
- Reuse wire messages `ST=` / `I1=` / `I2=` / `I3=` / `I4=` with domain as the
  id field (`I1=0:271`).
- Binlog reader snapshot and `GTID_EVENT` streaming for MariaDB.
- ProxySQL `min_gtid`, `gtid_from_hostgroup`, `add_gtid_from_ok`, and
  `stats_mysql_gtid_executed` for MariaDB format.

Out of scope:

- New wire message types or a protocol version bump.
- Per-server or global `gtid_flavor` configuration.
- Matching on `domain_id-server_id` (server_id is display-only).
- Mixed MySQL UUID keys and MariaDB domain keys on one backend endpoint.
- Adding a MariaDB-binlog TAP infra to ProxySQL (existing binlog groups are
  MySQL). ProxySQL proves routing with unit tests and MariaDB session TAP.

The two repositories stay independent. Parser behavior is specified here and
implemented in both trees (no shared submodule).

## Formats

MySQL (unchanged):

- Single: `aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:23` (dashes optional in the
  UUID).
- Set: comma-separated UUID groups, each with one or more `:` intervals.

MariaDB:

- Single: `domain-server-sequence` with three unsigned decimal fields and no
  `:`. Example: `0-1-270`.
- Set: comma-separated singles, one GTID per domain, as in
  `@@gtid_binlog_pos` / `@@gtid_current_pos`. Example: `0-1-270,1-2-50`.
- No interval syntax. Sequence `0` is invalid.

Detection is per token, not per process:

- Contains `:` → MySQL parser (must be UUID + intervals).
- Otherwise matches `digits-digits-digits` → MariaDB parser.
- Anything else is invalid.

The two forms do not overlap.

## Internal model

`GTID_Set` stays `map<id, list<TrxId_Interval>>`.

- MySQL `id`: 32-char lowercase hex UUID, dashes stripped.
- MariaDB `id`: decimal `domain_id` with no leading zeros except `0` itself.
  Leading zeros (`00-1-1`) are invalid so `0` and `00` cannot become two keys.

MariaDB sequence numbers in a domain are a watermark. Snapshot and OK-packet
positions therefore insert interval `[1, seq]`, not a single point. Incremental
binlog events insert the single sequence, which appends onto `[1, N]`.
`has_gtid(domain, seq)` then works with the existing interval membership check:
after snapshot `0-1-270`, `has_gtid("0", 100)` is true.

`GTID_Set` stores last-seen `server_id` per MariaDB domain for display only.
Matching never uses `server_id`. Missing `server_id` serializes as `0`.

`to_string()`:

- 32-hex key → existing MySQL UUID form with dashes and `:` intervals.
- Decimal domain key → one `domain-server-end` per domain, using the highest
  interval end and last-seen `server_id`. This matches MariaDB
  `gtid_current_pos` (a point, not a range).

## Wire protocol

Unchanged text lines. For MariaDB the id field is the domain, never
`domain-server`, so ProxySQL must not strip dashes from non-UUID ids.

Bootstrap from `0-1-270,1-2-50`:

```
ST=0:1-270,1:1-50
```

Later events:

```
I1=0:271
I2=272
```

`ST=` / `I1=` / `I3=` parsers must treat a decimal id as a domain. Current
`ST=` dash-stripping (`0-1` → `01`) is MySQL-only and must not run on domain
ids.

## Binlog reader (`proxysql_mysqlbinlog`)

Snapshot:

1. `SHOW BINARY LOG STATUS` or `SHOW MASTER STATUS` for File and Position
   (two columns are enough; do not require MySQL's fifth column).
2. If a fifth column is present and non-empty, it must parse as a MySQL GTID
   set or snapshot fails. Do not fall through to MariaDB on a malformed MySQL
   executed set.
3. If the fifth column is missing or empty, `SELECT @@GLOBAL.gtid_binlog_pos`
   and parse as MariaDB. Empty or invalid fails startup.

Stream:

- Keep handling MySQL `GTID_LOG_EVENT` (UUID + sequence).
- Also handle MariaDB `GTID_EVENT`: `domain_id` and `sequence_nr` from the
  event body, `server_id` from the event header. Callback remains
  `(id, trxid)` with `id = decimal domain`.

Emit the existing `ST=` / `I*` lines using domain as id.

## ProxySQL

Shared parse helper used by:

- `MySQL_Query_Processor::_is_valid_gtid` (accept MariaDB form).
- `MySQL_Session` connection checkout (today splits on `:` and strips UUID
  dashes). Replace with the helper; MariaDB yields `id="0"`, `trxid=100` for
  `0-1-100`.
- `GTID_Server_Data::add_gtid_from_ok`: MariaDB path inserts `[1, seq]` under
  the domain key and records `server_id`.
- `GTID_Server_Data::read_next_gtid`: decimal ids are domains.

Write-path GTID collection:

- Keep `SESSION_TRACK_GTIDS` for MySQL.
- On MariaDB backends (version comment contains `MariaDB`), also ensure
  `gtid_binlog_pos` is in `session_track_system_variables`.
- `MySQL_Connection::get_gtid()` tries `SESSION_TRACK_GTIDS` first, then
  `SESSION_TRACK_SYSTEM_VARIABLES` for `gtid_binlog_pos` / `gtid_current_pos`.
- Store the native string on the backend (`0-1-100` or `uuid:seq`). If tracking
  is off, the string stays empty and `gtid_from_hostgroup` skips GTID routing
  (same as today).

`min_gtid` annotations accept either native form:
`/*+ ;min_gtid=0-1-100 */`.

## Error handling

- Malformed GTID: reject. `min_gtid` warns and ignores; `add_gtid_from_ok`
  returns false; reader snapshot fails closed.
- Mixed UUID and domain tokens on one endpoint or in one `ST=` line: invalid
  message; reader disconnects as today.
- MariaDB snapshot with neither a MySQL executed set nor `@@gtid_binlog_pos`:
  reader refuses to start.
- Non-GTID binlog events stay ignored.
- Invalid `ST=` / `I*` still sets `active = false` and disconnects.

## Testing

ProxySQL (this repo):

- Unit: parser (MySQL UUID±dashes, MariaDB singles and sets, whitespace,
  rejects).
- Unit: `GTID_Set::to_string` and `has_gtid` for domain keys; watermark
  `[1, seq]`; `0-2-105` satisfies `0-1-100`.
- Unit: `add_gtid_from_ok` MariaDB; `GTID_Server_Data` `ST=`/`I1=` with `0:100`
  (no dash-stripping).
- Unit: `_is_valid_gtid` accepts `0-1-100` and still rejects junk.
- Existing MySQL causal-read TAP stays green.
- TAP on `mariadb10-galera` for native `min_gtid` and OK-packet ingestion when
  session tracking exposes `gtid_binlog_pos`. No new MariaDB-binlog TAP group.

Binlog reader (sibling repo):

- Unit: `parse` of `@@gtid_binlog_pos`, snapshot fallback, `GTID_EVENT` mapping.
- Live TAP against a MariaDB 10.11 service added to reader test infra:
  snapshot + stream + `ST=`/`I1=` output. Existing MySQL version matrix stays.

## Verification

- ProxySQL: debug build, GTID unit binaries, `mariadb10-galera` TAP for the
  new session/`min_gtid` case, existing MySQL GTID TAP unchanged.
- Reader: TAP build, parser unit binary, MariaDB live TAP, existing MySQL TAP
  unchanged.
