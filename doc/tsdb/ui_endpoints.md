# TSDB UI / HTTP Endpoints

No dedicated TSDB REST endpoints are currently implemented in ProxySQL.

Current access path is SQL via admin connection, querying `statsdb_disk.tsdb_*` tables.
Any future TSDB HTTP API should be documented here once endpoint handlers are added.
