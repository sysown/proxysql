# Embedded TSDB Quickstart

## Enabling the TSDB
To enable the embedded TSDB, set the following admin variable:
```sql
SET tsdb.enabled = 'true';
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;
```

## Accessing the Dashboard
Once enabled, the dashboard is accessible via the ProxySQL Admin HTTP interface (default port 6080):
`http://<proxysql-host>:6080/ui/`

## Configuration
- `tsdb.retention_hours`: How long to keep data (default 24).
- `tsdb.sample_interval_seconds`: Frequency of metric sampling (default 5).
- `tsdb.max_disk_mb`: Maximum disk space to use for TSDB files (default 2048).

## Troubleshooting
Check the TSDB status via Admin:
```sql
TSDB STATUS;
```
If you see high "drops" or "errors", ensure ProxySQL has write permissions to its data directory and that `tsdb.max_series` has not been exceeded.
