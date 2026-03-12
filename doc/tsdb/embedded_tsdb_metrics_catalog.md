# Embedded TSDB Metrics Catalog

The TSDB sampler records all metric families exposed by the built-in Prometheus registry.

## Family Coverage

- Counter
- Gauge
- Summary
- Histogram
- Info
- Untyped

## Stored Series Conventions

- Counter/Gauge/Untyped/Info: stored as metric name exactly as exposed.
- Summary:
  - quantiles in `<metric>` with `quantile` label
  - `<metric>_sum`
  - `<metric>_count`
- Histogram:
  - buckets in `<metric>_bucket` with `le` label
  - `<metric>_sum`
  - `<metric>_count`

Because the source registry can evolve, there is no fixed hardcoded metric list in TSDB code.
