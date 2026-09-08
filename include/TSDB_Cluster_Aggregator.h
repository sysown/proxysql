#ifndef __CLASS_TSDB_CLUSTER_AGGREGATOR_H
#define __CLASS_TSDB_CLUSTER_AGGREGATOR_H

// Pure planning logic for TSDB cluster aggregation (leader pulls peers'
// tsdb_metrics with a per-node watermark). Kept dependency-free so it is
// unit-testable in every tier.

struct Tsdb_Agg_Fetch_Result {
	long new_watermark = 0;
	bool caught_up = false;
};

// Start-point for replicating a node: the max timestamp already replicated,
// clamped forward to the backfill horizon (now - backfill_hours).
// existing_max_ts <= 0 means "nothing replicated yet".
long tsdb_agg_effective_watermark(long existing_max_ts, long now, int backfill_hours);

// Bookkeeping after one fetch of up to `limit` rows ordered by timestamp,
// where `last_row_ts` is the max timestamp among the fetched rows
// (ignored when rows_fetched == 0).
Tsdb_Agg_Fetch_Result tsdb_agg_apply_fetch(long prev_watermark, int rows_fetched, long last_row_ts, int limit);

#endif // __CLASS_TSDB_CLUSTER_AGGREGATOR_H
