#include "TSDB_Cluster_Aggregator.h"

long tsdb_agg_effective_watermark(long existing_max_ts, long now, int backfill_hours) {
	long horizon = now - (long)backfill_hours * 3600L;
	if (existing_max_ts > horizon) {
		return existing_max_ts;
	}
	return horizon;
}

Tsdb_Agg_Fetch_Result tsdb_agg_apply_fetch(long prev_watermark, int rows_fetched, long last_row_ts, int limit) {
	Tsdb_Agg_Fetch_Result r;
	if (rows_fetched == 0) {
		r.new_watermark = prev_watermark;
		r.caught_up = true;
		return r;
	}
	r.new_watermark = last_row_ts;
	r.caught_up = (rows_fetched < limit);
	return r;
}
