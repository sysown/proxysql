/**
 * @file tsdb_cluster_aggregator_unit-t.cpp
 * @brief Unit tests for the pure TSDB cluster aggregation planner
 *  (effective watermark + fetch-result bookkeeping).
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "TSDB_Cluster_Aggregator.h"

int main() {
	plan(11);

	const long now = 1000000000L;

	// --- tsdb_agg_effective_watermark (5 oks) ---
	ok(tsdb_agg_effective_watermark(0, now, 24) == now - 24*3600,
		"no existing data: watermark = now - backfill horizon");
	ok(tsdb_agg_effective_watermark(-1, now, 24) == now - 24*3600,
		"negative existing max treated as none");
	ok(tsdb_agg_effective_watermark(now - 100, now, 24) == now - 100,
		"recent existing max wins over horizon");
	ok(tsdb_agg_effective_watermark(now - 200000, now, 24) == now - 24*3600,
		"stale existing max (deposed leader) clamped forward to horizon");
	ok(tsdb_agg_effective_watermark(now - 100, now, 0) == now,
		"zero backfill hours: horizon is now (no history pulled)");

	// --- tsdb_agg_apply_fetch (6 oks) ---
	Tsdb_Agg_Fetch_Result r = tsdb_agg_apply_fetch(500, 0, 0, 1000);
	ok(r.new_watermark == 500 && r.caught_up == true,
		"empty fetch: watermark unchanged, caught up");

	r = tsdb_agg_apply_fetch(500, 999, 750, 1000);
	ok(r.new_watermark == 750, "partial fetch advances watermark to last row ts");
	ok(r.caught_up == true, "partial fetch (rows < limit) means caught up");

	r = tsdb_agg_apply_fetch(500, 1000, 800, 1000);
	ok(r.new_watermark == 800, "full fetch advances watermark to last row ts");
	ok(r.caught_up == false, "full fetch (rows == limit) means more to pull");

	r = tsdb_agg_apply_fetch(500, 1, 501, 1000);
	ok(r.new_watermark == 501 && r.caught_up == true,
		"single-row fetch advances and completes");

	return exit_status();
}
