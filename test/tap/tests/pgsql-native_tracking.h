/**
 * @file pgsql-native_tracking.h
 * @brief Per-operation coverage recorder for native-vs-libpq differential tests.
 *
 * USAGE
 * -----
 *   CoverageRecorder cov;
 *   cov.record(OpRecord{"BEGIN; INSERT; COMMIT", "TXN_CYCLE", true,
 *                      true, ""});
 *   // ... more records ...
 *   cov.emit_tap();
 *
 * The summary line groups by `kind` and reports the native coverage rate per
 * kind, e.g.: "TXN_BEGIN: 6/6 native, COPY_IN: 0/2 native (2 fell back)".
 */
#ifndef PGSQL_NATIVE_TRACKING_H
#define PGSQL_NATIVE_TRACKING_H

#include <string>
#include <vector>
#include <map>
#include <sstream>
#include "tap.h"

struct OpRecord {
	std::string label;
	std::string kind;        // e.g. "TXN_BEGIN", "COPY_IN", "EXT_PARSE", "PREPARE_SQL"
	bool result_match;       // byte-equal between libpq control and native candidate
	bool native_path_used;   // true iff no fallback warning in the proxy log
	std::string detail;      // optional diagnostic (e.g. SQLSTATE diff)
};

class CoverageRecorder {
public:
	void record(const OpRecord& r) { records.push_back(r); }

	// Emits one ok/not-ok per record (asserting result_match) and one final
	// summary ok with the per-kind native coverage rate.
	void emit_tap() const {
		for (size_t i = 0; i < records.size(); i++) {
			const auto& r = records[i];
			ok(r.result_match, "%s (native=%s%s)",
			   r.label.c_str(),
			   r.native_path_used ? "yes" : "no",
			   r.detail.empty() ? "" : (std::string("; ") + r.detail).c_str());
		}

		// Summary: per-kind native coverage.
		std::map<std::string, std::pair<int, int>> per_kind;  // kind -> (native, total)
		for (const auto& r : records) {
			auto& p = per_kind[r.kind];
			p.second++;
			if (r.native_path_used) p.first++;
		}
		std::stringstream ss;
		ss << "coverage: ";
		bool first = true;
		for (const auto& kv : per_kind) {
			const std::string& kind = kv.first;
			const auto& p = kv.second;
			if (!first) ss << ", ";
			first = false;
			if (p.first == p.second) {
				ss << kind << " " << p.first << "/" << p.second << " native";
			} else {
				ss << kind << " " << p.first << "/" << p.second << " native ("
				   << (p.second - p.first) << " fell back)";
			}
		}
		// The summary is informational - it always passes (the per-record
		// ok/not-ok lines already cover the strict assertions).
		ok(true, "%s", ss.str().c_str());
	}

	size_t size() const { return records.size(); }

private:
	std::vector<OpRecord> records;
};

#endif // PGSQL_NATIVE_TRACKING_H
