#include "duckdb_result.h"
#include "sqlite3db.h"

#include <vector>

SQLite3_result* duckdb_result_to_sqlite3(duckdb_result* res) {
	if (res == nullptr) return nullptr;

	const idx_t ncols = duckdb_column_count(res);
	if (ncols == 0) return nullptr;

	SQLite3_result* out = new SQLite3_result(static_cast<int>(ncols));
	for (idx_t c = 0; c < ncols; c++) {
		const char* name = duckdb_column_name(res, c);
		out->add_column_definition(SQLITE_TEXT, name != nullptr ? name : "");
	}

	const idx_t nrows = duckdb_row_count(res);
	std::vector<char*> fields(static_cast<size_t>(ncols), nullptr);

	for (idx_t r = 0; r < nrows; r++) {
		for (idx_t c = 0; c < ncols; c++) {
			// duckdb_value_varchar returns nullptr both for SQL NULL and
			// for any column type its deprecated cast switch doesn't
			// special-case (nested/composite types among others -- see
			// the header's doc comment) -- exactly the representation
			// SQLite3_row::add_fields wants for a null field either way.
			fields[c] = duckdb_value_is_null(res, c, r)
				? nullptr
				: duckdb_value_varchar(res, c, r);
		}
		out->add_row(fields.data());
		for (idx_t c = 0; c < ncols; c++) {
			if (fields[c] != nullptr) { duckdb_free(fields[c]); fields[c] = nullptr; }
		}
	}
	return out;
}

// Container/composite ("nested") duckdb_type enumerators, per DuckDB
// 1.4.5's duckdb.h. Verified exhaustively against every enumerator DuckDB
// 1.4.5 defines (duckdb.h:62-140, DUCKDB_TYPE_INVALID through
// DUCKDB_TYPE_TIME_NS): these five are the only ones DuckDB's own type
// system classifies as nested/composite (a value built out of other
// values) rather than scalar. duckdb_value_varchar() cannot render any of
// them -- confirmed both by reading GetInternalCValue's switch (duckdb/src
// /include/duckdb/main/capi/cast/generic.hpp), which has no case for any
// of the five and falls through to its NULL-producing default, and by
// compiling a standalone probe against the built duckdb_static archives
// and observing SELECT [1,2,3], SELECT {'a':1}, and SELECT MAP{'k':1} all
// return a nullptr value.
static bool duckdb_type_is_nested(duckdb_type t) {
	switch (t) {
		case DUCKDB_TYPE_LIST:
		case DUCKDB_TYPE_STRUCT:
		case DUCKDB_TYPE_MAP:
		case DUCKDB_TYPE_ARRAY:
		case DUCKDB_TYPE_UNION:
			return true;
		default:
			return false;
	}
}

bool duckdb_result_has_nested_column(duckdb_result* res) {
	if (res == nullptr) return false;

	const idx_t ncols = duckdb_column_count(res);
	for (idx_t c = 0; c < ncols; c++) {
		if (duckdb_type_is_nested(duckdb_column_type(res, c))) {
			return true;
		}
	}
	return false;
}
