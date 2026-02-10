#ifdef PROXYSQLGENAI

#include "sqlite3db.h"
#include "cpp.h"

#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

json MCP_Tool_Handler::resultset_to_json(SQLite3_result* resultset, int cols) {
	json rows = json::array();

	if (!resultset || resultset->rows_count == 0) {
		return rows;
	}

	for (const auto& row : resultset->rows) {
		json obj = json::object();
		for (int i = 0; i < cols && i < (int)resultset->column_definition.size(); i++) {
			const char* col_name = resultset->column_definition[i]->name;
			const char* val = row->fields[i];

			if (!val) {
				obj[col_name] = nullptr;
				continue;
			}

			// Try to parse the value as a number.
			// strtoll / strtod are used directly to avoid the overhead
			// of a separate is_numeric() scan followed by a second parse.
			char* end = nullptr;
			long long ll = strtoll(val, &end, 10);
			if (end != val && *end == '\0') {
				obj[col_name] = ll;
			} else {
				// Not a plain integer; try floating-point
				double d = strtod(val, &end);
				if (end != val && *end == '\0') {
					obj[col_name] = d;
				} else {
					obj[col_name] = std::string(val);
				}
			}
		}
		rows.push_back(obj);
	}

	return rows;
}

#endif /* PROXYSQLGENAI */