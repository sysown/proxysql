#ifdef PROXYSQL40


#include "proxysql.h"
#include "MCP_Thread.h"
#include "MCP_Tool_Handler.h"
#include "MySQL_Tool_Handler.h"
#include "Config_Tool_Handler.h"
#include "Query_Tool_Handler.h"
#include "Admin_Tool_Handler.h"
#include "Cache_Tool_Handler.h"
#include "Stats_Tool_Handler.h"
#include "proxysql_debug.h"
#include "ProxySQL_MCP_Server.hpp"
#include "sqlite3db.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <pthread.h>
#include <algorithm>
#include <string>
#include <unordered_map>

// Define the array of variable names for the MCP module
static const char* mcp_thread_variables_names[] = {
	"enabled",
	"port",
	"use_ssl",
	"config_endpoint_auth",
	"stats_endpoint_auth",
	"query_endpoint_auth",
	"admin_endpoint_auth",
	"cache_endpoint_auth",
	"ai_endpoint_auth",
	"rag_endpoint_auth",
	"timeout_ms",
	"stats_show_queries_max_rows",
	"stats_show_processlist_max_rows",
	"stats_enable_debug_tools",
	NULL
};

MCP_Threads_Handler::MCP_Threads_Handler() {
	shutdown_ = 0;

	// Initialize the rwlock
	pthread_rwlock_init(&rwlock, NULL);

	// Initialize variables with default values
	variables.mcp_enabled = false;
	variables.mcp_port = 6071;
	variables.mcp_use_ssl = true;                      // Default to true for security
	variables.mcp_config_endpoint_auth = strdup("");
	variables.mcp_stats_endpoint_auth = strdup("");
	variables.mcp_query_endpoint_auth = strdup("");
	variables.mcp_admin_endpoint_auth = strdup("");
	variables.mcp_cache_endpoint_auth = strdup("");
	variables.mcp_ai_endpoint_auth = strdup("");
	variables.mcp_rag_endpoint_auth = strdup("");
	variables.mcp_timeout_ms = 30000;
	variables.mcp_stats_show_queries_max_rows = 200;
	variables.mcp_stats_show_processlist_max_rows = 200;
	variables.mcp_stats_enable_debug_tools = false;

	status_variables.total_requests = 0;
	status_variables.failed_requests = 0;
	status_variables.active_connections = 0;

	mcp_server = NULL;
	mysql_tool_handler = NULL;

	// Initialize new tool handlers
	config_tool_handler = NULL;
	query_tool_handler = NULL;
	admin_tool_handler = NULL;
	cache_tool_handler = NULL;
	stats_tool_handler = NULL;
	ai_tool_handler = NULL;
	rag_tool_handler = NULL;
}

MCP_Threads_Handler::~MCP_Threads_Handler() {
	if (variables.mcp_config_endpoint_auth)
		free(variables.mcp_config_endpoint_auth);
	if (variables.mcp_stats_endpoint_auth)
		free(variables.mcp_stats_endpoint_auth);
	if (variables.mcp_query_endpoint_auth)
		free(variables.mcp_query_endpoint_auth);
	if (variables.mcp_admin_endpoint_auth)
		free(variables.mcp_admin_endpoint_auth);
	if (variables.mcp_cache_endpoint_auth)
		free(variables.mcp_cache_endpoint_auth);
	if (variables.mcp_ai_endpoint_auth)
		free(variables.mcp_ai_endpoint_auth);
	if (variables.mcp_rag_endpoint_auth)
		free(variables.mcp_rag_endpoint_auth);

	if (mcp_server) {
		delete mcp_server;
		mcp_server = NULL;
	}

	if (mysql_tool_handler) {
		delete mysql_tool_handler;
		mysql_tool_handler = NULL;
	}

	// Clean up new tool handlers
	if (config_tool_handler) {
		delete config_tool_handler;
		config_tool_handler = NULL;
	}
	if (query_tool_handler) {
		delete query_tool_handler;
		query_tool_handler = NULL;
	}
	if (admin_tool_handler) {
		delete admin_tool_handler;
		admin_tool_handler = NULL;
	}
	if (cache_tool_handler) {
		delete cache_tool_handler;
		cache_tool_handler = NULL;
	}
	if (stats_tool_handler) {
		delete stats_tool_handler;
		stats_tool_handler = NULL;
	}
	if (ai_tool_handler) {
		delete ai_tool_handler;
		ai_tool_handler = NULL;
	}
	if (rag_tool_handler) {
		delete rag_tool_handler;
		rag_tool_handler = NULL;
	}

	// Destroy the rwlock
	pthread_rwlock_destroy(&rwlock);
}

void MCP_Threads_Handler::init() {
	proxy_info("Initializing MCP Threads Handler\n");
	// For now, this is a simple initialization
	// The HTTP/HTTPS server will be started when mcp_enabled is set to true
	// and will be managed through ProxySQL_Admin
	print_version();
}

void MCP_Threads_Handler::shutdown() {
	proxy_info("Shutting down MCP Threads Handler\n");
	shutdown_ = 1;

	// Stop the HTTP/HTTPS server if it's running
	if (mcp_server) {
		delete mcp_server;
		mcp_server = NULL;
	}
}

void MCP_Threads_Handler::wrlock() {
	pthread_rwlock_wrlock(&rwlock);
}

void MCP_Threads_Handler::wrunlock() {
	pthread_rwlock_unlock(&rwlock);
}

int MCP_Threads_Handler::get_variable(const char* name, char* val, size_t val_size) {
	if (!name || !val || val_size == 0)
		return -1;

	pthread_rwlock_rdlock(&rwlock);

	std::string out;
	int rc = 0;
	if (!strcmp(name, "enabled")) {
		out = variables.mcp_enabled ? "true" : "false";
	} else if (!strcmp(name, "port")) {
		out = std::to_string(variables.mcp_port);
	} else if (!strcmp(name, "use_ssl")) {
		out = variables.mcp_use_ssl ? "true" : "false";
	} else if (!strcmp(name, "config_endpoint_auth")) {
		out = variables.mcp_config_endpoint_auth ? variables.mcp_config_endpoint_auth : "";
	} else if (!strcmp(name, "stats_endpoint_auth")) {
		out = variables.mcp_stats_endpoint_auth ? variables.mcp_stats_endpoint_auth : "";
	} else if (!strcmp(name, "query_endpoint_auth")) {
		out = variables.mcp_query_endpoint_auth ? variables.mcp_query_endpoint_auth : "";
	} else if (!strcmp(name, "admin_endpoint_auth")) {
		out = variables.mcp_admin_endpoint_auth ? variables.mcp_admin_endpoint_auth : "";
	} else if (!strcmp(name, "cache_endpoint_auth")) {
		out = variables.mcp_cache_endpoint_auth ? variables.mcp_cache_endpoint_auth : "";
	} else if (!strcmp(name, "ai_endpoint_auth")) {
		out = variables.mcp_ai_endpoint_auth ? variables.mcp_ai_endpoint_auth : "";
	} else if (!strcmp(name, "rag_endpoint_auth")) {
		out = variables.mcp_rag_endpoint_auth ? variables.mcp_rag_endpoint_auth : "";
	} else if (!strcmp(name, "timeout_ms")) {
		out = std::to_string(variables.mcp_timeout_ms);
	} else if (!strcmp(name, "stats_show_queries_max_rows")) {
		out = std::to_string(variables.mcp_stats_show_queries_max_rows);
	} else if (!strcmp(name, "stats_show_processlist_max_rows")) {
		out = std::to_string(variables.mcp_stats_show_processlist_max_rows);
	} else if (!strcmp(name, "stats_enable_debug_tools")) {
		out = variables.mcp_stats_enable_debug_tools ? "true" : "false";
	} else {
		rc = -1;
	}
	pthread_rwlock_unlock(&rwlock);

	if (rc == 0) {
		snprintf(val, val_size, "%s", out.c_str());
	}
	return rc;
}

int MCP_Threads_Handler::set_variable(const char* name, const char* value) {
	if (!name || !value)
		return -1;

	pthread_rwlock_wrlock(&rwlock);
	int rc = -1;

	if (!strcmp(name, "enabled")) {
		if (strcasecmp(value, "true") == 0 || strcasecmp(value, "1") == 0) {
			variables.mcp_enabled = true;
			rc = 0;
		} else if (strcasecmp(value, "false") == 0 || strcasecmp(value, "0") == 0) {
			variables.mcp_enabled = false;
			rc = 0;
		}
	} else if (!strcmp(name, "port")) {
		int port = atoi(value);
		if (port > 0 && port < 65536) {
			variables.mcp_port = port;
			rc = 0;
		}
	} else if (!strcmp(name, "use_ssl")) {
		if (strcasecmp(value, "true") == 0 || strcasecmp(value, "1") == 0) {
			variables.mcp_use_ssl = true;
			rc = 0;
		} else if (strcasecmp(value, "false") == 0 || strcasecmp(value, "0") == 0) {
			variables.mcp_use_ssl = false;
			rc = 0;
		}
	} else if (!strcmp(name, "config_endpoint_auth")) {
		char* dup = strdup(value);
		if (dup != nullptr) {
			if (variables.mcp_config_endpoint_auth)
				free(variables.mcp_config_endpoint_auth);
			variables.mcp_config_endpoint_auth = dup;
			rc = 0;
		}
	} else if (!strcmp(name, "stats_endpoint_auth")) {
		char* dup = strdup(value);
		if (dup != nullptr) {
			if (variables.mcp_stats_endpoint_auth)
				free(variables.mcp_stats_endpoint_auth);
			variables.mcp_stats_endpoint_auth = dup;
			rc = 0;
		}
	} else if (!strcmp(name, "query_endpoint_auth")) {
		char* dup = strdup(value);
		if (dup != nullptr) {
			if (variables.mcp_query_endpoint_auth)
				free(variables.mcp_query_endpoint_auth);
			variables.mcp_query_endpoint_auth = dup;
			rc = 0;
		}
	} else if (!strcmp(name, "admin_endpoint_auth")) {
		char* dup = strdup(value);
		if (dup != nullptr) {
			if (variables.mcp_admin_endpoint_auth)
				free(variables.mcp_admin_endpoint_auth);
			variables.mcp_admin_endpoint_auth = dup;
			rc = 0;
		}
	} else if (!strcmp(name, "cache_endpoint_auth")) {
		char* dup = strdup(value);
		if (dup != nullptr) {
			if (variables.mcp_cache_endpoint_auth)
				free(variables.mcp_cache_endpoint_auth);
			variables.mcp_cache_endpoint_auth = dup;
			rc = 0;
		}
	} else if (!strcmp(name, "ai_endpoint_auth")) {
		char* dup = strdup(value);
		if (dup != nullptr) {
			if (variables.mcp_ai_endpoint_auth)
				free(variables.mcp_ai_endpoint_auth);
			variables.mcp_ai_endpoint_auth = dup;
			rc = 0;
		}
	} else if (!strcmp(name, "rag_endpoint_auth")) {
		char* dup = strdup(value);
		if (dup != nullptr) {
			if (variables.mcp_rag_endpoint_auth)
				free(variables.mcp_rag_endpoint_auth);
			variables.mcp_rag_endpoint_auth = dup;
			rc = 0;
		}
	} else if (!strcmp(name, "timeout_ms")) {
		int timeout = atoi(value);
		if (timeout >= 0) {
			variables.mcp_timeout_ms = timeout;
			rc = 0;
		}
	} else if (!strcmp(name, "stats_show_queries_max_rows")) {
		/**
		 * Hard safety cap: do not allow configuring values above 1000.
		 * This keeps MCP show_queries bounded even if callers request large pages.
		 */
		int max_rows = atoi(value);
		if (max_rows >= 1 && max_rows <= 1000) {
			variables.mcp_stats_show_queries_max_rows = max_rows;
			rc = 0;
		}
	} else if (!strcmp(name, "stats_show_processlist_max_rows")) {
		/**
		 * Hard safety cap: do not allow configuring values above 1000.
		 * This keeps MCP show_processlist bounded even if callers request
		 * large pages.
		 */
		int max_rows = atoi(value);
		if (max_rows >= 1 && max_rows <= 1000) {
			variables.mcp_stats_show_processlist_max_rows = max_rows;
			rc = 0;
		}
	} else if (!strcmp(name, "stats_enable_debug_tools")) {
		if (strcasecmp(value, "true") == 0 || strcasecmp(value, "1") == 0) {
			variables.mcp_stats_enable_debug_tools = true;
			rc = 0;
		} else if (strcasecmp(value, "false") == 0 || strcasecmp(value, "0") == 0) {
			variables.mcp_stats_enable_debug_tools = false;
			rc = 0;
		}
	}

	pthread_rwlock_unlock(&rwlock);
	return rc;
}

bool MCP_Threads_Handler::get_variable_string(const char* name, std::string& out) {
	if (!name) {
		out.clear();
		return false;
	}

	const auto bool_to_str = [](bool v) -> std::string { return v ? "true" : "false"; };
	const auto int_to_str  = [](int v) -> std::string { return std::to_string(v); };

	pthread_rwlock_rdlock(&rwlock);
	bool ok = true;
	if (!strcmp(name, "enabled")) {
		out = bool_to_str(variables.mcp_enabled);
	} else if (!strcmp(name, "port")) {
		out = int_to_str(variables.mcp_port);
	} else if (!strcmp(name, "use_ssl")) {
		out = bool_to_str(variables.mcp_use_ssl);
	} else if (!strcmp(name, "config_endpoint_auth")) {
		out = variables.mcp_config_endpoint_auth ? variables.mcp_config_endpoint_auth : "";
	} else if (!strcmp(name, "stats_endpoint_auth")) {
		out = variables.mcp_stats_endpoint_auth ? variables.mcp_stats_endpoint_auth : "";
	} else if (!strcmp(name, "query_endpoint_auth")) {
		out = variables.mcp_query_endpoint_auth ? variables.mcp_query_endpoint_auth : "";
	} else if (!strcmp(name, "admin_endpoint_auth")) {
		out = variables.mcp_admin_endpoint_auth ? variables.mcp_admin_endpoint_auth : "";
	} else if (!strcmp(name, "cache_endpoint_auth")) {
		out = variables.mcp_cache_endpoint_auth ? variables.mcp_cache_endpoint_auth : "";
	} else if (!strcmp(name, "ai_endpoint_auth")) {
		out = variables.mcp_ai_endpoint_auth ? variables.mcp_ai_endpoint_auth : "";
	} else if (!strcmp(name, "rag_endpoint_auth")) {
		out = variables.mcp_rag_endpoint_auth ? variables.mcp_rag_endpoint_auth : "";
	} else if (!strcmp(name, "timeout_ms")) {
		out = int_to_str(variables.mcp_timeout_ms);
	} else if (!strcmp(name, "stats_show_queries_max_rows")) {
		out = int_to_str(variables.mcp_stats_show_queries_max_rows);
	} else if (!strcmp(name, "stats_show_processlist_max_rows")) {
		out = int_to_str(variables.mcp_stats_show_processlist_max_rows);
	} else if (!strcmp(name, "stats_enable_debug_tools")) {
		out = bool_to_str(variables.mcp_stats_enable_debug_tools);
	} else {
		out.clear();
		ok = false;
	}
	pthread_rwlock_unlock(&rwlock);
	return ok;
}

bool MCP_Threads_Handler::has_variable(const char* name) {
	if (!name)
		return false;

	for (int i = 0; mcp_thread_variables_names[i]; i++) {
		if (!strcmp(name, mcp_thread_variables_names[i])) {
			return true;
		}
	}
	return false;
}

char** MCP_Threads_Handler::get_variables_list() {
	// Count variables
	int count = 0;
	while (mcp_thread_variables_names[count]) {
		count++;
	}

	// Allocate array
	char** list = (char**)malloc(sizeof(char*) * (count + 1));
	if (!list)
		return NULL;

	// Fill array
	for (int i = 0; i < count; i++) {
		list[i] = strdup(mcp_thread_variables_names[i]);
	}
	list[count] = NULL;

	return list;
}

void MCP_Threads_Handler::print_version() {
	fprintf(stderr, "MCP Threads Handler rev. %s -- %s -- %s\n", MCP_THREAD_VERSION, __FILE__, __TIMESTAMP__);
}

int MCP_Threads_Handler::load_target_auth_map(SQLite3_result* resultset) {
	if (!resultset) {
		return -1;
	}
	std::map<std::string, MCP_Target_Auth_Context> new_map;
	for (auto row : resultset->rows) {
		if (row->cnt < 12 || !row->fields[0] || !row->fields[1] || !row->fields[2] || !row->fields[3] ||
			!row->fields[9] || !row->fields[10]) {
			continue;
		}

		MCP_Target_Auth_Context ctx;
		ctx.target_id = row->fields[0];
		ctx.protocol = row->fields[1];
		std::transform(ctx.protocol.begin(), ctx.protocol.end(), ctx.protocol.begin(), ::tolower);
		ctx.hostgroup_id = atoi(row->fields[2]);
		ctx.auth_profile_id = row->fields[3];
		ctx.max_rows = row->fields[4] ? atoi(row->fields[4]) : 200;
		ctx.timeout_ms = row->fields[5] ? atoi(row->fields[5]) : 2000;
		ctx.allow_explain = row->fields[6] ? (atoi(row->fields[6]) != 0) : true;
		ctx.allow_discovery = row->fields[7] ? (atoi(row->fields[7]) != 0) : true;
		ctx.description = row->fields[8] ? row->fields[8] : "";
		ctx.db_username = row->fields[9];
		ctx.db_password = row->fields[10];
		ctx.default_schema = row->fields[11] ? row->fields[11] : "";

		new_map[ctx.target_id] = ctx;
	}
	delete resultset;

	pthread_rwlock_wrlock(&rwlock);
	target_auth_map.swap(new_map);
	pthread_rwlock_unlock(&rwlock);

	proxy_info("MCP_Threads_Handler: loaded %zu target auth profile mapping(s)\n", target_auth_map.size());
	return 0;
}

bool MCP_Threads_Handler::get_target_auth_context(const std::string& target_id, MCP_Target_Auth_Context& out_ctx) {
	pthread_rwlock_rdlock(&rwlock);
	auto it = target_auth_map.find(target_id);
	if (it == target_auth_map.end()) {
		pthread_rwlock_unlock(&rwlock);
		return false;
	}
	out_ctx = it->second;
	pthread_rwlock_unlock(&rwlock);
	return true;
}

std::vector<MCP_Threads_Handler::MCP_Target_Auth_Context> MCP_Threads_Handler::get_all_target_auth_contexts() {
	std::vector<MCP_Target_Auth_Context> out;
	pthread_rwlock_rdlock(&rwlock);
	out.reserve(target_auth_map.size());
	for (const auto& kv : target_auth_map) {
		out.push_back(kv.second);
	}
	pthread_rwlock_unlock(&rwlock);
	return out;
}

// ----------------------------------------------------------------------------
// ABI-3 separation-of-duties: per-table install / save / project triplets.
//
// auth_profiles_ and target_profiles_ hold the module's authoritative
// in-memory snapshot of the editable mcp_<X> tables. The legacy joined
// target_auth_map is now derived from these two and rebuilt on every
// install. SAVE pulls from these vectors back into main.mcp_<X>; the
// runtime-view callbacks DELETE+INSERT runtime_mcp_<X> from them.
// ----------------------------------------------------------------------------

namespace {

// `field` may be NULL; treat as empty string.
inline const char* nz(const char* field) {
	return field != nullptr ? field : "";
}

// Bind text — empty becomes empty string, never NULL.  Use SQLITE_TRANSIENT
// so SQLite copies before the next reset/clear cycle invalidates the source.
inline void bind_text_or_null(sqlite3_stmt* stmt, int idx, const char* val) {
	if (val == nullptr) {
		(*proxy_sqlite3_bind_null)(stmt, idx);
	} else {
		(*proxy_sqlite3_bind_text)(stmt, idx, val, -1, SQLITE_TRANSIENT);
	}
}

inline void bind_int(sqlite3_stmt* stmt, int idx, int val) {
	(*proxy_sqlite3_bind_int64)(stmt, idx, static_cast<sqlite3_int64>(val));
}

} // namespace

void MCP_Threads_Handler::rebuild_target_auth_map_locked() {
	// Caller holds write lock on rwlock.
	std::unordered_map<std::string, const MCP_Auth_Profile_Row*> by_id;
	by_id.reserve(auth_profiles_.size());
	for (const auto& a : auth_profiles_) {
		by_id[a.auth_profile_id] = &a;
	}

	std::map<std::string, MCP_Target_Auth_Context> new_map;
	for (const auto& t : target_profiles_) {
		if (t.active == 0) continue;
		auto it = by_id.find(t.auth_profile_id);
		if (it == by_id.end()) continue;  // dangling FK; skip silently
		const MCP_Auth_Profile_Row& a = *it->second;

		MCP_Target_Auth_Context ctx;
		ctx.target_id = t.target_id;
		ctx.protocol = t.protocol;
		std::transform(ctx.protocol.begin(), ctx.protocol.end(), ctx.protocol.begin(), ::tolower);
		ctx.hostgroup_id = t.hostgroup_id;
		ctx.auth_profile_id = t.auth_profile_id;
		ctx.max_rows = t.max_rows;
		ctx.timeout_ms = t.timeout_ms;
		ctx.allow_explain = t.allow_explain != 0;
		ctx.allow_discovery = t.allow_discovery != 0;
		ctx.description = t.description;
		ctx.db_username = a.db_username;
		ctx.db_password = a.db_password;
		ctx.default_schema = a.default_schema;

		new_map[t.target_id] = ctx;
	}
	target_auth_map.swap(new_map);
}

namespace {

// Read main.mcp_auth_profiles into a fresh vector.  No module-state
// access — purely SELECT + parse.  Caller decides when to take the
// wrlock to swap the result into MCP_Threads_Handler::auth_profiles_.
// Lifting this out of install_auth_profiles_from_admin lets the
// combined install_profiles_from_admin run both reads outside the
// lock, hold one wrlock for both swaps, and rebuild target_auth_map
// once after both succeed (avoids the partial-success window where
// the joined map references new auth rows but stale target rows).
bool read_auth_profiles_from_admin(
	SQLite3DB& admindb,
	std::vector<MCP_Threads_Handler::MCP_Auth_Profile_Row>& out,
	std::string& err
) {
	char* sqlite_err = nullptr;
	int cols = 0, affected_rows = 0;
	SQLite3_result* rs = nullptr;
	const char* q =
		"SELECT auth_profile_id, db_username, db_password, default_schema,"
		" use_ssl, ssl_mode, comment FROM main.mcp_auth_profiles"
		" ORDER BY auth_profile_id";
	admindb.execute_statement(q, &sqlite_err, &cols, &affected_rows, &rs);
	if (sqlite_err != nullptr) {
		err.assign(sqlite_err);
		free(sqlite_err);
		if (rs != nullptr) delete rs;
		return false;
	}
	if (rs != nullptr) {
		out.reserve(rs->rows.size());
		for (auto* row : rs->rows) {
			if (row->cnt < 7 || row->fields[0] == nullptr) continue;
			MCP_Threads_Handler::MCP_Auth_Profile_Row a;
			a.auth_profile_id = nz(row->fields[0]);
			a.db_username     = nz(row->fields[1]);
			a.db_password     = nz(row->fields[2]);
			a.default_schema  = nz(row->fields[3]);
			a.use_ssl         = row->fields[4] ? atoi(row->fields[4]) : 0;
			a.ssl_mode        = nz(row->fields[5]);
			a.comment         = nz(row->fields[6]);
			out.push_back(std::move(a));
		}
		delete rs;
	}
	return true;
}

// Read main.mcp_target_profiles into a fresh vector.  See
// read_auth_profiles_from_admin above for the rationale.
bool read_target_profiles_from_admin(
	SQLite3DB& admindb,
	std::vector<MCP_Threads_Handler::MCP_Target_Profile_Row>& out,
	std::string& err
) {
	char* sqlite_err = nullptr;
	int cols = 0, affected_rows = 0;
	SQLite3_result* rs = nullptr;
	const char* q =
		"SELECT target_id, protocol, hostgroup_id, auth_profile_id, description,"
		" max_rows, timeout_ms, allow_explain, allow_discovery, active, comment"
		" FROM main.mcp_target_profiles ORDER BY target_id";
	admindb.execute_statement(q, &sqlite_err, &cols, &affected_rows, &rs);
	if (sqlite_err != nullptr) {
		err.assign(sqlite_err);
		free(sqlite_err);
		if (rs != nullptr) delete rs;
		return false;
	}
	if (rs != nullptr) {
		out.reserve(rs->rows.size());
		for (auto* row : rs->rows) {
			if (row->cnt < 11 || row->fields[0] == nullptr) continue;
			MCP_Threads_Handler::MCP_Target_Profile_Row t;
			t.target_id        = nz(row->fields[0]);
			t.protocol         = nz(row->fields[1]);
			t.hostgroup_id     = row->fields[2] ? atoi(row->fields[2]) : 0;
			t.auth_profile_id  = nz(row->fields[3]);
			t.description      = nz(row->fields[4]);
			t.max_rows         = row->fields[5] ? atoi(row->fields[5]) : 200;
			t.timeout_ms       = row->fields[6] ? atoi(row->fields[6]) : 2000;
			t.allow_explain    = row->fields[7] ? atoi(row->fields[7]) : 1;
			t.allow_discovery  = row->fields[8] ? atoi(row->fields[8]) : 1;
			t.active           = row->fields[9] ? atoi(row->fields[9]) : 1;
			t.comment          = nz(row->fields[10]);
			out.push_back(std::move(t));
		}
		delete rs;
	}
	return true;
}

// Per-row INSERT helpers: bind, step, return false on error.  The
// transaction-level callers wrap a loop of these in BEGIN ... COMMIT
// and ROLLBACK if any returns false, so the half-done DELETE+INSERT
// state is never left committed.
bool insert_auth_row(sqlite3_stmt* st, const MCP_Threads_Handler::MCP_Auth_Profile_Row& a) {
	int rc = 0;
	bind_text_or_null(st, 1, a.auth_profile_id.c_str());
	bind_text_or_null(st, 2, a.db_username.c_str());
	bind_text_or_null(st, 3, a.db_password.c_str());
	bind_text_or_null(st, 4, a.default_schema.c_str());
	bind_int        (st, 5, a.use_ssl);
	bind_text_or_null(st, 6, a.ssl_mode.c_str());
	bind_text_or_null(st, 7, a.comment.c_str());
	SAFE_SQLITE3_STEP2(st);
	const bool ok = (rc == SQLITE_DONE);
	(*proxy_sqlite3_clear_bindings)(st);
	(*proxy_sqlite3_reset)(st);
	return ok;
}

bool insert_target_row(sqlite3_stmt* st, const MCP_Threads_Handler::MCP_Target_Profile_Row& t) {
	int rc = 0;
	bind_text_or_null(st, 1, t.target_id.c_str());
	bind_text_or_null(st, 2, t.protocol.c_str());
	bind_int         (st, 3, t.hostgroup_id);
	bind_text_or_null(st, 4, t.auth_profile_id.c_str());
	bind_text_or_null(st, 5, t.description.c_str());
	bind_int         (st, 6, t.max_rows);
	bind_int         (st, 7, t.timeout_ms);
	bind_int         (st, 8, t.allow_explain);
	bind_int         (st, 9, t.allow_discovery);
	bind_int         (st, 10, t.active);
	bind_text_or_null(st, 11, t.comment.c_str());
	SAFE_SQLITE3_STEP2(st);
	const bool ok = (rc == SQLITE_DONE);
	(*proxy_sqlite3_clear_bindings)(st);
	(*proxy_sqlite3_reset)(st);
	return ok;
}

bool insert_query_rule_row(sqlite3_stmt* st, const MCP_Threads_Handler::MCP_Query_Rule_Row& r) {
	int rc = 0;
	bind_int         (st, 1,  r.rule_id);
	bind_int         (st, 2,  r.active);
	bind_text_or_null(st, 3,  r.username.c_str());
	bind_text_or_null(st, 4,  r.target_id.c_str());
	bind_text_or_null(st, 5,  r.schemaname.c_str());
	bind_text_or_null(st, 6,  r.tool_name.c_str());
	bind_text_or_null(st, 7,  r.match_pattern.c_str());
	bind_int         (st, 8,  r.negate_match_pattern);
	bind_text_or_null(st, 9,  r.re_modifiers.c_str());
	bind_int         (st, 10, r.flagIN);
	if (r.flagOUT_is_null) (*proxy_sqlite3_bind_null)(st, 11);
	else                   bind_int(st, 11, r.flagOUT);
	bind_text_or_null(st, 12, r.replace_pattern.c_str());
	if (r.timeout_ms_is_null) (*proxy_sqlite3_bind_null)(st, 13);
	else                      bind_int(st, 13, r.timeout_ms);
	bind_text_or_null(st, 14, r.error_msg.c_str());
	bind_text_or_null(st, 15, r.OK_msg.c_str());
	if (r.log_is_null) (*proxy_sqlite3_bind_null)(st, 16);
	else               bind_int(st, 16, r.log);
	bind_int         (st, 17, r.apply);
	bind_text_or_null(st, 18, r.comment.c_str());
	SAFE_SQLITE3_STEP2(st);
	const bool ok = (rc == SQLITE_DONE);
	(*proxy_sqlite3_clear_bindings)(st);
	(*proxy_sqlite3_reset)(st);
	return ok;
}

} // namespace

bool MCP_Threads_Handler::install_auth_profiles_from_admin(SQLite3DB& admindb, std::string& err) {
	std::vector<MCP_Auth_Profile_Row> next;
	if (!read_auth_profiles_from_admin(admindb, next, err)) {
		return false;
	}
	pthread_rwlock_wrlock(&rwlock);
	auth_profiles_.swap(next);
	rebuild_target_auth_map_locked();
	pthread_rwlock_unlock(&rwlock);
	return true;
}

bool MCP_Threads_Handler::install_target_profiles_from_admin(SQLite3DB& admindb, std::string& err) {
	std::vector<MCP_Target_Profile_Row> next;
	if (!read_target_profiles_from_admin(admindb, next, err)) {
		return false;
	}
	pthread_rwlock_wrlock(&rwlock);
	target_profiles_.swap(next);
	rebuild_target_auth_map_locked();
	pthread_rwlock_unlock(&rwlock);
	return true;
}

bool MCP_Threads_Handler::install_profiles_from_admin(SQLite3DB& admindb, std::string& err) {
	std::vector<MCP_Auth_Profile_Row> auth_next;
	std::vector<MCP_Target_Profile_Row> target_next;

	// Read both source tables BEFORE acquiring the wrlock so a slow
	// admin DB doesn't gate the listener (which holds rdlock during
	// every request).  If either read fails, the in-memory state is
	// untouched.
	if (!read_auth_profiles_from_admin(admindb, auth_next, err))     return false;
	if (!read_target_profiles_from_admin(admindb, target_next, err)) return false;

	pthread_rwlock_wrlock(&rwlock);
	auth_profiles_.swap(auth_next);
	target_profiles_.swap(target_next);
	rebuild_target_auth_map_locked();
	pthread_rwlock_unlock(&rwlock);
	return true;
}

bool MCP_Threads_Handler::save_auth_profiles_to_admin_table(SQLite3DB& admindb) {
	if (!admindb.execute("BEGIN")) return false;
	if (!admindb.execute("DELETE FROM main.mcp_auth_profiles")) {
		admindb.execute("ROLLBACK");
		return false;
	}
	auto [prep_rc, stmt] = admindb.prepare_v2(
		"INSERT INTO main.mcp_auth_profiles"
		" (auth_profile_id, db_username, db_password, default_schema,"
		"  use_ssl, ssl_mode, comment)"
		" VALUES(?1,?2,?3,?4,?5,?6,?7)");
	if (prep_rc != SQLITE_OK) {
		admindb.execute("ROLLBACK");
		return false;
	}
	sqlite3_stmt* st = stmt.get();

	pthread_rwlock_rdlock(&rwlock);
	auto snapshot = auth_profiles_;
	pthread_rwlock_unlock(&rwlock);

	for (const auto& a : snapshot) {
		if (!insert_auth_row(st, a)) {
			admindb.execute("ROLLBACK");
			return false;
		}
	}
	return admindb.execute("COMMIT");
}

bool MCP_Threads_Handler::save_target_profiles_to_admin_table(SQLite3DB& admindb) {
	if (!admindb.execute("BEGIN")) return false;
	if (!admindb.execute("DELETE FROM main.mcp_target_profiles")) {
		admindb.execute("ROLLBACK");
		return false;
	}
	auto [prep_rc, stmt] = admindb.prepare_v2(
		"INSERT INTO main.mcp_target_profiles"
		" (target_id, protocol, hostgroup_id, auth_profile_id, description,"
		"  max_rows, timeout_ms, allow_explain, allow_discovery, active, comment)"
		" VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)");
	if (prep_rc != SQLITE_OK) {
		admindb.execute("ROLLBACK");
		return false;
	}
	sqlite3_stmt* st = stmt.get();

	pthread_rwlock_rdlock(&rwlock);
	auto snapshot = target_profiles_;
	pthread_rwlock_unlock(&rwlock);

	for (const auto& t : snapshot) {
		if (!insert_target_row(st, t)) {
			admindb.execute("ROLLBACK");
			return false;
		}
	}
	return admindb.execute("COMMIT");
}

bool MCP_Threads_Handler::save_profiles_to_admin_table(SQLite3DB& admindb) {
	// Snapshot both vectors under a single rdlock so the two source
	// arrays are coherent even if a concurrent LOAD MCP PROFILES is
	// installing fresh state in between.  Then delete + repopulate
	// both target tables in a single BEGIN ... COMMIT — operators
	// querying main.mcp_<X> mid-save can never see one table updated
	// and the other still on the old data, and the FK constraint
	// enforced by SQLite has no chance to flag dangling
	// target.auth_profile_id rows.
	pthread_rwlock_rdlock(&rwlock);
	auto auth_snapshot = auth_profiles_;
	auto target_snapshot = target_profiles_;
	pthread_rwlock_unlock(&rwlock);

	if (!admindb.execute("BEGIN")) return false;
	// Delete targets BEFORE auths so the FK constraint never trips
	// during the delete pass: target.auth_profile_id references
	// auth_profile_id, so removing parents (auths) first would orphan
	// children (targets).  Reverse on the insert side: write parents
	// before children for the same reason.
	if (!admindb.execute("DELETE FROM main.mcp_target_profiles")) {
		admindb.execute("ROLLBACK");
		return false;
	}
	if (!admindb.execute("DELETE FROM main.mcp_auth_profiles")) {
		admindb.execute("ROLLBACK");
		return false;
	}

	auto [auth_prep_rc, auth_stmt] = admindb.prepare_v2(
		"INSERT INTO main.mcp_auth_profiles"
		" (auth_profile_id, db_username, db_password, default_schema,"
		"  use_ssl, ssl_mode, comment)"
		" VALUES(?1,?2,?3,?4,?5,?6,?7)");
	if (auth_prep_rc != SQLITE_OK) {
		admindb.execute("ROLLBACK");
		return false;
	}
	for (const auto& a : auth_snapshot) {
		if (!insert_auth_row(auth_stmt.get(), a)) {
			admindb.execute("ROLLBACK");
			return false;
		}
	}

	auto [target_prep_rc, target_stmt] = admindb.prepare_v2(
		"INSERT INTO main.mcp_target_profiles"
		" (target_id, protocol, hostgroup_id, auth_profile_id, description,"
		"  max_rows, timeout_ms, allow_explain, allow_discovery, active, comment)"
		" VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)");
	if (target_prep_rc != SQLITE_OK) {
		admindb.execute("ROLLBACK");
		return false;
	}
	for (const auto& t : target_snapshot) {
		if (!insert_target_row(target_stmt.get(), t)) {
			admindb.execute("ROLLBACK");
			return false;
		}
	}
	return admindb.execute("COMMIT");
}

void MCP_Threads_Handler::project_auth_profiles_to_runtime_view(SQLite3DB& admindb) {
	if (!admindb.execute("BEGIN")) return;
	if (!admindb.execute("DELETE FROM runtime_mcp_auth_profiles")) {
		admindb.execute("ROLLBACK");
		return;
	}
	auto [prep_rc, stmt] = admindb.prepare_v2(
		"INSERT INTO runtime_mcp_auth_profiles"
		" (auth_profile_id, db_username, db_password, default_schema,"
		"  use_ssl, ssl_mode, comment)"
		" VALUES(?1,?2,?3,?4,?5,?6,?7)");
	if (prep_rc != SQLITE_OK) {
		admindb.execute("ROLLBACK");
		return;
	}
	sqlite3_stmt* st = stmt.get();

	pthread_rwlock_rdlock(&rwlock);
	auto snapshot = auth_profiles_;
	pthread_rwlock_unlock(&rwlock);

	for (const auto& a : snapshot) {
		if (!insert_auth_row(st, a)) {
			admindb.execute("ROLLBACK");
			return;
		}
	}
	admindb.execute("COMMIT");
}

void MCP_Threads_Handler::project_target_profiles_to_runtime_view(SQLite3DB& admindb) {
	if (!admindb.execute("BEGIN")) return;
	if (!admindb.execute("DELETE FROM runtime_mcp_target_profiles")) {
		admindb.execute("ROLLBACK");
		return;
	}
	auto [prep_rc, stmt] = admindb.prepare_v2(
		"INSERT INTO runtime_mcp_target_profiles"
		" (target_id, protocol, hostgroup_id, auth_profile_id, description,"
		"  max_rows, timeout_ms, allow_explain, allow_discovery, active, comment)"
		" VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)");
	if (prep_rc != SQLITE_OK) {
		admindb.execute("ROLLBACK");
		return;
	}
	sqlite3_stmt* st = stmt.get();

	pthread_rwlock_rdlock(&rwlock);
	auto snapshot = target_profiles_;
	pthread_rwlock_unlock(&rwlock);

	for (const auto& t : snapshot) {
		if (!insert_target_row(st, t)) {
			admindb.execute("ROLLBACK");
			return;
		}
	}
	admindb.execute("COMMIT");
}

std::vector<MCP_Threads_Handler::MCP_Auth_Profile_Row>
MCP_Threads_Handler::get_auth_profiles_snapshot() {
	pthread_rwlock_rdlock(&rwlock);
	auto snapshot = auth_profiles_;
	pthread_rwlock_unlock(&rwlock);
	return snapshot;
}

std::vector<MCP_Threads_Handler::MCP_Target_Profile_Row>
MCP_Threads_Handler::get_target_profiles_snapshot() {
	pthread_rwlock_rdlock(&rwlock);
	auto snapshot = target_profiles_;
	pthread_rwlock_unlock(&rwlock);
	return snapshot;
}

bool MCP_Threads_Handler::install_query_rules_from_admin(SQLite3DB& admindb, std::string& err) {
	char* sqlite_err = nullptr;
	int cols = 0, affected_rows = 0;
	SQLite3_result* rs = nullptr;
	const char* q =
		"SELECT rule_id, active, username, target_id, schemaname, tool_name,"
		" match_pattern, negate_match_pattern, re_modifiers, flagIN, flagOUT,"
		" replace_pattern, timeout_ms, error_msg, OK_msg, log, apply, comment"
		" FROM main.mcp_query_rules ORDER BY rule_id";
	admindb.execute_statement(q, &sqlite_err, &cols, &affected_rows, &rs);
	if (sqlite_err != nullptr) {
		err.assign(sqlite_err);
		free(sqlite_err);
		if (rs != nullptr) delete rs;
		return false;
	}

	std::vector<MCP_Query_Rule_Row> next;
	if (rs != nullptr) {
		next.reserve(rs->rows.size());
		for (auto* row : rs->rows) {
			if (row->cnt < 18) continue;
			MCP_Query_Rule_Row r;
			r.rule_id              = row->fields[0]  ? atoi(row->fields[0])  : 0;
			r.active               = row->fields[1]  ? atoi(row->fields[1])  : 0;
			r.username             = nz(row->fields[2]);
			r.target_id            = nz(row->fields[3]);
			r.schemaname           = nz(row->fields[4]);
			r.tool_name            = nz(row->fields[5]);
			r.match_pattern        = nz(row->fields[6]);
			r.negate_match_pattern = row->fields[7]  ? atoi(row->fields[7])  : 0;
			r.re_modifiers         = nz(row->fields[8]);
			r.flagIN               = row->fields[9]  ? atoi(row->fields[9])  : 0;
			r.flagOUT_is_null      = (row->fields[10] == nullptr);
			r.flagOUT              = r.flagOUT_is_null ? 0 : atoi(row->fields[10]);
			r.replace_pattern      = nz(row->fields[11]);
			r.timeout_ms_is_null   = (row->fields[12] == nullptr);
			r.timeout_ms           = r.timeout_ms_is_null ? 0 : atoi(row->fields[12]);
			r.error_msg            = nz(row->fields[13]);
			r.OK_msg               = nz(row->fields[14]);
			r.log_is_null          = (row->fields[15] == nullptr);
			r.log                  = r.log_is_null ? 0 : atoi(row->fields[15]);
			r.apply                = row->fields[16] ? atoi(row->fields[16]) : 1;
			r.comment              = nz(row->fields[17]);
			next.push_back(std::move(r));
		}
		// rs is consumed below by the listener-attach path if available;
		// otherwise we just delete it.
	}

	pthread_rwlock_wrlock(&rwlock);
	query_rules_.swap(next);
	pthread_rwlock_unlock(&rwlock);

	// If the MCP listener is up, also push the rows into the live
	// Discovery_Schema cache so the request hot-path picks them up
	// immediately. Discovery_Schema::load_mcp_query_rules takes
	// ownership of the resultset, so we hand off `rs` here and skip
	// the explicit delete; if the listener is down, delete it ourselves.
	if (rs != nullptr) {
		Query_Tool_Handler* qth = this->query_tool_handler;
		Discovery_Schema* catalog = qth ? qth->get_catalog() : nullptr;
		if (catalog != nullptr) {
			catalog->load_mcp_query_rules(rs);
		} else {
			delete rs;
		}
	}
	return true;
}

bool MCP_Threads_Handler::save_query_rules_to_admin_table(SQLite3DB& admindb) {
	if (!admindb.execute("BEGIN")) return false;
	if (!admindb.execute("DELETE FROM main.mcp_query_rules")) {
		admindb.execute("ROLLBACK");
		return false;
	}
	auto [prep_rc, stmt] = admindb.prepare_v2(
		"INSERT INTO main.mcp_query_rules"
		" (rule_id, active, username, target_id, schemaname, tool_name,"
		"  match_pattern, negate_match_pattern, re_modifiers, flagIN, flagOUT,"
		"  replace_pattern, timeout_ms, error_msg, OK_msg, log, apply, comment)"
		" VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)");
	if (prep_rc != SQLITE_OK) {
		admindb.execute("ROLLBACK");
		return false;
	}
	sqlite3_stmt* st = stmt.get();

	pthread_rwlock_rdlock(&rwlock);
	auto snapshot = query_rules_;
	pthread_rwlock_unlock(&rwlock);

	for (const auto& r : snapshot) {
		if (!insert_query_rule_row(st, r)) {
			admindb.execute("ROLLBACK");
			return false;
		}
	}
	return admindb.execute("COMMIT");
}

void MCP_Threads_Handler::project_query_rules_to_runtime_view(SQLite3DB& admindb) {
	if (!admindb.execute("BEGIN")) return;
	if (!admindb.execute("DELETE FROM runtime_mcp_query_rules")) {
		admindb.execute("ROLLBACK");
		return;
	}
	auto [prep_rc, stmt] = admindb.prepare_v2(
		"INSERT INTO runtime_mcp_query_rules"
		" (rule_id, active, username, target_id, schemaname, tool_name,"
		"  match_pattern, negate_match_pattern, re_modifiers, flagIN, flagOUT,"
		"  replace_pattern, timeout_ms, error_msg, OK_msg, log, apply, comment)"
		" VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)");
	if (prep_rc != SQLITE_OK) {
		admindb.execute("ROLLBACK");
		return;
	}
	sqlite3_stmt* st = stmt.get();

	pthread_rwlock_rdlock(&rwlock);
	auto snapshot = query_rules_;
	pthread_rwlock_unlock(&rwlock);

	for (const auto& r : snapshot) {
		if (!insert_query_rule_row(st, r)) {
			admindb.execute("ROLLBACK");
			return;
		}
	}
	admindb.execute("COMMIT");
}

std::vector<MCP_Threads_Handler::MCP_Query_Rule_Row>
MCP_Threads_Handler::get_query_rules_snapshot() {
	pthread_rwlock_rdlock(&rwlock);
	auto snapshot = query_rules_;
	pthread_rwlock_unlock(&rwlock);
	return snapshot;
}

std::vector<std::pair<std::string, std::string>> MCP_Threads_Handler::collect_status_variables() {
	std::vector<std::pair<std::string, std::string>> vars;
	vars.push_back({"mcp_total_requests", std::to_string(status_variables.total_requests)});
	vars.push_back({"mcp_failed_requests", std::to_string(status_variables.failed_requests)});
	vars.push_back({"mcp_active_connections", std::to_string(status_variables.active_connections)});
	return vars;
}

#endif /* PROXYSQL40 */
