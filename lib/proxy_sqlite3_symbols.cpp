#include "sqlite3.h"
#include <cstddef>
#include "sqlite3db.h"
// Forward declarations for proxy types
class SQLite3DB;
class SQLite3_result;
class SQLite3_row;

/*
 * This translation unit defines the storage for the proxy_sqlite3_*
 * function pointers. Exactly one TU must define these symbols to
 * avoid multiple-definition issues; other TUs should include
 * include/sqlite3db.h which declares them as extern.
 */

int (*proxy_sqlite3_bind_double)(sqlite3_stmt*, int, double) = sqlite3_bind_double;
int (*proxy_sqlite3_bind_int)(sqlite3_stmt*, int, int) = sqlite3_bind_int;
int (*proxy_sqlite3_bind_int64)(sqlite3_stmt*, int, sqlite3_int64) = sqlite3_bind_int64;
int (*proxy_sqlite3_bind_null)(sqlite3_stmt*, int) = sqlite3_bind_null;
int (*proxy_sqlite3_bind_text)(sqlite3_stmt*,int,const char*,int,void(*)(void*)) = sqlite3_bind_text;
int (*proxy_sqlite3_bind_blob)(sqlite3_stmt*, int, const void*, int, void(*)(void*)) = sqlite3_bind_blob;
const char *(*proxy_sqlite3_column_name)(sqlite3_stmt*, int) = sqlite3_column_name;
const unsigned char *(*proxy_sqlite3_column_text)(sqlite3_stmt*, int) = sqlite3_column_text;
int (*proxy_sqlite3_column_bytes)(sqlite3_stmt*, int) = sqlite3_column_bytes;
int (*proxy_sqlite3_column_type)(sqlite3_stmt*, int) = sqlite3_column_type;
int (*proxy_sqlite3_column_count)(sqlite3_stmt*) = sqlite3_column_count;
int (*proxy_sqlite3_column_int)(sqlite3_stmt*, int) = sqlite3_column_int;
sqlite3_int64 (*proxy_sqlite3_column_int64)(sqlite3_stmt*, int) = sqlite3_column_int64;
double (*proxy_sqlite3_column_double)(sqlite3_stmt*, int) = sqlite3_column_double;
sqlite3_int64 (*proxy_sqlite3_last_insert_rowid)(sqlite3*) = sqlite3_last_insert_rowid;
const char *(*proxy_sqlite3_errstr)(int) = sqlite3_errstr;
sqlite3* (*proxy_sqlite3_db_handle)(sqlite3_stmt*) = sqlite3_db_handle;
int (*proxy_sqlite3_enable_load_extension)(sqlite3*, int) = sqlite3_enable_load_extension;
int (*proxy_sqlite3_auto_extension)(void(*)(void)) = sqlite3_auto_extension;
const char *(*proxy_sqlite3_errmsg)(sqlite3*) = sqlite3_errmsg;
int (*proxy_sqlite3_finalize)(sqlite3_stmt *) = sqlite3_finalize;
int (*proxy_sqlite3_reset)(sqlite3_stmt *) = sqlite3_reset;
int (*proxy_sqlite3_clear_bindings)(sqlite3_stmt*) = sqlite3_clear_bindings;
int (*proxy_sqlite3_close_v2)(sqlite3*) = sqlite3_close_v2;
int (*proxy_sqlite3_get_autocommit)(sqlite3*) = sqlite3_get_autocommit;
void (*proxy_sqlite3_free)(void*) = sqlite3_free;
int (*proxy_sqlite3_status)(int, int*, int*, int) = sqlite3_status;
int (*proxy_sqlite3_status64)(int, long long*, long long*, int) = sqlite3_status64;
int (*proxy_sqlite3_changes)(sqlite3*) = sqlite3_changes;
long long (*proxy_sqlite3_total_changes64)(sqlite3*) = sqlite3_total_changes64;
int (*proxy_sqlite3_step)(sqlite3_stmt*) = sqlite3_step;
int (*proxy_sqlite3_config)(int, ...) = sqlite3_config;
int (*proxy_sqlite3_shutdown)(void) = sqlite3_shutdown;
int (*proxy_sqlite3_prepare_v2)(sqlite3*, const char*, int, sqlite3_stmt**, const char**) = sqlite3_prepare_v2;
int (*proxy_sqlite3_open_v2)(const char*, sqlite3**, int, const char*) = sqlite3_open_v2;
int (*proxy_sqlite3_exec)(sqlite3*, const char*, int (*)(void*,int,char**,char**), void*, char**) = sqlite3_exec;

// Hook for sqlite-vec.  Gated on PROXYSQL40: vec.o + sqlite-vec.h
// only get built (deps/Makefile) and linked (src/Makefile) when the
// v4.0 plugin chassis is enabled.  Non-genai v3.0/v3.1 release
// binaries don't carry the vector-search extension; the genai plugin's
// AI_Vector_Storage is the only consumer of the hook anyway.
#ifdef PROXYSQL40
#include "sqlite-vec.h"
int (*proxy_sqlite3_vec_init)(sqlite3*, char**, const sqlite3_api_routines*) = sqlite3_vec_init;
#endif /* PROXYSQL40 */

// Internal helpers used by admin stats batching; keep defaults as NULL
void (*proxy_sqlite3_global_stats_row_step)(SQLite3DB*, sqlite3_stmt*, const char*, ...) = NULL;
