#ifndef PROXYSQL_SQLITE3EXTS_H
#define PROXYSQL_SQLITE3EXTS_H

#include "sqlite3.h"

int sqlite3_extensions_init(sqlite3 *db, char** errmsg, const sqlite3_api_routines* api);

#endif
