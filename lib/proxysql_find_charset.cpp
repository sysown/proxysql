#include "proxysql_find_charset.h"

//                            'proxysql_structs.h'
///////////////////////////////////////////////////////////////////////////////
#include <cstdint>
#include "openssl/ssl.h"
#include "proxysql_structs.h"
///////////////////////////////////////////////////////////////////////////////

#include <string.h>

const MARIADB_CHARSET_INFO * proxysql_find_charset_nr(unsigned int nr) {
	const MARIADB_CHARSET_INFO * c = mariadb_compiled_charsets;
	do {
		if (c->nr == nr) {
			return c;
		}
		++c;
	} while (c[0].nr != 0);
	return NULL;
}

/**
 * @brief Finds the default (first) collation for the supplied 'charset name'.
 * @details Previously, this function just returned the first collation found (default). Since v2.5.3, this
 *   function takes into consideration the thread variable 'SQL_COLLATION_CONNECTION'
 *   ('mysql-default_collation_connection'). This was introduced for being able to serve the same default
 *   collation as the server (for bootstrap mode) in case it's detected to be a MySQL 8
 *   ('utf8mb4_0900_ai_ci'), instead of the retrocompatible default collation ('utf8mb4_general_ci'). This
 *   change also allows users to select the default collation that they please for a particular charset, if
 *   the collection specified via 'mysql-default_collation_connection', isn't found, the first found collation
 *   (original default) will be retrieved.
 * @param name The 'charset name' for which to find the default collation.
 * @return The collation found, NULL if none is find.
 */
MARIADB_CHARSET_INFO * proxysql_find_charset_name(const char *name_) {
	const char* default_collation = mysql_thread___default_variables[SQL_COLLATION_CONNECTION];
	MARIADB_CHARSET_INFO *c = (MARIADB_CHARSET_INFO *)mariadb_compiled_charsets;
	MARIADB_CHARSET_INFO* charset_collation = nullptr;

	const char *name;
	if (strcasecmp(name_,(const char *)"utf8mb3")==0) {
		name = (const char *)"utf8";
	} else {
		name = name_;
	}

	do {
		if (!strcasecmp(c->csname, name)) {
			if (charset_collation == nullptr) {
				charset_collation = c;
			}

			if (default_collation == nullptr) {
				charset_collation = c;
				break;
			} else {
				if (!strcmp(default_collation, c->name)) {
					charset_collation = c;
					break;
				}
			}
		}
		++c;
	} while (c[0].nr != 0);

	return charset_collation;
}

/**
 * @brief Find charset and collation information based on the given charset name and collation name.
 *
 * This function searches for charset and collation information in the compiled charsets based on the provided
 * charset name and collation name. It performs case-insensitive comparisons to find a match.
 *
 * @param csname_ The name of the charset.
 * @param collatename_ The name of the collation.
 * @return A pointer to the MARIADB_CHARSET_INFO structure representing the charset and collation information
 *         if a match is found. If no matching charset and collation are found, it returns NULL.
 */
MARIADB_CHARSET_INFO * proxysql_find_charset_collate_names(const char *csname_, const char *collatename_) {
	MARIADB_CHARSET_INFO *c = (MARIADB_CHARSET_INFO *)mariadb_compiled_charsets;
	char buf[64];
	const char *csname;
	const char *collatename;
	if (strcasecmp(csname_,(const char *)"utf8mb3")==0) {
		csname = (const char *)"utf8";
	} else {
		csname = csname_;
	}
	if (strncasecmp(collatename_,(const char *)"utf8mb3", 7)==0) {
		memcpy(buf,(const char *)"utf8",4);
		strcpy(buf+4,collatename_+7);
		collatename = buf;
	} else {
		collatename = collatename_;
	}
	do {
		if (!strcasecmp(c->csname, csname) && !strcasecmp(c->name, collatename)) {
			return c;
		}
		++c;
	} while (c[0].nr != 0);
	return NULL;
}

/**
 * @brief Find charset and collation information based on the given collation name.
 *
 * This function searches for charset and collation information in the compiled charsets based on the provided
 * collation name. It performs case-insensitive comparisons to find a match.
 *
 * @param collatename The name of the collation to search for.
 * @return A pointer to the MARIADB_CHARSET_INFO structure representing the charset and collation information
 *         if a match is found. If no matching collation is found, it returns NULL.
 */
MARIADB_CHARSET_INFO * proxysql_find_charset_collate(const char *collatename) {
	MARIADB_CHARSET_INFO *c = (MARIADB_CHARSET_INFO *)mariadb_compiled_charsets;
	do {
		if (!strcasecmp(c->name, collatename)) {
			return c;
		}
		++c;
	} while (c[0].nr != 0);
	return NULL;
}
