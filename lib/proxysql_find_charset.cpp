#include "proxysql_find_charset.h"
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

MARIADB_CHARSET_INFO * proxysql_find_charset_name(const char *name_) {
	MARIADB_CHARSET_INFO *c = (MARIADB_CHARSET_INFO *)mariadb_compiled_charsets;
	const char *name;
	if (strcasecmp(name_,(const char *)"utf8mb3")==0) {
		name = (const char *)"utf8";
	} else {
		name = name_;
	}
	do {
		if (!strcasecmp(c->csname, name)) {
			return c;
		}
		++c;
	} while (c[0].nr != 0);
	return NULL;
}

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
