#include "mysql.h"
#include "mariadb_com.h"

MARIADB_CHARSET_INFO * proxysql_find_charset_name(const char * const name);
MARIADB_CHARSET_INFO * proxysql_find_charset_collate_names(const char *csname, const char *collatename);
const MARIADB_CHARSET_INFO * proxysql_find_charset_nr(unsigned int nr);
MARIADB_CHARSET_INFO * proxysql_find_charset_collate(const char *collatename);
