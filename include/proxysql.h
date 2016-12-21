#ifndef PROXYSQL_H__
#define PROXYSQL_H__
#ifdef NDEBUG
#undef NDEBUG
#endif

#include "proxysql_structs.h"
#include "proxysql_macros.h"

#ifdef DEBUG
//#define VALGRIND_ENABLE_ERROR_REPORTING
//#define VALGRIND_DISABLE_ERROR_REPORTING
#include "valgrind.h"
#else
#define VALGRIND_ENABLE_ERROR_REPORTING
#define VALGRIND_DISABLE_ERROR_REPORTING
#endif /* DEBUG */

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_VERSION	GITVERSION DEB
#define PROXYSQL_CODENAME	"Truls"

#ifndef PROXYSQL_FUNC_DEFS
#define PROXYSQL_FUNC_DEFS

int config_file_is_readable(char *);
unsigned int CPY3(unsigned char *);

int pkt_ok(unsigned char *, unsigned int);
int pkt_end(unsigned char *, unsigned int);
int pkt_com_query(unsigned char *, unsigned int);
enum MySQL_response_type mysql_response(unsigned char *, unsigned int);

#ifdef DEBUG
void init_debug_struct();
void init_debug_struct_from_cmdline();
void proxy_debug_func(enum debug_module, int, int, const char *, int, const char *, const char *, ...);
#endif

#endif /* PROXYSQL_FUNC_DEFS */
#endif // PROXYSQL_H__
