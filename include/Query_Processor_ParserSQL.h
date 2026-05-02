#ifndef PROXYSQL_QUERY_PROCESSOR_PARSERSQL_H
#define PROXYSQL_QUERY_PROCESSOR_PARSERSQL_H

#include "proxysql_structs.h"
#include <map>
#include <string>
#include <vector>

void parsersql_digest_init_mysql(SQP_par_t* qp, const char* query, int query_length);
void parsersql_digest_init_pgsql(SQP_par_t* qp, const char* query, int query_length);

enum MYSQL_COM_QUERY_command parsersql_command_type_mysql(const char* query, int query_length);
enum PGSQL_QUERY_command parsersql_command_type_pgsql(const char* query, int query_length);

std::map<std::string, std::vector<std::string>> parsersql_parse_set_mysql(const std::string& query);
std::map<std::string, std::vector<std::string>> parsersql_parse_set_pgsql(const std::string& query);

#endif
