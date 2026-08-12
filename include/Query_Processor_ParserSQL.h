/**
 * @file Query_Processor_ParserSQL.h
 * @brief Adapter layer between the standalone ParserSQL library and ProxySQL's query processor.
 *
 * @details This header declares the three capabilities that ParserSQL provides to ProxySQL:
 *
 *   1. **Digest generation** — produces a normalized query text and a 64-bit hash, compatible
 *      with ProxySQL's existing SpookyHash-based digest infrastructure.
 *   2. **Command type detection** — classifies a query as SELECT, INSERT, SET, etc., mapping
 *      ParserSQL's internal `StmtType` enum to ProxySQL's `MYSQL_COM_QUERY_command` /
 *      `PGSQL_QUERY_command` enums.
 *   3. **SET statement parsing** — walks the AST of a SET statement to extract variable-value
 *      pairs, producing the same `map<string, vector<string>>` format used by ProxySQL's
 *      regex-based `MySQL_Set_Stmt_Parser`.
 *
 * These capabilities are toggled at runtime by two global variables:
 *
 *   - `mysql-query_processor_parser` (0 or 1): enables ParserSQL as the query parser instead
 *     of the default tokenizer-based implementation (c_tokenizer / pgsql_tokenizer).
 *   - `mysql-set_parser_algorithm` (1, 2, or 3): selects the SET parsing backend (1 = legacy
 *     regex, 2 = ProxySQL's internal parser, 3 = ParserSQL).
 *
 * The ParserSQL library is vendored as a static library; both repositories remain independent.
 * Thread safety is achieved through per-thread parser instances (`thread_local`), so none of
 * the functions declared here require external synchronization.
 */

#ifndef PROXYSQL_QUERY_PROCESSOR_PARSERSQL_H
#define PROXYSQL_QUERY_PROCESSOR_PARSERSQL_H

#include "MySQL_User_Variables.h"
#include "proxysql_structs.h"
#include <map>
#include <string>
#include <vector>

/**
 * @brief Computes a query digest using the MySQL-flavour ParserSQL parser.
 *
 * Parses the query, normalizes it into digest text (replacing literals with
 * placeholders), and stores both the normalized text and its SpookyHash in
 * `qp->digest_text` / `qp->digest`.
 *
 * Controlled by `mysql-query_processor_parser`.
 *
 * @param qp           Output structure. `digest_text`, `first_comment`, and
 *                      `query_prefix` are set; `digest` receives the 64-bit hash.
 * @param query         Raw SQL query bytes.
 * @param query_length  Length of `query` in bytes.
 */
void parsersql_digest_init_mysql(SQP_par_t* qp, const char* query, int query_length);

/**
 * @brief Computes a query digest using the PostgreSQL-flavour ParserSQL parser.
 *
 * Identical to parsersql_digest_init_mysql() but targets PostgreSQL syntax.
 *
 * Controlled by `mysql-query_processor_parser`.
 *
 * @param qp           Output structure (see parsersql_digest_init_mysql).
 * @param query         Raw SQL query bytes.
 * @param query_length  Length of `query` in bytes.
 */
void parsersql_digest_init_pgsql(SQP_par_t* qp, const char* query, int query_length);

/**
 * @brief Classifies a MySQL query by its command type.
 *
 * Parses the query and maps the resulting StmtType to a
 * `MYSQL_COM_QUERY_command` enum value (e.g. MYSQL_COM_QUERY_SELECT).
 * Returns MYSQL_COM_QUERY_UNKNOWN for unrecognised statements.
 *
 * Controlled by `mysql-query_processor_parser`.
 *
 * @param query         Raw SQL query bytes.
 * @param query_length  Length of `query` in bytes.
 * @return              The detected command type.
 */
enum MYSQL_COM_QUERY_command parsersql_command_type_mysql(const char* query, int query_length);

/**
 * @brief Classifies a PostgreSQL query by its command type.
 *
 * Parses the query and maps the resulting StmtType to a
 * `PGSQL_QUERY_command` enum value. Returns PGSQL_QUERY_UNKNOWN for
 * unrecognised statements.
 *
 * Controlled by `mysql-query_processor_parser`.
 *
 * @param query         Raw SQL query bytes.
 * @param query_length  Length of `query` in bytes.
 * @return              The detected command type.
 */
enum PGSQL_QUERY_command parsersql_command_type_pgsql(const char* query, int query_length);

/**
 * @brief Parses a MySQL SET statement into variable-value pairs.
 *
 * Walks the AST produced by the MySQL ParserSQL parser and extracts each
 * `SET var = value` assignment into a `map<string, vector<string>>`, matching
 * the output format of ProxySQL's regex-based `MySQL_Set_Stmt_Parser`.
 * Variable names are normalised (lowercased, scope prefixes stripped, legacy
 * aliases resolved).
 *
 * Controlled by `mysql-set_parser_algorithm` (value 3).
 *
 * @param query  The SET statement to parse.
 * @return       Map from normalised variable name to its value(s). Empty map
 *               if the query is not a valid SET statement.
 */
std::map<std::string, std::vector<std::string>> parsersql_parse_set_mysql(const std::string& query);

/**
 * @brief Parses a PostgreSQL SET statement into variable-value pairs.
 *
 * Identical to parsersql_parse_set_mysql() but targets PostgreSQL syntax.
 *
 * Controlled by `mysql-set_parser_algorithm` (value 3).
 *
 * @param query  The SET statement to parse.
 * @return       Map from normalised variable name to its value(s). Empty map
 *               if the query is not a valid SET statement.
 */
std::map<std::string, std::vector<std::string>> parsersql_parse_set_pgsql(const std::string& query);

#endif
