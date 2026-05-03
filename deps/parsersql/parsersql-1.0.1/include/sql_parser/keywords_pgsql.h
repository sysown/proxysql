#ifndef SQL_PARSER_KEYWORDS_PGSQL_H
#define SQL_PARSER_KEYWORDS_PGSQL_H

#include "sql_parser/token.h"
#include "sql_parser/keyword_hash.h"

namespace sql_parser {
namespace pgsql_keywords {

struct KeywordEntry {
    const char* text;
    uint8_t len;
    TokenType token;
};

inline constexpr KeywordEntry KEYWORDS[] = {
    {"ALL", 3, TokenType::TK_ALL},
    {"ALTER", 5, TokenType::TK_ALTER},
    {"ANALYZE", 7, TokenType::TK_ANALYZE},
    {"AND", 3, TokenType::TK_AND},
    {"ARRAY", 5, TokenType::TK_ARRAY},
    {"AS", 2, TokenType::TK_AS},
    {"ASC", 3, TokenType::TK_ASC},
    {"AVG", 3, TokenType::TK_AVG},
    {"BEGIN", 5, TokenType::TK_BEGIN},
    {"BETWEEN", 7, TokenType::TK_BETWEEN},
    {"BUFFERS", 7, TokenType::TK_BUFFERS},
    {"BY", 2, TokenType::TK_BY},
    {"CALL", 4, TokenType::TK_CALL},
    {"CASE", 4, TokenType::TK_CASE},
    {"CHARACTER", 9, TokenType::TK_CHARACTER},
    {"COLLATE", 7, TokenType::TK_COLLATE},
    {"COLUMNS", 7, TokenType::TK_COLUMNS},
    {"COMMIT", 6, TokenType::TK_COMMIT},
    {"COMMITTED", 9, TokenType::TK_COMMITTED},
    {"CONFLICT", 8, TokenType::TK_CONFLICT},
    {"CONSTRAINT", 10, TokenType::TK_CONSTRAINT},
    {"COSTS", 5, TokenType::TK_COSTS},
    {"COUNT", 5, TokenType::TK_COUNT},
    {"CREATE", 6, TokenType::TK_CREATE},
    {"CROSS", 5, TokenType::TK_CROSS},
    {"DATA", 4, TokenType::TK_DATA},
    {"DATABASE", 8, TokenType::TK_DATABASE},
    {"DEALLOCATE", 10, TokenType::TK_DEALLOCATE},
    {"DEFAULT", 7, TokenType::TK_DEFAULT},
    {"DELETE", 6, TokenType::TK_DELETE},
    {"DENSE_RANK", 10, TokenType::TK_DENSE_RANK},
    {"DESC", 4, TokenType::TK_DESC},
    {"DESCRIBE", 8, TokenType::TK_DESCRIBE},
    {"DISTINCT", 8, TokenType::TK_DISTINCT},
    {"DO", 2, TokenType::TK_DO},
    {"DROP", 4, TokenType::TK_DROP},
    {"ELSE", 4, TokenType::TK_ELSE},
    {"END", 3, TokenType::TK_END},
    {"EXCEPT", 6, TokenType::TK_EXCEPT},
    {"EXECUTE", 7, TokenType::TK_EXECUTE},
    {"EXISTS", 6, TokenType::TK_EXISTS},
    {"EXPLAIN", 7, TokenType::TK_EXPLAIN},
    {"FALSE", 5, TokenType::TK_FALSE},
    {"FETCH", 5, TokenType::TK_FETCH},
    {"FIRST_VALUE", 11, TokenType::TK_FIRST_VALUE},
    {"FOR", 3, TokenType::TK_FOR},
    {"FORMAT", 6, TokenType::TK_FORMAT},
    {"FROM", 4, TokenType::TK_FROM},
    {"FULL", 4, TokenType::TK_FULL},
    {"GRANT", 5, TokenType::TK_GRANT},
    {"GROUP", 5, TokenType::TK_GROUP},
    {"HAVING", 6, TokenType::TK_HAVING},
    {"IF", 2, TokenType::TK_IF},
    {"IN", 2, TokenType::TK_IN},
    {"INDEX", 5, TokenType::TK_INDEX},
    {"INNER", 5, TokenType::TK_INNER},
    {"INSERT", 6, TokenType::TK_INSERT},
    {"INTERSECT", 9, TokenType::TK_INTERSECT},
    {"INTO", 4, TokenType::TK_INTO},
    {"IS", 2, TokenType::TK_IS},
    {"ISOLATION", 9, TokenType::TK_ISOLATION},
    {"JOIN", 4, TokenType::TK_JOIN},
    {"LAG", 3, TokenType::TK_LAG},
    {"LAST_VALUE", 10, TokenType::TK_LAST_VALUE},
    {"LEAD", 4, TokenType::TK_LEAD},
    {"LEFT", 4, TokenType::TK_LEFT},
    {"LEVEL", 5, TokenType::TK_LEVEL},
    {"LIKE", 4, TokenType::TK_LIKE},
    {"LIMIT", 5, TokenType::TK_LIMIT},
    {"LOAD", 4, TokenType::TK_LOAD},
    {"LOCAL", 5, TokenType::TK_LOCAL},
    {"LOCK", 4, TokenType::TK_LOCK},
    {"MAX", 3, TokenType::TK_MAX},
    {"MIN", 3, TokenType::TK_MIN},
    {"NAMES", 5, TokenType::TK_NAMES},
    {"NATURAL", 7, TokenType::TK_NATURAL},
    {"NOT", 3, TokenType::TK_NOT},
    {"NOTHING", 7, TokenType::TK_NOTHING},
    {"NULL", 4, TokenType::TK_NULL},
    {"OF", 2, TokenType::TK_OF},
    {"OFFSET", 6, TokenType::TK_OFFSET},
    {"ON", 2, TokenType::TK_ON},
    {"ONLY", 4, TokenType::TK_ONLY},
    {"OR", 2, TokenType::TK_OR},
    {"ORDER", 5, TokenType::TK_ORDER},
    {"OUTER", 5, TokenType::TK_OUTER},
    {"OVER", 4, TokenType::TK_OVER},
    {"PARTITION", 9, TokenType::TK_PARTITION},
    {"PREPARE", 7, TokenType::TK_PREPARE},
    {"PROCEDURE", 9, TokenType::TK_PROCEDURE},
    {"RANK", 4, TokenType::TK_RANK},
    {"READ", 4, TokenType::TK_READ},
    {"RECURSIVE", 9, TokenType::TK_RECURSIVE},
    {"REPEATABLE", 10, TokenType::TK_REPEATABLE},
    {"RESET", 5, TokenType::TK_RESET},
    {"RETURNING", 9, TokenType::TK_RETURNING},
    {"REVOKE", 6, TokenType::TK_REVOKE},
    {"RIGHT", 5, TokenType::TK_RIGHT},
    {"ROLLBACK", 8, TokenType::TK_ROLLBACK},
    {"ROW", 3, TokenType::TK_ROW},
    {"ROW_NUMBER", 10, TokenType::TK_ROW_NUMBER},
    {"SAVEPOINT", 9, TokenType::TK_SAVEPOINT},
    {"SCHEMA", 6, TokenType::TK_SCHEMA},
    {"SELECT", 6, TokenType::TK_SELECT},
    {"SERIALIZABLE", 12, TokenType::TK_SERIALIZABLE},
    {"SESSION", 7, TokenType::TK_SESSION},
    {"SET", 3, TokenType::TK_SET},
    {"SETTINGS", 8, TokenType::TK_SETTINGS},
    {"SHARE", 5, TokenType::TK_SHARE},
    {"SHOW", 4, TokenType::TK_SHOW},
    {"START", 5, TokenType::TK_START},
    {"SUM", 3, TokenType::TK_SUM},
    {"SUMMARY", 7, TokenType::TK_SUMMARY},
    {"TABLE", 5, TokenType::TK_TABLE},
    {"THEN", 4, TokenType::TK_THEN},
    {"TIMING", 6, TokenType::TK_TIMING},
    {"TO", 2, TokenType::TK_TO},
    {"TRANSACTION", 11, TokenType::TK_TRANSACTION},
    {"TRUE", 4, TokenType::TK_TRUE},
    {"TRUNCATE", 8, TokenType::TK_TRUNCATE},
    {"UNION", 5, TokenType::TK_UNION},
    {"UNCOMMITTED", 11, TokenType::TK_UNCOMMITTED},
    {"UNLOCK", 6, TokenType::TK_UNLOCK},
    {"UPDATE", 6, TokenType::TK_UPDATE},
    {"USE", 3, TokenType::TK_USE},
    {"USING", 5, TokenType::TK_USING},
    {"VALUES", 6, TokenType::TK_VALUES},
    {"VERBOSE", 7, TokenType::TK_VERBOSE},
    {"VIEW", 4, TokenType::TK_VIEW},
    {"WAL", 3, TokenType::TK_WAL},
    {"WHEN", 4, TokenType::TK_WHEN},
    {"WHERE", 5, TokenType::TK_WHERE},
    {"WITH", 4, TokenType::TK_WITH},
    {"WRITE", 5, TokenType::TK_WRITE},
};

inline constexpr size_t KEYWORD_COUNT = sizeof(KEYWORDS) / sizeof(KEYWORDS[0]);

inline keyword_hash::HashEntry HASH_TABLE[keyword_hash::TABLE_SIZE];
inline bool HASH_TABLE_INIT = [] {
    keyword_hash::build_table(KEYWORDS, HASH_TABLE);
    return true;
}();

inline TokenType lookup(const char* text, uint32_t len) {
    return keyword_hash::lookup_in_table(HASH_TABLE, text, len);
}

} // namespace pgsql_keywords
} // namespace sql_parser

#endif // SQL_PARSER_KEYWORDS_PGSQL_H
