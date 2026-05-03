#ifndef SQL_PARSER_PARSER_H
#define SQL_PARSER_PARSER_H

#include "sql_parser/common.h"
#include "sql_parser/arena.h"
#include "sql_parser/tokenizer.h"
#include "sql_parser/ast.h"
#include "sql_parser/parse_result.h"
#include "sql_parser/stmt_cache.h"

namespace sql_parser {

struct ParserConfig {
    size_t arena_block_size = 65536;    // 64KB
    size_t arena_max_size = 1048576;    // 1MB
    size_t stmt_cache_capacity = 128;
};

template <Dialect D>
class Parser {
public:
    explicit Parser(const ParserConfig& config = {});
    ~Parser() = default;

    // Non-copyable, non-movable
    Parser(const Parser&) = delete;
    Parser& operator=(const Parser&) = delete;

    // Parse a SQL string. Returns ParseResult with classification, AST, and
    // statement metadata when parsing succeeds.
    ParseResult parse(const char* sql, size_t len);

    // Reset the arena. Call after each query is fully processed.
    void reset();

    // Access the arena (for emitter use)
    Arena& arena() { return arena_; }

    // Prepared statement support
    ParseResult parse_and_cache(const char* sql, size_t len, uint32_t stmt_id);
    ParseResult execute(uint32_t stmt_id, const ParamBindings& params);
    void prepare_cache_evict(uint32_t stmt_id);

private:
    Arena arena_;
    Tokenizer<D> tokenizer_;
    StmtCache stmt_cache_;

    // Classifier: dispatches to the right extractor/parser
    ParseResult classify_and_dispatch();

    // Tier 1 parsers
    ParseResult parse_select();
    ParseResult parse_select_from_lparen();
    ParseResult parse_with();
    ParseResult parse_set();
    ParseResult parse_insert(bool is_replace = false);
    ParseResult parse_update();
    ParseResult parse_delete();
    ParseResult parse_explain(bool is_describe = false);
    ParseResult parse_call();
    ParseResult parse_do();
    ParseResult parse_load_data();

    // Tier 2 extractors
    ParseResult extract_insert(const Token& first);
    ParseResult extract_update(const Token& first);
    ParseResult extract_delete(const Token& first);
    ParseResult extract_replace(const Token& first);
    ParseResult extract_transaction(const Token& first);
    ParseResult extract_use(const Token& first);
    ParseResult extract_show(const Token& first);
    ParseResult extract_prepare(const Token& first);
    ParseResult extract_execute(const Token& first);
    ParseResult extract_deallocate(const Token& first);
    ParseResult extract_ddl(const Token& first);
    ParseResult extract_acl(const Token& first);
    ParseResult extract_lock(const Token& first);
    // extract_load removed -- replaced by parse_load_data()
    ParseResult extract_reset(const Token& first);
    ParseResult extract_unknown(const Token& first);

    // Helpers
    // Read optional schema.table or just table. Returns table token.
    // If qualified (schema.table), sets schema_out.
    Token read_table_name(StringRef& schema_out);

    // Scan forward to semicolon or EOF, set result.remaining
    void scan_to_end(ParseResult& result);
};

} // namespace sql_parser

#endif // SQL_PARSER_PARSER_H
