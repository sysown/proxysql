#ifndef SQL_PARSER_PARSE_RESULT_H
#define SQL_PARSER_PARSE_RESULT_H

#include "sql_parser/common.h"
#include "sql_parser/ast.h"

namespace sql_parser {

struct ErrorInfo {
    uint32_t offset = 0;
    StringRef message;
};

struct BoundValue {
    enum Type : uint8_t { INT, FLOAT, DOUBLE, STRING, BLOB, NULL_VAL, DATETIME, DECIMAL };
    Type type = NULL_VAL;
    union {
        int64_t int_val;
        float float32_val;
        double float64_val;
        StringRef str_val;
    };

    BoundValue() : type(NULL_VAL), int_val(0) {}
    BoundValue(const BoundValue&) = default;
    BoundValue& operator=(const BoundValue&) = default;
};

struct ParamBindings {
    BoundValue* values = nullptr;
    uint16_t count = 0;
};

struct ParseResult {
    enum Status : uint8_t { OK = 0, PARTIAL, ERROR };

    Status status = ERROR;
    StmtType stmt_type = StmtType::UNKNOWN;
    AstNode* ast = nullptr;
    ErrorInfo error;
    StringRef remaining;

    StringRef table_name;
    StringRef schema_name;
    StringRef database_name;

    ParamBindings bindings;    // populated by execute()

    bool ok() const { return status == OK; }
    bool has_remaining() const { return !remaining.empty(); }
};

} // namespace sql_parser

#endif // SQL_PARSER_PARSE_RESULT_H
