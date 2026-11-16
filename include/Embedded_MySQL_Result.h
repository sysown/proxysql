#pragma once
// Internal C++17 MySQL binary-result metadata and row-payload codec for the
// embedded prepared-statement slice. This is not a plugin ABI.
//
// The codec consumes the typed Value/Type/Column model from
// Embedded_Execution.h and produces only the binary-row PAYLOAD. The caller
// owns packet framing: MySQL packet header, sequence id, and fragmentation.
//
// Dynamic-column policy:
//  * TypeKind::dynamic describes engines such as SQLite whose prepare-time
//    result metadata has no fixed wire type. Dynamic columns advertise
//    MYSQL_TYPE_VAR_STRING with BINARY_FLAG. Every non-NULL dynamic value is
//    rendered as its exact text representation: integers and floating-point
//    values through std::to_chars (shortest round-trippable form for doubles),
//    Text/Bytes as their raw bytes, Decimal as its exact text, and bool as 0/1. This keeps
//    SQLite's value-preserving text view without silently choosing a numeric
//    wire encoding from the runtime value.
//  * Fixed typed descriptors retain their native MySQL wire encodings:
//    one-byte booleans, eight-byte little-endian signed/unsigned integers and doubles, and
//    length-encoded text/blob/decimal payloads.
//  * NULL is the empty Value alternative and is represented only in the row's
//    NULL bitmap. Empty text/blob/decimal values remain non-NULL zero-length
//    values. NULL in a NOT NULL column is rejected.
//  * Temporal result types remain unsupported.
//
// All operations are allocation-local and perform no SQL execution, engine
// access, or protocol I/O. On error both output parameters are left empty.
//
// Row encoding supports `payload` aliasing a Bytes value in `row`: the output
// is not cleared on entry, all input bytes are read into a local buffer, and
// only a successful encoding is swapped into `payload`. A failed encoding
// clears `payload` on return (which also clears the aliased row value), never
// producing a partial payload.
#include <cstdint>
#include <string>
#include <vector>

#include <mysql.h>

#include "Embedded_Execution.h"
#include "MySQL_encode.h"

namespace embedded {

// Internal field metadata derived from one typed result Column. It carries
// the subset needed by a later MySQL column-definition emitter.
struct MySQLColumn {
    TypeKind kind;
    bool nullable;
    std::string name;
    uint8_t wire_type;
    uint16_t charset;
    uint16_t flags;
    uint32_t length;
    uint8_t decimals;
};

// Translate typed result columns into MySQL field metadata. Dynamic columns
// are intentionally described as binary VAR_STRING; no runtime row value is
// inspected here. Decimal precision/scale and embedded-NUL names are
// validated. At most 65535 columns are accepted.
Status mysql_describe_columns(const std::vector<Column>& columns,
                              std::vector<MySQLColumn>& out);

// Encode one binary result-row payload from a typed descriptor and row.
// Validates arity, fixed-type alternatives, NULL policy, and the complete
// payload size before producing output. Payload layout is:
//   0x00 | NULL bitmap[(columns + 9) / 8] | value payloads
// The bitmap is zero-based and uses column index + 2. NULL columns add no
// value bytes. Output is swapped only on success.
Status mysql_encode_binary_row(const std::vector<MySQLColumn>& columns,
                               const Row& row,
                               std::vector<unsigned char>& payload,
                               size_t max_payload = 64u * 1024u * 1024u);

}  // namespace embedded
