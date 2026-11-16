#pragma once
// Internal C++17 PostgreSQL parameter-datum decoder for the shared embedded
// prepared-statement frontend. This is not a plugin ABI.
//
// The decoder consumes exactly one already-framed PostgreSQL Bind parameter
// value: the resolved parameter OID, the selected text(0)/binary(1) format,
// and the raw datum pointer/length. Packet framing, OID inference, parameter
// format expansion and protocol callbacks belong to the caller. This module
// performs no SQL parsing, engine access, network I/O or protocol I/O.
//
// Supported scalar OID/format pairs:
//   INT2/INT4/INT8      text and binary -> int64_t (exact type ranges)
//   FLOAT4/FLOAT8       text and binary -> double
//   TEXT/VARCHAR/BPCHAR text and binary -> Text (strictly validated UTF-8)
//   BYTEA               text and binary -> Bytes
//   NUMERIC             text only       -> Decimal (canonical fixed point)
//
// BOOL, temporal types, arrays, UUID, JSON, binary NUMERIC and all other OIDs
// are rejected with SQLSTATE 0A000. This decoder intentionally does not claim
// full PostgreSQL type coverage; additional families belong to later work.
//
// NULL is length -1. A known supported OID is still required for NULL because
// the caller resolves OID inference first. A zero length with a null data
// pointer is a valid empty non-NULL value; a positive length with a null data
// pointer is malformed (08P01).
//
// Binary integers must be exactly 2/4/8 bytes in big-endian order and are
// sign-extended into int64_t without implementation-defined narrowing.
// Binary floating-point values must be exactly 4/8 bytes of IEEE-754
// big-endian, are reconstructed through their exact bit pattern, and are
// widened to double while preserving negative zero, NaN and infinities. The
// supported target platforms are assumed to use IEEE-754 float/double; byte
// order conversion is explicit here.
//
// Text values are owned raw UTF-8 bytes. Embedded NUL, overlong forms,
// surrogate code points, truncated sequences and code points above U+10FFFF
// are rejected with SQLSTATE 22021. No automatic encoding conversion is done;
// the frontend must establish a UTF-8 connection context.
//
// BYTEA text follows PostgreSQL's byteain: the \x hex form (with ASCII space,
// tab, CR or LF between complete pairs) and the legacy backslash/octal form
// are supported. Malformed hex, odd nibble counts, trailing backslashes and
// out-of-range or otherwise invalid escapes are rejected with 22P02 rather
// than silently discarded or coerced.
//
// NUMERIC text accepts finite fixed-point syntax only (optional ASCII
// whitespace, optional sign, decimal digits and at most one decimal point).
// Leading zeroes, a leading decimal point, a trailing decimal point and a
// leading plus sign are normalized to a canonical exact fixed-point string;
// fractional scale and non-zero digits are preserved exactly. Valid
// PostgreSQL exponent, non-finite, digit-separated and prefixed non-decimal integer forms are
// refused explicitly with 0A000 instead of being mis-classified as syntax
// errors. No float conversion and no DuckDB-scale clamping occurs in this core
// decoder. Separator-bearing forms are classified without full grammar validation.
// Floating-point NaN payload forms are also refused with 0A000.
//
// `budget` bounds the raw input datum and any produced Text/Bytes/Decimal
// payload. The raw length is checked before the data pointer is touched, and
// NUMERIC normalization is sized before the output string grows. Allocation
// failure maps to 53200; budget or length exhaustion maps to 54000. On
// failure `out` is std::monostate.
//
// Aliasing: `data` may point into out.Text.bytes or out.Bytes.bytes. `out` is
// not cleared on entry. Decoding uses a local Value, all input bytes are read
// before a successful commit, and a failed call clears `out` only after input
// reads have finished (RAII), never leaving a partial result.
#include <cstddef>
#include <cstdint>

#include "Embedded_Execution.h"

namespace embedded {

// PostgreSQL type OIDs supported by this scalar decoder. These are the
// pg_type OIDs sent by clients in Parse/Describe metadata.
inline constexpr uint32_t pgsql_oid_bytea = 17;
inline constexpr uint32_t pgsql_oid_int8 = 20;
inline constexpr uint32_t pgsql_oid_int2 = 21;
inline constexpr uint32_t pgsql_oid_int4 = 23;
inline constexpr uint32_t pgsql_oid_text = 25;
inline constexpr uint32_t pgsql_oid_float4 = 700;
inline constexpr uint32_t pgsql_oid_float8 = 701;
inline constexpr uint32_t pgsql_oid_bpchar = 1042;
inline constexpr uint32_t pgsql_oid_varchar = 1043;
inline constexpr uint32_t pgsql_oid_numeric = 1700;

// UTF-8 text validation shared with result encoding; embedded NUL is invalid.
bool pgsql_utf8_text_valid(const unsigned char*, size_t) noexcept;

// Decode one PostgreSQL parameter datum into the shared Value model.
//
// format is 0 (text) or 1 (binary). length is the raw datum length (INT32_MAX
// or less), or -1 for SQL NULL. `data` may be null only when length is 0.
//
// On success returns an empty Status and commits an owned alternative to
// `out`: int64_t, double, Text, Bytes, Decimal, or monostate for NULL.
// On failure returns an Error with an appropriate kind and SQLSTATE and leaves
// `out` holding std::monostate.
Status pgsql_decode_parameter(
    uint32_t oid, int16_t format, const unsigned char* data, int32_t length,
    Value& out, size_t budget = 16u * 1024u * 1024u);

}  // namespace embedded
