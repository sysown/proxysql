# Issue #6119: PCRE2 query-rule migration

## Goal

Replace the vendored, end-of-life PCRE 8.45 engine and its `pcrecpp` wrapper
with vendored PCRE2 10.47 for the PCRE query-rule mode. Preserve the existing
MySQL and PostgreSQL query-rule interface and behavior.

## Scope

The change covers the PCRE-backed branch of the shared query-processor code.
`mysql-query_processor_regex=2` and `pgsql-query_processor_regex=2` continue
to select RE2; every other value continues to select the PCRE-compatible
engine, now PCRE2.

The project will continue to build the regex engine from `deps`. It will not
use a system PCRE2 package or add a distro runtime dependency. The current
removal of some system regex packages from distributions is therefore not a
ProxySQL packaging blocker.

This migration does not change query-rule schema, configuration variable
names, rule ordering, or add JIT as a user-visible feature. JIT remains a
separate, benchmark-led follow-up rather than an assumed performance win.

## Current behavior

`lib/Query_Processor.cpp` stores PCRE 8 compiled regexes as `pcrecpp::RE`
objects in the shared rule representation. It compiles `match_digest` and
`match_pattern` with optional `CASELESS`, checks them with `PartialMatch`, and
rewrites `match_pattern` with `Replace` or `GlobalReplace` when `GLOBAL` is
set. The same shared implementation serves MySQL and PostgreSQL rules.

`pcrecpp` replacement syntax is part of that behavior: `\\0` represents the
whole match, `\\1` through `\\9` represent capture groups, and `\\\\` represents a
literal backslash. PCRE2 substitution syntax is different, so passing stored
`replace_pattern` values directly to PCRE2 would be a compatibility break.

## Design

### Dependency and build integration

Vendor the official PCRE2 10.47 source archive under `deps/pcre2` and build a
static 8-bit library only. Disable the 16-bit and 32-bit libraries, shared
libraries, and PCRE2's own test programs for the normal ProxySQL dependency
build. The target artifact is `libpcre2-8.a` and its headers.

Replace the `PCRE_PATH`, `PCRE_IDIR`, and `PCRE_LDIR` build variables with
PCRE2 equivalents. Update every static link path that currently adds
`-lpcrecpp -lpcre` or the two PCRE1 archives to add only `-lpcre2-8`. This
includes the main binary, unit tests, TAP tests, cluster simulator, and macOS
archive lists. No PCRE1 source, headers, patches, or link references remain.

### Query-rule adapter

Keep the PCRE2 details private to `Query_Processor.cpp`; no public ProxySQL
interface will expose PCRE2 types. The PCRE slot in the compiled-rule structure
will own one immutable `pcre2_code` object. Its lifetime remains tied to the
loaded query rule, exactly as the current `pcrecpp::RE` object is.

The adapter selects PCRE2's generic 8-bit API by defining
`PCRE2_CODE_UNIT_WIDTH 8` before including `pcre2.h`, then maps `CASELESS` to
`PCRE2_CASELESS`. Invalid patterns produce an actionable diagnostic using the
PCRE2 error text and make the rule fail closed: a compile failure is not a raw
regex non-match that `negate_match_pattern` can invert. Per-match data is
allocated for an operation and released before it returns, so a compiled query
rule remains safe to use concurrently.

Matching will use PCRE2 unanchored matching, which is the equivalent of the
current `PartialMatch` behavior. Negated rules will retain their current
inversion after the match result is known.

The adapter translates the established `pcrecpp` rewrite form into PCRE2
substitution form before calling `pcre2_substitute`: `\\0` through `\\9` map to
the corresponding capture references, `\\\\` stays a literal backslash, and
every legacy literal `$` becomes `$$` for PCRE2. Any other backslash escape is
malformed and leaves the query unchanged with a diagnostic. Optional captures
expand to empty text, as they did with pcrecpp. `GLOBAL` controls whether the
substitution has the global flag; without it, only the first match is replaced.
The same substitute options, including `GLOBAL` and `UNSET_EMPTY`, are used for
the sizing and execution calls. Buffer growth follows PCRE2's length-reporting
path, so a valid rewrite is never truncated.

The adapter will retain the existing behavior for both rule storage locations:
one compiled pattern for `match_digest` and a second for `match_pattern`.
Replacement always uses the latter, as it does today.

## Testing

Add focused unit coverage for the PCRE2 query-rule path, using both MySQL and
PostgreSQL rule types where the shared behavior differs at the API boundary.
The cases must cover:

- ordinary unanchored matching and non-matching;
- `CASELESS` matching and negated matching;
- first-only and `GLOBAL` replacement;
- whole-match, capture-group, and literal-backslash rewrites;
- a malformed pattern, including a negated rule, and a malformed rewrite, with
  no crash and no altered query text;
- a replacement that requires the PCRE2 output buffer to grow.

Run existing query-rule TAP regressions, including the MySQL and PostgreSQL
rewrite tests and the PostgreSQL extended-query rule test. Start validation
from a clean tree with `PROXYSQL31=1 make cleanall`, then build the normal and
debug targets that link query processors. The implementation PR must also run
the unit-test source-group check and format check.

## Acceptance criteria

- ProxySQL no longer includes or links PCRE1 or `pcrecpp`.
- Builds are self-contained from vendored PCRE2 10.47 on supported platforms.
- Existing persisted query-rule patterns, modifiers, and rewrites preserve the
  behavior defined above for MySQL and PostgreSQL. The repository has no
  versioned historical PCRE1 rule corpus, so this migration's compatibility
  boundary is the documented pcrecpp rewrite grammar. The MySQL and PostgreSQL
  frontend cases save each representative rule to disk, reload it, then verify
  first/global rewrites and malformed-input fallback through runtime.
- Focused unit and TAP coverage pass after a clean build.
