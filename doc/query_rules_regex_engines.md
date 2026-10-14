# Query rule regex engines: PCRE (engine 1), RE2 (engine 2), PCRE2 (engine 3)

`mysql-query_processor_regex` and `pgsql-query_processor_regex` select the regex
engine used for the `match_digest`, `match_pattern` and `replace_pattern`
columns of `mysql_query_rules` and `pgsql_query_rules`.

| Value | Engine | v3.0 (Stable) | v3.1 (Innovative) | v4.0 |
|---|---|---|---|---|
| 1 | PCRE 8.45 (`pcrecpp`) | default | default | available |
| 2 | RE2 | available | available | available |
| 3 | PCRE2 10.47 | not available | available (opt-in) | **default** |

Engine 1 behaves exactly as in v3.0.11 and earlier, except that a match can
no longer overflow the worker stack (see [Stack vs heap](#stack-vs-heap)). Engine 3 is not
syntax-compatible with engine 1: review your rules with the checklist below
before switching, and before upgrading to v4.0 if you do not set the variable
explicitly. To keep the previous behaviour on v4.0, set
`mysql-query_processor_regex=1` / `pgsql-query_processor_regex=1`.

## What engine 3 is

- PCRE2 10.47, built with UTF support available but not enabled by default,
  and without JIT. A pattern enables UTF mode with `(*UTF)`; `(*UCP)` only makes
  `\d`, `\w`, `\s` and POSIX classes use Unicode properties, it does not enable
  UTF mode on its own.
- Lookaround may contain `\K` (`PCRE2_EXTRA_ALLOW_LOOKAROUND_BSK`).
- Per-match limits: 64 MiB of backtracking heap, and the PCRE2 default match
  and depth limits (10,000,000; engine 1 runs with the same match limit, see
  [Stack vs heap](#stack-vs-heap) for its recursion limit).

## Unchanged between engines 1 and 3

- `\s \d \w \b`, escaped punctuation (`\. \( \- \_ \% \'`), `(?i)` and CASELESS, GLOBAL.
- Caseless matching for bytes >= 128 (C locale), LF newline, `$` before a final newline,
  `\K` in a lookaround.
- Empty matches in a global replace (`x*` on `abc` gives `<>a<>b<>c<>`).
- Rewrite syntax `\0`-`\9` and `\\`; `$` is literal.
- Already errors in both engines: `\L \l \U \u \N{..}`, `\o` without a brace, `\c` at end,
  `\g`, `\k`, `\x{100}`, `\400`, `[a-\d]`, `a{2,1}`.

## Differences

### Valid in PCRE, compile error in PCRE2 (the rule stops matching)

| Pattern | Engine 1 | Engine 3 error | Portable rewrite |
|---|---|---|---|
| `\y \i \j \m \q \T \Y \O \I \M` (unknown letter escape) | literal letter | `unrecognized character follows \` (103) | `y`, `i`, ... |
| `\F` | literal `F` | `PCRE2 does not support \F, \L, \l, \N{name}, \U, or \u` (137) | `F` |
| `[\y]`, `[\i]` | literal | 103 | `[y]` |
| `[\w-.]+`, `[\w-\.]`, `[\d-z]`, `[\s-x]`, `[\d-\w]`, `[[:alpha:]-z]` | `-` is a literal hyphen | `invalid range in character class` (150) | `[\w.-]` or `[\w\-.]` |
| `[\R]`, `[\X]`, `[\B]` | literal R/X/B | `escape sequence is invalid in character class` (107) | `[R]` |
| `a\8`, `a\9` (no such group) | literal digit | `reference to non-existent subpattern` (115) | `a8` |
| `(?X)abc` | accepted | `unrecognized character after (?` (141) | remove `(?X)` |
| bare `\x` | matches NUL | `digits missing after \x` | `\x00` |

### Valid in both, different meaning (nothing is logged)

| Pattern | Engine 1 | Engine 3 |
|---|---|---|
| `x{,3}` | literal text `x{,3}` | `x{0,3}` |
| `x{ 2 }`, `x{2, 3}` | literal text | quantifier |
| `(?xx)` | n/a | also ignores spaces inside character classes |

If literal text was intended, write `\{`.

### Invalid in PCRE, valid in PCRE2 (inert rules become active)

- Variable-length lookbehind up to 255 characters, e.g. `(?<=a{1,3})b`.
- `(*UTF)`, `(*UTF8)`, `(*UCP)`, `\p{L}`, `\pL`, `\X`.
- `(?n)`, `(?^i)`; group names longer than 32 characters.
- `(*LIMIT_DEPTH=)`, `(*LIMIT_HEAP=)`; `\x{ 41 }` (spaces inside the braces).

On engine 1 such a rule never matches, or matches every query if it is
negated. On engine 3 it matches according to the pattern.

### replace_pattern

| Case | Engine 1 | Engine 3 |
|---|---|---|
| `(a)\|(b)`, rewrite `[\1][\2]`, subject `a` | query unchanged; with GLOBAL a truncated `[a][` | `[a][]` |
| rewrite `[\5]` (no group 5), GLOBAL | truncated query `[[` | query unchanged; nothing is logged |
| GLOBAL rewrite with an invalid escape, e.g. `x\ny` | query replaced with `xx` | query unchanged; logged once |

### Stack vs heap

- Engine 1 recurses on the stack of the worker thread (`mysql-stacksize` /
  `pgsql-stacksize`, 1 MiB by default, 256 KiB to 4 MiB). Each repetition
  of a group such as `(.|\n)*` or `(\d+,?)+` that may have to be resumed adds
  2-4 nested calls of about 450 bytes each. Up to v3.0.11 there was no limit,
  so `^(.|\n)*FOR UPDATE` crashed ProxySQL on a query of about 2 KB.
- Engine 1 now runs with a recursion limit derived from the worker's stack:
  (free stack when the rules are compiled - 64 KiB) / 1 KiB, about 900 on the
  default 1 MiB stack and about 160 on a 256 KiB stack. A larger stacksize
  allows deeper matches. Its match limit is 10,000,000 (the PCRE default).
- `.*`, `.*?`, `\s+` and `[\s\S]*` do not nest: `^SELECT\s.*\sFROM\s+t\b`
  needs 2 levels on a 1 MB query. Only a repeated group on a long query
  reaches the limit, e.g. `IN \((\d+,)*\d+\)` on an IN list of a few hundred
  values with the default stack.
- Engine 3 keeps backtracking frames on the heap, limited per match.
- For both engines, use `[\s\S]*` or `(?s).*` instead of `(.|\n)*`, and a
  character class (`IN \([\d,]+\)`) instead of a repeated group.

## Invalid regex and limit hits

| | Engine 1 | Engine 2 | Engine 3 |
|---|---|---|---|
| Invalid regex | never matches | never matches | never matches |
| Invalid regex, `negate_match_pattern=1` | **matches every query** (as in v3.0.11) | **matches every query** (as in v3.0.11) | never matches |
| Limit reached on a query | recursion/match limit: the rule is not applied to that query, negated or not | n/a (RE2 does not backtrack) | heap/depth/match limit: the rule is not applied to that query, negated or not |
| Limit reached by `replace_pattern` | the query is not rewritten (also with GLOBAL: no partial rewrite) | n/a | the query is not rewritten |

| Limit | Engine 1 (PCRE) | Engine 3 (PCRE2) |
|---|---|---|
| Recursion / depth | (free worker stack - 64 KiB) / 1 KiB: ~900 with the default 1 MiB `stacksize` | 10,000,000 |
| Match | 10,000,000 | 10,000,000 |
| Heap | n/a (frames on the stack) | 64 MiB |

An invalid regex is logged once per rules load, by the first worker thread that
compiles the new rules (not once per worker):
`Query rule <id>: match_digest|match_pattern '<pattern>' cannot be compiled by the PCRE|RE2|PCRE2 regex engine, ...`.
A limit hit is logged at most every 10 seconds:
`Query rule <id>: match_digest|match_pattern matching stopped with PCRE2 error <code> ...` (engine 3),
`Query rule <id>: match_digest|match_pattern matching stopped with PCRE error <code> (recursion|match limit <n> reached) ...` or
`Query rule <id>: replace_pattern stopped with PCRE error <code> ...` (engine 1).

## Migrating to engine 3: checklist

1. List the rules: `SELECT rule_id, match_digest, match_pattern, replace_pattern, negate_match_pattern FROM runtime_mysql_query_rules`
   (and `runtime_pgsql_query_rules`).
2. Look for the constructs above, either with `grep` or by switching a staging
   instance to engine 3 and checking the error log for `cannot be compiled`.
3. Rewrite the affected patterns with the portable forms above. They behave
   the same on both engines.
4. Check `replace_pattern` rules against the replace_pattern cases.
5. Compare `stats_mysql_query_rules.hits` before and after the switch.
