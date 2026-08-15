# ParserSQL

This directory vendors the [ParserSQL] SQL parser library that ProxySQL
links into `libsqlparser.a` and uses for `mysql-set_parser_algorithm=3`
/ `pgsql-set_parser_algorithm=3` (the ParserSQL-backed SET parser) and
related dialect-aware parsing paths.

[ParserSQL]: https://github.com/ProxySQL/ParserSQL

## Layout

- `parsersql-<VERSION>.tar.gz` — vendored upstream release tarball,
  expected to be byte-identical to `git archive --prefix=ParserSQL-<VERSION>/
  v<VERSION>` against the [upstream repo][ParserSQL].
- `parsersql` — symlink to the extracted source directory
  (`parsersql-<VERSION>/`), created by the top-level build at extract
  time. The symlink is what every other Makefile rule and `-I` /
  `-L` flag references, so the rest of the build is version-agnostic.
- `README.md` — this file.

`deps/Makefile`'s `parsersql/parsersql/libsqlparser.a` target unpacks
the tarball (renaming `ParserSQL-*` → `parsersql-*` for case-insensitive
filesystem friendliness) and runs `make lib` inside it.

## Upstream

- Repository: **https://github.com/ProxySQL/ParserSQL**
- License: see `parsersql/LICENSE` after extraction.
- Maintainers: same team as ProxySQL (sysown). It is a sibling project,
  not a third-party dependency — bug reports and PRs are welcome there.

## Bumping the version

```bash
# In the ParserSQL repo, after tagging vX.Y.Z:
git archive --format=tar.gz --prefix=ParserSQL-X.Y.Z/ vX.Y.Z \
    -o /tmp/parsersql-X.Y.Z.tar.gz

# In ProxySQL:
cd deps/parsersql
rm parsersql-*.tar.gz
cp /tmp/parsersql-X.Y.Z.tar.gz .
rm parsersql && ln -s parsersql-X.Y.Z parsersql
# Then git add the new tarball + symlink and commit.
```

The Makefile auto-detects the version via `parsersql-*.tar.gz` and
`ParserSQL-*/` glob patterns, so no Makefile change is required for
a routine bump.

## Working on the parser: fix it upstream, don't work around it

When `set_parser_algorithm=3` (or any other ParserSQL-backed code path)
misbehaves, the **preferred fix is in [ParserSQL][ParserSQL] itself**,
not a workaround in `lib/Query_Processor_ParserSQL.cpp` or in the
PgSQL_Session / MySQL_Session handlers.

Reasons:

1. **One source of truth.** ParserSQL exists to be the SQL parsing
   layer. If ProxySQL silently compensates for a parser bug, the next
   consumer (or a future ProxySQL refactor) will hit the same bug and
   re-discover the workaround.
2. **Tests live where the code lives.** Every parser fix should ship
   with regression coverage in `tests/test_*.cpp` upstream so the bug
   can't come back. Workarounds in ProxySQL only get tested by the
   downstream TAP suite, which is heavier and slower to run.
3. **Single version bump.** The expected workflow is: identify all
   related parser issues at once, fix them upstream in one PR, tag a
   new release, and bump here exactly once — rather than dribbling a
   ProxySQL workaround per bug followed by a parser bump that then
   needs the workarounds reverted.
4. **AST richness.** ParserSQL already carries node-type information
   (e.g. `NODE_LITERAL_STRING` vs `NODE_COLUMN_REF` for `'val'` vs
   `name`, `FLAG_IDENT_DELIMITED` for `"name"` vs `name`). When
   ProxySQL collapses everything to text in the walker, that
   information is lost and downstream code can't make correct
   decisions. Push richer typing into the AST upstream rather than
   re-deriving it in the consumer.

### When a ProxySQL-side change is the right call

- The fix is about *what ProxySQL does with* a correctly-parsed AST
  (e.g. which validator to apply, which session variable to track,
  whether to lock a hostgroup). The AST is fine; the policy is in
  ProxySQL.
- The fix is in the walker (`lib/Query_Processor_ParserSQL.cpp`) — for
  example, handling a new `NODE_*` type that ParserSQL emits but the
  walker hasn't been taught about yet.
- The bug is in ProxySQL's pre/post processing around the parse
  (digest, normalization, scope-prefix stripping, etc.).

### When a ParserSQL fix is the right call

- A SQL form that PostgreSQL or MySQL documents as valid returns
  `ParseResult::ERROR` or `PARTIAL`, or produces an AST shape that
  loses information the standard preserves.
- Two semantically-distinct inputs produce identical AST nodes (the
  parser is throwing away information the consumer needs).
- A keyword or shorthand isn't recognized (`SET SCHEMA`, `SET LOCAL`,
  `SET TRANSACTION ...`).
- The lexer truncates or mis-classifies tokens (`@@\`var\`` losing
  the closing backtick, `$word` falling through to a generic
  identifier instead of being rejected, etc.).

## Audit history

Significant audits / bumps:

- **v1.0.11 (2026-08-12)** — Adds lossless literal and user-variable AST
  nodes, full-input coverage for MySQL parsing, and user-variable usage
  classification. ProxySQL's typed SET adapter can therefore preserve exact
  replay literals while distinguishing safe read-only references from unsafe
  or unknown use.
- **v1.0.8 (2026-05-23)** — Tokenizer: unclosed delimited identifier
  (`"name` in PG, `` `name `` in MySQL) now emits `TK_ERROR` instead
  of silently consuming everything to EOF as one giant identifier.
  Closes the case-#172 cascade in ProxySQL's
  `pgsql-set_parameter_validation_test-t` under `set_parser_algorithm=3`,
  where `SET search_path = "unclosed_quote, public` was being parsed
  as identifier `unclosed_quote, public` and then accepted by the
  search_path validator — corrupting the stored value with what PG
  itself would have rejected outright.
  ([PR #44](https://github.com/ProxySQL/ParserSQL/pull/44))
- **v1.0.7 (2026-05-23)** — Tokenizer: allow `$` as PG identifier
  continuation char (per PG lexical-syntax docs). Before, `SET
  search_path = schema$1` truncated to `schema` and `$1` fell through
  as a placeholder, breaking ProxySQL's `set_parser_algorithm=3` path
  in `pgsql-set_parameter_validation_test-t` (case 169). First-char
  constraint preserved (`$<word>` at token start still emits
  `TK_ERROR`); MySQL behaviour unchanged.
  ([PR #43](https://github.com/ProxySQL/ParserSQL/pull/43))
- **v1.0.6 (2026-05-23)** — Hot-fix on top of v1.0.5: `parse_set()`'s
  PARTIAL → ERROR downgrade was too aggressive for multi-assignment
  SETs where one element is malformed alongside well-formed ones
  (`SET sql_mode='X', whatever=, autocommit=1`). v1.0.6 only
  downgrades when the parse produced no children at all, so the
  successful elements remain in the AST.
  ([PR #42](https://github.com/ProxySQL/ParserSQL/pull/42))
- **v1.0.5 (2026-05-23)** — Post-1.0.4 audit follow-up after a wider
  SET-form sweep. Adds three new node types
  (`NODE_SET_ROLE`, `NODE_SET_SESSION_AUTHORIZATION`,
  `NODE_SET_CONSTRAINTS`) so PG non-GUC SET forms are no longer
  misclassified as unknown GUC assignments; recognizes
  schema-qualified GUC names (`SET pg_catalog.search_path`,
  `SET myapp.setting`); preserves the full `SET TIME ZONE INTERVAL
  '1' HOUR` literal (was dropping value + unit); and surfaces
  clearly-malformed SET inputs (`SET = 1`, `SET x = ;`, `SET x =`,
  `SET x = ,foo`, `SET search_path TO`, bare `SET`, `SET GLOBAL`)
  as `ParseResult::ERROR` instead of `PARTIAL`.
  ([PR #40](https://github.com/ProxySQL/ParserSQL/pull/40))
- **v1.0.4 (2026-05-23)** — Six fixes from the initial
  `set_parser_algorithm=3` audit: backtick-delimited `@@\`var\``
  identifiers, PG `SET SCHEMA` / `SET SEED` shorthands, identifier
  quote-style flag (`FLAG_IDENT_DELIMITED`), bare PG `$word` →
  `ERROR`.
  ([PR #39](https://github.com/ProxySQL/ParserSQL/pull/39))
- **v1.0.3** — PG `SET TIME ZONE` alias + PG multi-value list
  (`SET search_path TO 'a', 'b'`).
  ([PR #38](https://github.com/ProxySQL/ParserSQL/pull/38))
