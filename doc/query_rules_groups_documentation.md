# ProxySQL Query Rules: Capture Groups and Backreferences

## Introduction

ProxySQL's query rules engine supports regular expression capture groups and backreferences, allowing sophisticated query rewriting. This document explains how to use these features to transform SQL queries dynamically.

## Core Concepts

### Table Columns for Pattern Matching

| Column | Purpose | Example |
|--------|---------|---------|
| `digest` | Hash of the normalized query pattern | `0x1d2cc217c860282` |
| `match_digest` | Normalized query pattern with placeholders | `SELECT * FROM users WHERE id = ?` |
| `match_pattern` | Raw query pattern with regex groups | `SELECT (.*) FROM users WHERE id = (\d+)` |
| `replace_pattern` | Replacement pattern with backreferences | `SELECT \1 FROM customers WHERE user_id = \2` |
| `re_modifiers` | Regex modifiers | `'CASELESS'` or `'CASELESS,GLOBAL'` |

### Regex Engine Support

ProxySQL supports two regex engines (configurable via `mysql-query_processor_regex`):
- **PCRE** (default, `query_processor_regex=1`): Full regex support including capture groups
- **RE2** (`query_processor_regex=2`): Google's RE2 library, supports capture groups in replacement patterns

Both engines support backreferences (`\1`, `\2`, etc.) in `replace_pattern`.

## Basic Syntax

### Capture Groups in match_pattern

Use parentheses `()` to define capture groups:

```sql
-- Two capture groups: column list and WHERE clause
INSERT INTO mysql_query_rules (
    match_pattern, replace_pattern, apply
) VALUES (
    'SELECT (.*) FROM users WHERE (.*)',
    'SELECT \1 FROM customers WHERE \2',
    1
);
```

### Backreferences in replace_pattern

Reference captured groups with `\1`, `\2`, etc.:

```sql
-- \1 = column list, \2 = WHERE conditions
'\1 FROM modified_table WHERE \2'
```

**Important**: Use single backslash (`\1`), not double (`\\1`), in the SQL INSERT statement.

## Practical Examples

### Example 1: Changing Table Names While Preserving Query Structure

**Goal**: Rewrite queries from `old_table` to `new_table` while keeping all other parts unchanged.

```sql
INSERT INTO mysql_query_rules (
    rule_id, active, match_pattern, replace_pattern, re_modifiers, apply
) VALUES (
    1, 1,
    '(SELECT .* FROM )old_table( WHERE .*)',
    '\1new_table\2',
    'CASELESS',
    1
);
```

**Matches**: `SELECT id, name FROM old_table WHERE status = 'active'`
**Becomes**: `SELECT id, name FROM new_table WHERE status = 'active'`

### Example 2: Adding Hints to Specific Queries

**Goal**: Add `FORCE INDEX (primary)` to SELECT queries on `orders` table with specific conditions.

```sql
INSERT INTO mysql_query_rules (
    rule_id, active, digest, match_pattern, replace_pattern, apply
) VALUES (
    2, 1, '0x1234567890abcdef',
    '(SELECT .* FROM orders)( WHERE customer_id = \d+.*)',
    '\1 FORCE INDEX (primary)\2',
    1
);
```

**Matches**: `SELECT * FROM orders WHERE customer_id = 100 AND date > '2024-01-01'`
**Becomes**: `SELECT * FROM orders FORCE INDEX (primary) WHERE customer_id = 100 AND date > '2024-01-01'`

### Example 3: Column Renaming in SELECT Queries

**Goal**: Rename column `legacy_id` to `new_id` in all SELECT queries.

```sql
INSERT INTO mysql_query_rules (
    rule_id, active, match_pattern, replace_pattern, re_modifiers, apply
) VALUES (
    3, 1,
    '(SELECT.*?)legacy_id(.*FROM.*)',
    '\1new_id\2',
    'CASELESS',
    1
);
```

**Matches**: `SELECT legacy_id, name FROM products WHERE category = 'electronics'`
**Becomes**: `SELECT new_id, name FROM products WHERE category = 'electronics'`

### Example 4: Conditional Rewriting Based on Values

**Goal**: Add `USE INDEX` hint only for queries with `status = 'pending'`.

```sql
INSERT INTO mysql_query_rules (
    rule_id, active, match_pattern, replace_pattern, re_modifiers, apply
) VALUES (
    4, 1,
    '(SELECT .* FROM tasks)( WHERE.*status\s*=\s*''pending''.*)',
    '\1 USE INDEX (idx_status)\2',
    'CASELESS',
    1
);
```

**Matches**: `SELECT * FROM tasks WHERE status = 'pending' AND due_date < NOW()`
**Becomes**: `SELECT * FROM tasks USE INDEX (idx_status) WHERE status = 'pending' AND due_date < NOW()`

### Example 5: Complex Multi-Group Rewriting

**Goal**: Reorder WHERE clause conditions and add optimizer hint.

```sql
INSERT INTO mysql_query_rules (
    rule_id, active, match_pattern, replace_pattern, re_modifiers, apply
) VALUES (
    5, 1,
    'SELECT (.*) FROM (\w+) WHERE (column1 = .*) AND (column2 = .*)',
    'SELECT /*+ MAX_EXECUTION_TIME(1000) */ \1 FROM \2 WHERE \4 AND \3',
    'CASELESS',
    1
);
```

**Matches**: `SELECT id, name FROM accounts WHERE column1 = 'value1' AND column2 = 'value2'`
**Becomes**: `SELECT /*+ MAX_EXECUTION_TIME(1000) */ id, name FROM accounts WHERE column2 = 'value2' AND column1 = 'value1'`

## Advanced Techniques

### Combining digest and match_pattern

For precise targeting, combine `digest` (hash of normalized query) with `match_pattern` (specific values):

```sql
INSERT INTO mysql_query_rules (
    rule_id, active, digest, match_pattern, replace_pattern, apply
) VALUES (
    6, 1, '0xa1b2c3d4e5f67890',
    '(SELECT .* FROM users)( WHERE id = 12345.*)',
    '\1 FORCE INDEX (primary)\2',
    1
);
```

### Using re_modifiers

- `CASELESS`: Case-insensitive matching
- `GLOBAL`: Replace all occurrences (not just first)

```sql
INSERT INTO mysql_query_rules (
    rule_id, active, match_pattern, re_modifiers, replace_pattern, apply
) VALUES (
    7, 1,
    '(SELECT)(.*)(FROM)(.*)',
    'CASELESS,GLOBAL',
    '\1 SQL_NO_CACHE \2\3\4',
    1
);
```

### Rule Chaining with flagIN/flagOUT

For complex transformations, chain rules using flags:

```sql
-- Rule 1: Match pattern and set flagOUT
INSERT INTO mysql_query_rules (
    rule_id, active, match_pattern, flagOUT, apply
) VALUES (
    8, 1, 'SELECT .* FROM sensitive_table', 100, 0
);

-- Rule 2: Apply transformation only when flagIN matches
INSERT INTO mysql_query_rules (
    rule_id, active, flagIN, match_pattern, replace_pattern, apply
) VALUES (
    9, 1, 100,
    '(SELECT .* FROM )sensitive_table( WHERE .*)',
    '\1audited_sensitive_table\2',
    1
);
```

## Testing and Validation

### 1. Verify Rule Matching

```sql
-- Check stats for specific rule
SELECT * FROM stats_mysql_query_rules WHERE rule_id = 1;

-- Test pattern matching
SELECT * FROM mysql_query_rules
WHERE match_pattern = '(SELECT .* FROM )old_table( WHERE .*)';
```

### 2. Monitor Rule Performance

```sql
-- View hits and performance
SELECT rule_id, hits, mysql_query_rules.match_pattern,
       sum_time, min_time, max_time
FROM stats_mysql_query_rules
JOIN mysql_query_rules USING (rule_id)
ORDER BY hits DESC;
```


## Common Pitfalls and Solutions

### Problem 1: Groups Not Capturing Entire Needed Text

**Symptom**: Replacement loses part of the original query.

**Solution**: Expand capture groups to include more context:

```sql
-- Before (loses WHERE clause):
'(SELECT .* FROM table)( WHERE)'

-- After (captures entire WHERE clause):
'(SELECT .* FROM table)( WHERE.*)'
```

### Problem 2: Backreferences Not Working

**Symptom**: `\1` appears literally in output instead of replaced text.

**Solution**: Ensure:
1. Parentheses in `match_pattern` define capture groups
2. `replace_pattern` uses `\1`, not `\\1` or `$1`
3. Rule is active (`active = 1`)

### Problem 3: Overly Broad Matching

**Symptom**: Rule applies to unintended queries.

**Solution**: Add more specific constraints:
- Use `digest` column to restrict to specific query patterns
- Add `username` or `schemaname` restrictions
- Make `match_pattern` more specific

```sql
INSERT INTO mysql_query_rules (
    active, username, digest, match_pattern, replace_pattern, apply
) VALUES (
    1, 'app_user', '0x1234567890abcdef',
    '(SELECT .* FROM orders)( WHERE .*)',
    '\1 FORCE INDEX (primary)\2',
    1
);
```

## Best Practices

1. **Test Incrementally**: Start with simple patterns, then add complexity.
2. **Use digest for Precision**: Combine `digest` with `match_pattern` for exact targeting.
3. **Case-Insensitive by Default**: Use `re_modifiers = 'CASELESS'` unless case sensitivity is required.
4. **Monitor Performance**: Regularly check `stats_mysql_query_rules` for rule hits and timing.
5. **Document Rules**: Add comments to rules explaining their purpose:

```sql
INSERT INTO mysql_query_rules (
    rule_id, active, match_pattern, replace_pattern, apply, comment
) VALUES (
    10, 1,
    '(SELECT .* FROM )products( WHERE .*)',
    '\1products_v2\2',
    1,
    'Rewrite: Route queries from products to products_v2 table'
);
```

6. **Version Control**: Keep query rule definitions in version-controlled SQL files.

## Conclusion

ProxySQL's capture group and backreference capabilities provide powerful query rewriting options. By understanding how to properly structure `match_pattern` with parentheses and reference captured groups with `\1`, `\2` in `replace_pattern`, you can implement sophisticated query transformations while maintaining query correctness.

Always test rules in a staging environment before deploying to production, and monitor their impact on query performance and correctness.