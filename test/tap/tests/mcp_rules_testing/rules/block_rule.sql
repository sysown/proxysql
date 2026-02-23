-- Test Block Rule for MCP Query Rules
-- This rule blocks queries matching DROP TABLE pattern
-- Rule ID 100: Block any query containing DROP TABLE
INSERT INTO mcp_query_rules (
    rule_id,
    active,
    username,
    schemaname,
    tool_name,
    match_pattern,
    negate_match_pattern,
    re_modifiers,
    flagIN,
    flagOUT,
    replace_pattern,
    timeout_ms,
    error_msg,
    OK_msg,
    log,
    apply,
    comment
) VALUES (
    100,                                    -- rule_id
    1,                                      -- active
    NULL,                                   -- username (any user)
    NULL,                                   -- schemaname (any schema)
    NULL,                                   -- tool_name (any tool)
    'DROP TABLE',                           -- match_pattern
    0,                                      -- negate_match_pattern
    'CASELESS',                             -- re_modifiers
    0,                                      -- flagIN
    NULL,                                   -- flagOUT
    NULL,                                   -- replace_pattern
    NULL,                                   -- timeout_ms
    'Blocked by MCP query rule: DROP TABLE statements are not allowed',  -- error_msg (BLOCK action)
    NULL,                                   -- OK_msg
    1,                                      -- log
    1,                                      -- apply
    'Test rule: Block DROP TABLE statements' -- comment
);

-- Rule ID 101: Block SELECT queries on customers table (more specific pattern)
INSERT INTO mcp_query_rules (
    rule_id,
    active,
    username,
    schemaname,
    tool_name,
    match_pattern,
    negate_match_pattern,
    re_modifiers,
    flagIN,
    flagOUT,
    replace_pattern,
    timeout_ms,
    error_msg,
    OK_msg,
    log,
    apply,
    comment
) VALUES (
    101,                                    -- rule_id
    1,                                      -- active
    NULL,                                   -- username (any user)
    'testdb',                               -- schemaname (only testdb)
    'run_sql_readonly',                     -- tool_name (only this tool)
    'SELECT.*FROM.*customers',              -- match_pattern
    0,                                      -- negate_match_pattern
    'CASELESS',                             -- re_modifiers
    0,                                      -- flagIN
    NULL,                                   -- flagOUT
    NULL,                                   -- replace_pattern
    NULL,                                   -- timeout_ms
    'Blocked by MCP query rule: Direct access to customers table is restricted',  -- error_msg
    NULL,                                   -- OK_msg
    1,                                      -- log
    1,                                      -- apply
    'Test rule: Block SELECT from customers table in testdb' -- comment
);
