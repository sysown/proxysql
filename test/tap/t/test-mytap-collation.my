/*
TAP Tests for collation functions 
*/

BEGIN;

SELECT tap.plan(12);

-- setup for tests
-- None
-- Tests for collations applying at schema, table and column level
-- are tested at the specific level 
/****************************************************************************/
-- has_collation(cname VARCHAR(32), description TEXT)

SELECT tap.check_test(
    tap.has_collation('ASCII_bin', ''),
    true,
    'has_collation() extant collation',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.has_collation('nonexistent', ''),
    false,
    'has_collation() nonexistent collation',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.has_collation('ascii_bin', ''),
    true,
    'has_collation() default description',
    'Collation ASCII_bin should be available',
    null,
    0
);

SELECT tap.check_test(
    tap.has_collation('ascii_bin', 'desc'),
    true,
    'has_collation() description supplied',
    'desc',
    null,
    0
);




/****************************************************************************/
-- hasnt_collation(sname VARCHAR(64), description TEXT)

SELECT tap.check_test(
    tap.hasnt_collation('nonexistent', ''),
    true,
    'hasnt_collation() with nonexistent collation',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_collation('ascii_bin', ''),
    false,
    'hasnt_collation() with extant collation',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_collation('nonexistent', ''),
    true,
    'hasnt_collation() default description',
    'Collation nonexistent should not be available',
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_collation('nonexistent', 'desc'),
    true,
    'hasnt_collation() description supplied',
    'desc',
    null,
    0
);


/****************************************************************************/

-- Finish the tests and clean up.

call tap.finish();

ROLLBACK;
