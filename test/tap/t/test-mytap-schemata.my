/*
TAP Tests for schema functions 
*/

BEGIN;

SELECT tap.plan(51);

-- setup for tests
DROP DATABASE IF EXISTS taptest;
CREATE DATABASE taptest COLLATE latin1_general_ci;


/****************************************************************************/
-- has_schema(sname VARCHAR(64), description TEXT)

SELECT tap.check_test(
    tap.has_schema('taptest', ''),
    true,
    'has_schema() extant schema',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.has_schema('nonexistent', ''),
    false,
    'has_schema() nonexistent schema',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.has_schema('taptest', ''),
    true,
    'has_schema() default description',
    'Schema taptest should exist',
    null,
    0
);

SELECT tap.check_test(
    tap.has_schema('taptest', 'desc'),
    true,
    'has_schema() description supplied',
    'desc',
    null,
    0
);




/****************************************************************************/
-- hasnt_schema(sname VARCHAR(64), description TEXT)

SELECT tap.check_test(
    tap.hasnt_schema('nonexistent', ''),
    true,
    'hasnt_schema() with nonexistent schema',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_schema('taptest', ''),
    false,
    'hasnt_schema() with exitant schema',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_schema('nonexistent', ''),
    true,
    'hasnt_schema() default description',
    'Schema nonexistent should not exist',
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_schema('nonexistent', 'desc'),
    true,
    'hasnt_schema() description supplied',
    'desc',
    null,
    0
);




/****************************************************************************/
-- schema_collation_is(sname VARCHAR(64), cname VARCHAR(32), description TEXT)

SELECT tap.check_test(
    tap.schema_collation_is('taptest', 'latin1_general_ci', ''),
    true,
    'schema_collation_is() with correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.schema_collation_is('taptest', 'utf8_bin', ''),
    false,
    'schema_collation_is() with incorrect specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.schema_collation_is('taptest', 'latin1_general_ci', ''),
    true,
    'schema_collation_is() default description',
    'Schema taptest should have Collation \'latin1_general_ci\'',
    null,
    0
);

SELECT tap.check_test(
    tap.schema_collation_is('taptest', 'latin1_general_ci', 'desc'),
    true,
    'schema_collation_is() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.schema_collation_is('taptest', 'INVALID_COLLATION', ''),
    false,
    'schema_collation_is() invalid collation supplied',
    null,
    'Collation INVALID_COLLATION is not available',
    0
);

SELECT tap.check_test(
    tap.schema_collation_is('nonexistent', 'latin1_general_ci', ''),
    false,
    'schema_collation_is() nonexistent schema supplied',
    null,
    'Schema nonexistent does not exist',
    0
);




/****************************************************************************/
-- schema_charset_is(sname VARCHAR(64), cname VARCHAR(32), description TEXT)

SELECT tap.check_test(
    tap.schema_charset_is('taptest', 'latin1', ''),
    true,
    'schema_charset_is() with correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.schema_charset_is('taptest', 'utf8', ''),
    false,
    'schema_charset_is() with incorrect specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.schema_charset_is('taptest', 'latin1', ''),
    true,
    'schema_charset_is() default description',
    'Schema taptest should use Character set latin1',
    null,
    0
);

SELECT tap.check_test(
    tap.schema_charset_is('taptest', 'latin1', 'desc'),
    true,
    'schema_charset_is() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.schema_charset_is('taptest', 'INVALID', ''),
    false,
    'schema_charset_is() invalid charset supplied',
    null,
    'Character set INVALID is not available',
    0
);

SELECT tap.check_test(
    tap.schema_charset_is('nonexistent', 'latin1', ''),
    false,
    'schema_charset_is() nonexistent schema supplied',
    null,
    'Schema nonexistent does not exist',
    0
);


/****************************************************************************/
-- schema_character_set_is(sname VARCHAR(64), cname VARCHAR(32), description TEXT)

SELECT tap.check_test(
    tap.schema_character_set_is('taptest',  'latin1', ''),
    true,
    'schema_character_set_is() with correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.schema_character_set_is('taptest', 'utf8', ''),
    false,
    'schema_character_set_is() with incorrect specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.schema_character_set_is('taptest', 'latin1', ''),
    true,
    'schema_character_set_is() default description',
    'Schema taptest should use Character set latin1',
    null,
    0
);

SELECT tap.check_test(
    tap.schema_character_set_is('taptest', 'latin1', 'desc'),
    true,
    'schema_character_set_is() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.schema_character_set_is('taptest', 'INVALID', ''),
    false,
    'schema_character_set_is() invalid charset supplied',
    null,
    'Character set INVALID is not available',
    0
);

SELECT tap.check_test(
    tap.schema_character_set_is('nonexistent', 'latin1', ''),
    false,
    'schema_character_set_is() nonexistent schema supplied',
    null,
    'Schema nonexistent does not exist',
    0
);

SELECT tap.check_test(
    tap.schema_character_set_is('taptest', 'latin1', ''),
    true,
    'schema_character_set_is() with correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.schema_character_set_is('taptest', 'latin1', ''),
    true,
    'schema_character_set_is() default description',
    'Schema taptest should use Character set latin1',
    null,
    0
);

SELECT tap.check_test(
    tap.schema_character_set_is('taptest', 'latin1', 'desc'),
    true,
    'schema_character_set_is() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.schema_character_set_is('taptest', 'INVALID', ''),
    false,
    'schema_character_set_is() invalid charset supplied',
    null,
    'Character set INVALID is not available',
    0
);

SELECT tap.check_test(
    tap.schema_character_set_is('nonexistent', 'latin1', ''),
    false,
    'schema_character_set_is() nonexistent schema supplied',
    null,
    'Schema nonexistent does not exist',
    0
);


/****************************************************************************/
-- schemas_are(want TEXT, description TEXT)
-- Can't really test this except on a virgin system

/****************************************************************************/

-- Finish the tests and clean up.

call tap.finish();
DROP DATABASE IF EXISTS taptest;
ROLLBACK;
