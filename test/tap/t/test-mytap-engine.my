/*
TAP Tests for engine functions 
*/

BEGIN;

SELECT tap.plan(14);

-- setup for tests
-- none required
-- INNODB is the default, MEMORY is automatically enabled so both should
-- always be available on a MySQL installation.

/****************************************************************************/
-- has_engine(ename VARCHAR(64), description TEXT)

SELECT tap.check_test(
    tap.has_engine('INNODB', ''),
    true,
    'has_engine() extant engine',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.has_engine('nonexistent', ''),
    false,
    'has_engine() nonexistent engine',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.has_engine('MEMORY', ''),
    true,
    'has_engine() default description',
    'Storage Engine MEMORY should be available',
    null,
    0
);

SELECT tap.check_test(
    tap.has_engine('MEMORY', 'desc'),
    true,
    'has_engine() description supplied',
    'desc',
    null,
    0
);


/****************************************************************************/
-- engine_is_default(ename VARCHAR(64), description TEXT)

SELECT tap.check_test(
    tap.engine_is_default('INNODB', ''),
    true,
    'engine_is_default() extant engine',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.engine_is_default('MEMORY', ''),
    false,
    'engine_is_default() extant non-default engine',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.engine_is_default('nonexistent', ''),
    false,
    'engine_is_default() nonexistent engine',
    null,
    'Storage engine nonexistent is not available',
    0
);


SELECT tap.check_test(
    tap.engine_is_default('INNODB', ''),
    true,
    'engine_is_default() default description',
    'Storage Engine INNODB should be the default',
    null,
    0
);


SELECT tap.check_test(
    tap.engine_is_default('INNODB', 'desc'),
    true,
    'engine_is_default() description supplied',
    'desc',
    null,
    0
);




/****************************************************************************/

-- Finish the tests and clean up.

call tap.finish();
ROLLBACK;
