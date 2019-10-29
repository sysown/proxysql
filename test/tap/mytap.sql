CREATE SCHEMA IF NOT EXISTS tap;
USE tap;

-- We use connection_id() in "cid" to keep things separate from other proceses.
DROP TABLE IF EXISTS __tcache__;
CREATE TABLE __tcache__ (
    id    INTEGER AUTO_INCREMENT PRIMARY KEY,
    cid   INTEGER NOT NULL,
    label TEXT    NOT NULL,
    value INTEGER NOT NULL,
    note  TEXT    NOT NULL
);

DROP TABLE IF EXISTS __tresults__;
CREATE TABLE __tresults__ (
    numb   INTEGER NOT NULL,
    cid    INTEGER NOT NULL,
    ok     BOOLEAN NOT NULL DEFAULT 1,
    aok    BOOLEAN NOT NULL DEFAULT 1,
    descr  TEXT    NOT NULL,
    type   TEXT    NOT NULL,
    reason TEXT    NOT NULL
);

DELIMITER //

DROP FUNCTION IF EXISTS mytap_version //
CREATE FUNCTION mytap_version()
RETURNS VARCHAR(10)
DETERMINISTIC NO SQL
BEGIN
    RETURN '1.0';
END //


DROP FUNCTION IF EXISTS mysql_version //
CREATE FUNCTION mysql_version() RETURNS integer
DETERMINISTIC CONTAINS SQL
BEGIN
    RETURN (substring_index(version(), '.', 1) * 100000)
         + (substring_index(substring_index(version(), '.', 2), '.', -1) * 1000)
         + CAST(substring_index(substring_index(substring_index(version(), '-', 1),'.', 3), '.', -1) AS UNSIGNED);
END //


DROP FUNCTION IF EXISTS mysql_variant //
CREATE FUNCTION mysql_variant() RETURNS VARCHAR(7)
DETERMINISTIC CONTAINS SQL
BEGIN
   RETURN (SELECT
           CASE
	     WHEN version() REGEXP 'MariaDB' = 1 THEN 'MariaDB'
	     WHEN version() REGEXP 'Percona' = 1 THEN 'Percona'
	     ELSE 'MySQL'
	   END);
END //

DROP FUNCTION IF EXISTS _get //
CREATE FUNCTION _get ( vlabel text ) RETURNS integer
READS SQL DATA
BEGIN
    DECLARE ret integer;
    SELECT value INTO ret
      FROM __tcache__
     WHERE cid   = connection_id()
       AND label = vlabel LIMIT 1;
    RETURN ret;
END //

DROP FUNCTION IF EXISTS _set //
CREATE FUNCTION _set ( vlabel text, vvalue integer, vnote text ) RETURNS INTEGER
READS SQL DATA
BEGIN
    UPDATE __tcache__
       SET value = vvalue,
           note  = COALESCE(vnote, '')
     WHERE cid   = connection_id()
       AND label = vlabel;
    IF ROW_COUNT() = 0 THEN
        RETURN _add( vlabel, vvalue, vnote );
    END IF;
    RETURN vvalue;
END//

DROP PROCEDURE IF EXISTS _idset //
CREATE PROCEDURE _idset( vid integer, vvalue integer)
DETERMINISTIC MODIFIES SQL DATA
BEGIN
    UPDATE __tcache__
       SET value = vvalue
     WHERE id = vid;
END //

DROP FUNCTION IF EXISTS _nextnumb //
CREATE FUNCTION _nextnumb() RETURNS INTEGER
DETERMINISTIC CONTAINS SQL
BEGIN
    DECLARE nextnumb INTEGER DEFAULT COALESCE(_get('tnumb'), 0) + 1;
    RETURN _set('tnumb', nextnumb, '');
END //

DROP FUNCTION IF EXISTS _add //
CREATE FUNCTION _add ( vlabel text, vvalue integer, vnote text )
RETURNS integer
DETERMINISTIC MODIFIES SQL DATA
BEGIN
    INSERT INTO __tcache__ (label, cid, value, note)
    VALUES (vlabel, connection_id(), vvalue, COALESCE(vnote, ''));
    RETURN vvalue;
END //

DROP PROCEDURE IF EXISTS _cleanup //
CREATE PROCEDURE _cleanup ()
DETERMINISTIC MODIFIES SQL DATA
BEGIN
    DELETE FROM __tcache__   WHERE cid = connection_id();
    DELETE FROM __tresults__ WHERE cid = connection_id();
end //

DROP FUNCTION IF EXISTS plan //
CREATE FUNCTION plan( numb integer) RETURNS TEXT
DETERMINISTIC READS SQL DATA
BEGIN
    DECLARE trash TEXT;
    IF _get('plan') IS NOT NULL THEN
        CALL _cleanup();
        -- Ugly hack to throw an exception.
        SELECT `You tried to plan twice!` INTO trash;
    END IF;

    RETURN concat('1..', _set('plan', numb, NULL ));
END //

DROP PROCEDURE IF EXISTS no_plan //
CREATE PROCEDURE no_plan()
DETERMINISTIC CONTAINS SQL
BEGIN
    DECLARE hide TEXT DEFAULT plan(0);
END //

DROP FUNCTION IF EXISTS add_result //
CREATE FUNCTION add_result ( vok bool, vaok bool, vdescr text, vtype text, vreason text )
RETURNS integer
DETERMINISTIC MODIFIES SQL DATA
BEGIN
    DECLARE tnumb INTEGER DEFAULT _nextnumb();
    INSERT INTO __tresults__ ( numb, cid, ok, aok, descr, type, reason )
    VALUES(tnumb, connection_id(), vok, vaok, coalesce(vdescr, ''), coalesce(vtype, ''), coalesce(vreason, ''));
    RETURN tnumb;
END //

DROP FUNCTION IF EXISTS _tap //
CREATE FUNCTION _tap(aok BOOLEAN, test_num INTEGER, descr TEXT, todo_why TEXT)
RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
    RETURN concat(CASE aok WHEN TRUE THEN '' ELSE 'not ' END,
        'ok ', test_num,
        CASE descr WHEN '' THEN '' ELSE COALESCE( concat(' - ', substr(diag( descr ), 3)), '' ) END,
        COALESCE( concat(' ', diag( concat('TODO ', todo_why) )), ''),
        CASE WHEN aok THEN '' ELSE concat('\n',
            diag(concat('Failed ',
                CASE WHEN todo_why IS NULL THEN '' ELSE '(TODO) ' END,
                'test ', test_num,
                CASE descr WHEN '' THEN '' ELSE COALESCE(concat(': "', descr, '"'), '') END,
                CASE WHEN aok IS NULL THEN concat('\n', '    (test result was NULL)') ELSE '' END
        ))) END
    );
END //

DROP FUNCTION IF EXISTS ok //
CREATE FUNCTION ok(aok BOOLEAN, descr TEXT) RETURNS TEXT
DETERMINISTIC MODIFIES SQL DATA
BEGIN
    DECLARE todo_why TEXT DEFAULT _todo();
    DECLARE ok BOOLEAN;
    DECLARE test_num INTEGER;

    SET ok = CASE
        WHEN aok THEN aok
        WHEN todo_why IS NULL THEN COALESCE(aok, 0)
        ELSE 1
    END;

    SET test_num = add_result(
        ok,
        COALESCE(aok, false),
        descr,
        CASE WHEN todo_why IS NULL THEN '' ELSE 'todo' END,
        COALESCE(todo_why, '')
    );

    RETURN _tap(aok, test_num, descr, todo_why);

END //

DROP FUNCTION IF EXISTS num_failed //
CREATE FUNCTION num_failed () RETURNS INTEGER
READS SQL DATA
BEGIN
    DECLARE ret integer;
    SELECT COUNT(*) INTO ret
      FROM __tresults__
     WHERE cid = connection_id()
       AND ok  = 0;
    RETURN ret;
END //

DROP FUNCTION IF EXISTS _finish //
CREATE FUNCTION _finish ( curr_test INTEGER,  exp_tests INTEGER, num_faild INTEGER)
RETURNS TEXT
DETERMINISTIC MODIFIES SQL DATA
BEGIN
    DECLARE ret    TEXT DEFAULT '';
    DECLARE plural CHAR DEFAULT '';
    IF exp_tests = 1 THEN SET plural = 's'; END IF;

    IF curr_test IS NULL THEN
        CALL _cleanup();
        -- Ugly hack to throw an exception.
        SELECT `# No tests run!` INTO ret;
    END IF;

    IF exp_tests = 0 OR exp_tests IS NULL THEN
         -- No plan. Output one now.
        SET exp_tests = curr_test;
        SET ret = concat('1..', COALESCE(exp_tests, 0));
    END IF;

    IF curr_test <> exp_tests THEN
        SET ret = concat(ret, CASE WHEN ret THEN '\n' ELSE '' END, diag(concat(
            'Looks like you planned ', exp_tests, ' test',
            plural, ' but ran ', curr_test
        )));
    ELSEIF num_faild > 0 THEN
        SET ret = concat(ret, CASE WHEN ret THEN '\n' ELSE '' END, diag(concat(
            'Looks like you failed ', num_faild, ' test',
            CASE num_faild WHEN 1 THEN '' ELSE 's' END,
            ' of ', exp_tests
        )));
    END IF;

    -- Clean up our mess.
    CALL _cleanup();
    RETURN ret;
END //

DROP PROCEDURE IF EXISTS finish //
CREATE PROCEDURE finish ()
READS SQL DATA
BEGIN
    DECLARE msg TEXT DEFAULT _finish(
        _get('tnumb'),
        _get('plan'),
        num_failed()
    );
    if msg IS NOT NULL AND msg <> '' THEN SELECT msg; END IF;
END //

DROP FUNCTION IF EXISTS diag //
CREATE FUNCTION diag ( msg text ) RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
    RETURN concat('# ', replace(
       replace(
            replace( msg, '\r\n', '\n# ' ),
            '\n',
            '\n# '
        ),
        '\r',
        '\n# '
    ));
END //

DROP FUNCTION IF EXISTS _get_latest_value //
CREATE FUNCTION _get_latest_value ( vlabel text )
RETURNS integer
READS SQL DATA
BEGIN
    DECLARE ret integer;
    SELECT value INTO ret
      FROM __tcache__
     WHERE cid = connection_id()
       AND label = vlabel
       AND id = (SELECT MAX(id) FROM __tcache__ WHERE cid = connection_id() AND label = vlabel)
     LIMIT 1;
    RETURN ret;
END //

DROP FUNCTION IF EXISTS _get_latest_id //
CREATE FUNCTION _get_latest_id ( vlabel text )
RETURNS integer
READS SQL DATA
BEGIN
    DECLARE ret integer;
    SELECT id INTO ret
      FROM __tcache__
     WHERE cid = connection_id()
       AND label = vlabel
       AND id = (SELECT MAX(id) FROM __tcache__ WHERE cid = connection_id() AND label = vlabel)
     LIMIT 1;
    RETURN ret;
END //

DROP FUNCTION IF EXISTS _get_latest_with_value //
CREATE FUNCTION _get_latest_with_value ( vlabel text, vvalue integer ) RETURNS INTEGER
READS SQL DATA
BEGIN
    DECLARE ret integer;
    SELECT MAX(id)
      INTO ret
      FROM __tcache__
     WHERE label = vlabel
       AND value = vvalue
       AND cid = connection_id();
    RETURN ret;
END //

DROP FUNCTION IF EXISTS _todo //
CREATE FUNCTION _todo() RETURNS TEXT
DETERMINISTIC MODIFIES SQL DATA
BEGIN
    -- Get the latest id and value, because todo() might have been called
    -- again before the todos ran out for the first call to todo(). This
    -- allows them to nest.
    DECLARE todos   INTEGER DEFAULT _get_latest_value('todo');
    DECLARE todo_id INTEGER;
    DECLARE note    TEXT;

    IF todos IS NULL THEN
        -- No todos.
        RETURN NULL;
    END IF;

    SET todo_id = _get_latest_id('todo');
    IF todos = 0 THEN
        -- Todos depleted. Clean up.
        DELETE FROM __tcache__ WHERE id = todo_id;
        RETURN NULL;
    END IF;
    -- Decrement the count of counted todos and return the reason.
    IF todos <> -1 THEN
        CALL _idset(todo_id, todos - 1);
    END IF;

    SET note = _get_note_by_id(todo_id);
    IF todos = 1 THEN
        -- This was the last todo, so delete the record.
        DELETE FROM __tcache__ WHERE id = todo_id;
    END IF;
    RETURN note;
END //

DROP FUNCTION IF EXISTS _get_note_by_id //
CREATE FUNCTION _get_note_by_id ( vid integer ) RETURNS text
READS SQL DATA
BEGIN
    DECLARE ret TEXT;
    SELECT note INTO ret FROM __tcache__ WHERE id = vid  LIMIT 1;
    RETURN ret;
END //

DROP FUNCTION IF EXISTS _eq //
CREATE FUNCTION _eq( have TEXT, want TEXT) RETURNS BOOLEAN
DETERMINISTIC CONTAINS SQL
BEGIN
    RETURN (have IS NOT NULL AND want IS NOT NULL AND have = want)
        OR (have IS NULL AND want IS NULL)
        OR 0;
END //

DROP FUNCTION IF EXISTS eq //
CREATE FUNCTION eq( have TEXT, want TEXT, descr TEXT) RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
    IF _eq(have, want) THEN RETURN ok(1, descr); END IF;

    -- Fail.
    RETURN concat( ok(0, descr), '\n', diag(concat(
           '        have: ', COALESCE(have, 'NULL'),
         '\n        want: ', COALESCE(want, 'NULL')
    )));
END //

DROP FUNCTION IF EXISTS not_eq //
CREATE FUNCTION not_eq( have TEXT, want TEXT, descr TEXT) RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
    IF NOT _eq(have, want) THEN RETURN ok(1, descr); END IF;

    -- Fail.
    RETURN concat( ok(0, descr), '\n', diag(concat(
           '        have: ', COALESCE(have, 'NULL'),
         '\n        want: anything else'
    )));
END //

DROP FUNCTION IF EXISTS _alike //
CREATE FUNCTION _alike ( res BOOLEAN, got TEXT, pat TEXT, descr TEXT ) RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
    IF res THEN RETURN  ok( res, descr ); END IF;
    RETURN concat(ok(res, descr), '\n',  diag(concat(
           '                  ', COALESCE( quote(got), 'NULL' ),
        '\n   doesn''t match: ', COALESCE( quote(pat), 'NULL' )
    )));
END //

DROP FUNCTION IF EXISTS matches //
CREATE FUNCTION matches ( got TEXT, pat TEXT, descr TEXT ) RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
    RETURN _alike( got REGEXP pat, got, pat, descr );
END //

DROP FUNCTION IF EXISTS alike //
CREATE FUNCTION alike ( got TEXT, pat TEXT, descr TEXT ) RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
    RETURN _alike( got LIKE pat, got, pat, descr );
END //

DROP FUNCTION IF EXISTS _unalike //
CREATE FUNCTION _unalike ( res BOOLEAN, got TEXT, pat TEXT, descr TEXT ) RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
    IF res THEN RETURN  ok( res, descr ); END IF;
    RETURN concat(ok(res, descr), '\n',  diag(concat(
           '                  ', COALESCE( quote(got), 'NULL' ),
        '\n          matches: ', COALESCE( quote(pat), 'NULL' )
    )));
END //

DROP FUNCTION IF EXISTS doesnt_match //
CREATE FUNCTION doesnt_match ( got TEXT, pat TEXT, descr TEXT ) RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
    RETURN _unalike( got NOT REGEXP pat, got, pat, descr );
END //

DROP FUNCTION IF EXISTS unalike //
CREATE FUNCTION unalike ( got TEXT, pat TEXT, descr TEXT ) RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
    RETURN _unalike( got NOT LIKE pat, got, pat, descr );
END //

DROP FUNCTION IF EXISTS pass //
CREATE FUNCTION pass(descr TEXT) RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
    RETURN ok(1, descr);
END //

DROP FUNCTION IF EXISTS fail //
CREATE FUNCTION fail(descr TEXT) RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
    RETURN ok(0, descr);
END //

DROP FUNCTION IF EXISTS is_reserved //
CREATE FUNCTION is_reserved(word TEXT) RETURNS BOOLEAN
DETERMINISTIC CONTAINS SQL
BEGIN
    RETURN UPPER(word) IN (
        'ADD',                    'ALL',                    'ALTER',
        'ANALYZE',                'AND',                    'AS',
        'ASC',                    'ASENSITIVE',             'BEFORE',
        'BETWEEN',                'BIGINT',                 'BINARY',
        'BLOB',                   'BOTH',                   'BY',
        'CALL',                   'CASCADE',                'CASE',
        'CHANGE',                 'CHAR',                   'CHARACTER',
        'CHECK',                  'COLLATE',                'COLUMN',
        'CONDITION',              'CONSTRAINT',             'CONTINUE',
        'CONVERT',                'CREATE',                 'CROSS',
        'CURRENT_DATE',           'CURRENT_TIME',           'CURRENT_TIMESTAMP',
        'CURRENT_USER',           'CURSOR',                 'DATABASE',
        'DATABASES',              'DAY_HOUR',               'DAY_MICROSECOND',
        'DAY_MINUTE',             'DAY_SECOND',             'DEC',
        'DECIMAL',                'DECLARE',                'DEFAULT',
        'DELAYED',                'DELETE',                 'DESC',
        'DESCRIBE',               'DETERMINISTIC',          'DISTINCT',
        'DISTINCTROW',            'DIV',                    'DOUBLE',
        'DROP',                   'DUAL',                   'EACH',
        'ELSE',                   'ELSEIF',                 'ENCLOSED',
        'ESCAPED',                'EXISTS',                 'EXIT',
        'EXPLAIN',                'FALSE',                  'FETCH',
        'FLOAT',                  'FLOAT4',                 'FLOAT8',
        'FOR',                    'FORCE',                  'FOREIGN',
        'FROM',                   'FULLTEXT',               'GRANT',
        'GROUP',                  'HAVING',                 'HIGH_PRIORITY',
        'HOUR_MICROSECOND',       'HOUR_MINUTE',            'HOUR_SECOND',
        'IF',                     'IGNORE',                 'IN',
        'INDEX',                  'INFILE',                 'INNER',
        'INOUT',                  'INSENSITIVE',            'INSERT',
        'INT',                    'INT1',                   'INT2',
        'INT3',                   'INT4',                   'INT8',
        'INTEGER',                'INTERVAL',               'INTO',
        'IS',                     'ITERATE',                'JOIN',
        'KEY',                    'KEYS',                   'KILL',
        'LEADING',                'LEAVE',                  'LEFT',
        'LIKE',                   'LIMIT',                  'LINES',
        'LOAD',                   'LOCALTIME',              'LOCALTIMESTAMP',
        'LOCK',                   'LONG',                   'LONGBLOB',
        'LONGTEXT',               'LOOP',                   'LOW_PRIORITY',
        'MATCH',                  'MEDIUMBLOB',             'MEDIUMINT',
        'MEDIUMTEXT',             'MIDDLEINT',              'MINUTE_MICROSECOND',
        'MINUTE_SECOND',          'MOD',                    'MODIFIES',
        'NATURAL',                'NOT',                    'NO_WRITE_TO_BINLOG',
        'NULL',                   'NUMERIC',                'ON',
        'OPTIMIZE',               'OPTION',                 'OPTIONALLY',
        'OR',                     'ORDER',                  'OUT',
        'OUTER',                  'OUTFILE',                'PRECISION',
        'PRIMARY',                'PROCEDURE',              'PURGE',
        'RAID0',                  'READ',                   'READS',
        'REAL',                   'REFERENCES',             'REGEXP',
        'RELEASE',                'RENAME',                 'REPEAT',
        'REPLACE',                'REQUIRE',                'RESTRICT',
        'RETURN',                 'REVOKE',                 'RIGHT',
        'RLIKE',                  'SCHEMA',                 'SCHEMAS',
        'SECOND_MICROSECOND',     'SELECT',                 'SENSITIVE',
        'SEPARATOR',              'SET',                    'SHOW',
        'SMALLINT',               'SONAME',                 'SPATIAL',
        'SPECIFIC',               'SQL',                    'SQLEXCEPTION',
        'SQLSTATE',               'SQLWARNING',             'SQL_BIG_RESULT',
        'SQL_CALC_FOUND_ROWS',    'SQL_SMALL_RESULT',       'SSL',
        'STARTING',               'STRAIGHT_JOIN',          'TABLE',
        'TERMINATED',             'THEN',                   'TINYBLOB',
        'TINYINT',                'TINYTEXT',               'TO',
        'TRAILING',               'TRIGGER',                'TRUE',
        'UNDO',                   'UNION',                  'UNIQUE',
        'UNLOCK',                 'UNSIGNED',               'UPDATE',
        'USAGE',                  'USE',                    'USING',
        'UTC_DATE',               'UTC_TIME',               'UTC_TIMESTAMP',
        'VALUES',                 'VARBINARY',              'VARCHAR',
        'VARCHARACTER',           'VARYING',                'WHEN',
        'WHERE',                  'WHILE',                  'WITH',
        'WRITE',                  'X509',                   'XOR',
        'YEAR_MONTH',             'ZEROFILL',
        'ASENSITIVE',             'CALL',                   'CONDITION',
        'CONTINUE',               'CURSOR',                 'DECLARE',
        'DETERMINISTIC',          'EACH',                   'ELSEIF',
        'EXIT',                   'FETCH',                  'INOUT',
        'INSENSITIVE',            'ITERATE',                'LEAVE',
        'LOOP',                   'MODIFIES',               'OUT',
        'READS',                  'RELEASE',                'REPEAT',
        'RETURN',                 'SCHEMA',                 'SCHEMAS',
        'SENSITIVE',              'SPECIFIC',               'SQL',
        'SQLEXCEPTION',           'SQLSTATE',               'SQLWARNING',
        'TRIGGER',                'UNDO',                   'WHILE',
        'ACTION', 'BIT', 'DATE', 'ENUM', 'NO', 'TEXT', 'TIME', 'TIMESTAMP'
    );
END //

DROP FUNCTION IF EXISTS quote_ident //
CREATE FUNCTION quote_ident(ident TEXT) RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
    IF ISNULL(ident) THEN
      RETURN 'NULL';
    END IF;

    IF ident = '' THEN
      RETURN '\'\'';
    END IF;

    IF LOCATE('ANSI_QUOTES', @@SQL_MODE) > 0 THEN
        IF is_reserved(ident) OR locate('"', ident) > 0 THEN
            RETURN concat('"', replace(ident, '"', '""'), '"');
        END IF;
    ELSE
        IF is_reserved(ident) OR locate('`', ident) > 0 THEN
            RETURN concat('`', replace(ident, '`', '``'), '`');
        END IF;
    END IF;

    RETURN ident;
END //



-- Just do it
-- I wish people wouldn't choose identifiers that need quoting,
-- but they do, and often just because they can. MySQL has no
-- array type (yet), which would make a lot of this simpler, so
-- we have to lay down some rules about how identifiers
-- can be presented for tests. In the end this boils down to:

-- lists must have all elements quoted
-- and
-- there can't be any spaces between elements because they are
-- legal characters in a quoted identifier.

-- In addition, all identifiers need be presented in a
-- consistent manner because the lack of function overloading means
-- you can't have similarly named functions to deal with multi-valued
-- identifier checks and scalar value ones. This, in turn, means
-- that scalars that wouldn't normally need quoting need to be and
-- that the quoting method needs to be consistent.

DROP FUNCTION IF EXISTS qi //
CREATE FUNCTION qi(ident TEXT) RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
-- It's quoted already return it
-- replace ANSI quotes with backticks
-- add backticks to everything else
-- This won't work for people who use quotes within identifiers
-- but they deserve everything coming to them anyway.

  IF LEFT(ident,1) = '`' AND RIGHT(ident,1) = '`' THEN
	  RETURN ident;
  END IF;

  IF LEFT(ident,1) = '"' AND RIGHT(ident,1) = '"' THEN
	  RETURN CONCAT('`', TRIM(BOTH '"' FROM ident) ,'`');
  END IF;

  RETURN CONCAT('`', ident, '`');
END //


DROP FUNCTION IF EXISTS uqi //
CREATE FUNCTION uqi(ident TEXT) RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
-- We may want to unquote it for the sake of comparison

  IF LEFT(ident,1) = '`' AND RIGHT(ident,1) = '`' THEN
	  RETURN TRIM(BOTH '`' FROM REPLACE(ident,'``','`'));
  END IF;

  IF LEFT(ident,1) = '"' AND RIGHT(ident,1) = '"' THEN
	  RETURN TRIM(BOTH '"' FROM REPLACE(ident,'""','"'));
  END IF;

  RETURN ident;
END //

DROP FUNCTION IF EXISTS qv //
CREATE FUNCTION qv(val TEXT) RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
    IF ISNULL(val) THEN
      RETURN 'NULL';
    END IF;

    -- NB this will catch number only hex eg 000000 or 009600
    IF val REGEXP '^[[:digit:]]+$' THEN
      RETURN val;
    END IF;

    RETURN CONCAT('\'', REPLACE(val, '''', '\\\''), '\'');
END //

-- quote as a string or NULL
DROP FUNCTION IF EXISTS qs //
CREATE FUNCTION qs(val TEXT) RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
    IF ISNULL(val) THEN
      RETURN 'NULL';
    END IF;

    RETURN CONCAT('\'', REPLACE(val, '''', '\\\''), '\'');
END //


DROP FUNCTION IF EXISTS dqv //
CREATE FUNCTION dqv(val TEXT) RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
    IF ISNULL(val) THEN
      RETURN 'NULL';
    END IF;

    -- NB this will catch number only hex eg 000000 or 009600
    IF val REGEXP '^[[:digit:]]+$' THEN
      RETURN val;
    END IF;

    RETURN CONCAT('"', REPLACE(val, '''', '\\\''), '"');
END //


-- check_test( test_output, pass, name, description, diag, match_diag )
DROP FUNCTION IF EXISTS check_test //
CREATE FUNCTION check_test(
    have    TEXT,
    eok     BOOLEAN,
    name    TEXT,
    edescr  TEXT,
    ediag   TEXT,
    matchit BOOLEAN
) RETURNS TEXT
DETERMINISTIC MODIFIES SQL DATA
BEGIN
    DECLARE tnumb   INTEGER DEFAULT _get('tnumb');
    DECLARE hok     BOOLEAN;
    DECLARE hdescr  TEXT;
    DECLARE ddescr  TEXT;
    DECLARE hdiag   TEXT;
    DECLARE tap     TEXT;
    DECLARE myok    BOOLEAN;

    -- Fetch the result.
    SELECT aok, descr INTO hok ,hdescr
      FROM __tresults__ WHERE numb = tnumb;

    SET myok = CASE WHEN hok = eok THEN 1 ELSE 0 END;

    -- Set up the description.
    SET ddescr = concat(coalesce( concat(name, ' '), 'Test ' ), 'should ');

    -- Replace the test result with this test result.
    UPDATE __tresults__
       SET ok     = myok,
           aok    = myok,
           descr  = concat(ddescr, CASE WHEN eok then 'pass' ELSE 'fail' END),
           type   = '',
           reason = ''
     WHERE numb = tnumb;
    SET tap = _tap(myok, tnumb, concat(ddescr, CASE WHEN eok then 'pass' ELSE 'fail' END), NULL);

    -- Was the description as expected?
    IF edescr IS NOT NULL THEN
        SET tap = concat(tap, '\n', eq(
            hdescr,
            edescr,
            concat(ddescr, 'have the proper description')
        ));
    END IF;

    -- Were the diagnostics as expected?
    IF ediag IS NOT NULL THEN
        -- Remove ok and the test number.
        SET hdiag = substring(
            have
            FROM (CASE WHEN hok THEN 4 ELSE 9 END) + char_length(tnumb)
        );

        -- Remove the description, if there is one.
        IF hdescr <> '' THEN
            SET hdiag = substring( hdiag FROM 3 + char_length( diag( hdescr ) ) );
        END IF;

        -- Remove failure message from ok().
        IF NOT hok THEN
           SET hdiag = substring(
               hdiag
               FROM 14 + char_length(tnumb)
                       + CASE hdescr WHEN '' THEN 3 ELSE 3 + char_length( diag( hdescr ) ) END
           );
        END IF;

        -- Remove the #s.
        SET hdiag = replace( substring(hdiag from 3), '\n# ', '\n' );

        -- Now compare the diagnostics.
        IF matchit THEN
            SET tap = concat(tap, '\n', matches(
                hdiag,
                ediag,
                concat(ddescr, 'have the proper diagnostics')
            ));
        ELSE
            SET tap = concat(tap, '\n', eq(
                hdiag,
                ediag,
                concat(ddescr, 'have the proper diagnostics')
            ));
        END IF;
    END IF;

    -- And we're done
    RETURN tap;
END //

DROP PROCEDURE IF EXISTS todo //
CREATE PROCEDURE todo (how_many int, why text)
DETERMINISTIC CONTAINS SQL
BEGIN
    DECLARE hide INTEGER DEFAULT _add('todo', COALESCE(how_many, 1), COALESCE(why, ''));
END //

DROP PROCEDURE IF EXISTS todo_start //
CREATE PROCEDURE todo_start (why text)
DETERMINISTIC CONTAINS SQL
BEGIN
    DECLARE hide INTEGER DEFAULT _add('todo', -1, COALESCE(why, ''));
END //

DROP FUNCTION IF EXISTS in_todo //
CREATE FUNCTION in_todo () RETURNS BOOLEAN
READS SQL DATA
BEGIN
    RETURN CASE WHEN _get('todo') IS NULL THEN 0 ELSE 1 END;
END //

DROP PROCEDURE IF EXISTS todo_end //
CREATE PROCEDURE todo_end ()
DETERMINISTIC MODIFIES SQL DATA
BEGIN
    DECLARE tid INTEGER DEFAULT _get_latest_with_value( 'todo', -1 );
    DECLARE trash TEXT;
    IF tid IS NULL THEN
        CALL _cleanup();
        SELECT  `todo_end() called without todo_start()` INTO trash;
    END IF;
    DELETE FROM __tcache__ WHERE id = tid;
END //

DROP FUNCTION IF EXISTS skip //
CREATE FUNCTION skip ( how_many int, why text )
RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
    DECLARE tap TEXT DEFAULT '';
    REPEAT
        SET tap = concat(
            tap,
            CASE WHEN tap = '' THEN '' ELSE '\n' END,
            ok(1, concat('SKIP: ', COALESCE(why, '')))
        );
        SET how_many = how_many - 1;
    UNTIL how_many = 0 END REPEAT;
    RETURN tap;
END //

-- fix up a comma separated list of values to compare
-- against a list of db objects
DROP FUNCTION IF EXISTS _fixCSL //
CREATE FUNCTION _fixCSL (want TEXT)
RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN

	SET want = REPLACE(want, '''','');
	SET want = REPLACE(want, '"','');
	SET want = REPLACE(want, '\n','');

-- invalid characters eg NUL byte and characters > U+10000
--   IF want REGEXP '[[.NUL.]\\u10000-\\u10FFFD]' = 1 THEN
--		RETURN NULL;
-- 	END IF;

	RETURN want;
END //


-- general pgTAP method to pretty print differences in lists
DROP FUNCTION IF EXISTS _are //
CREATE FUNCTION _are (what TEXT, extras TEXT, missing TEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
DECLARE msg TEXT    DEFAULT '';
DECLARE res BOOLEAN DEFAULT TRUE;

  IF extras <> '' THEN
    SET res = FALSE;
    SET msg = CONCAT('\n', CONCAT('\n'
      '    Extra ', what, ':\n       ' , REPLACE( extras, ',', '\n       ')));
  END IF;

  IF missing <> '' THEN
    SET res = FALSE;
    SET msg = CONCAT(msg, CONCAT('\n'
      '    Missing ', what, ':\n       ' , REPLACE( missing, ',', '\n       ')));
  END IF;

  RETURN CONCAT(ok(res, description), diag(msg));
END //


-- de-alias datatype synonyms to ensure consistent test for equality
-- a test shouldn't fail because it uses a valid synonym
-- sql_mode REAL_AS_FLOAT changes the aliased type when set

DROP FUNCTION IF EXISTS _datatype //
CREATE FUNCTION _datatype(word TEXT) RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN

  SET word =
    CASE
      WHEN word IN ('BOOL', 'BOOLEAN') THEN 'TINYINT'
      WHEN word =  'INTEGER' THEN 'INT'
      WHEN word IN ('DEC', 'NUMERIC', 'FIXED') THEN 'DECIMAL'
      WHEN word IN ('DOUBLE_PRECISION') THEN 'DOUBLE'
      WHEN word = 'REAL' THEN IF (INSTR(@@GLOBAL.sql_mode, 'REAL_AS_FLOAT') > 0 , 'FLOAT' , 'DOUBLE')
      WHEN word IN ('NCHAR', 'CHARACTER', 'NATIONAL_CHARACTER') THEN 'CHAR'
      WHEN word IN ('NVARCHAR', 'VARCHARACTER', 'CHARACTER_VARYING', 'NATIONAL_VARCHAR') THEN 'VARCHAR'
      WHEN word = 'CHAR_BYTE' THEN 'BIT'
      ELSE word
	END ;

  RETURN word;
END //

-- upper case first character of word
DROP FUNCTION IF EXISTS ucf //
CREATE FUNCTION ucf(val TEXT)
RETURNS TEXT
DETERMINISTIC CONTAINS SQL
BEGIN
  RETURN CONCAT(UPPER(LEFT(val, 1)), LOWER(SUBSTRING(val, 2)));
END //



/***********************************************************************************/
-- Utility functions for *_are style test.
-- Create and populate tmp tables
-- Diff expected against current to find missing and extra

DROP PROCEDURE IF EXISTS _populate_want //
CREATE PROCEDURE _populate_want(IN want TEXT)
DETERMINISTIC MODIFIES SQL DATA
COMMENT 'Create a temp table and populate with comma-separated data'
BEGIN
  DECLARE sep       CHAR(1) DEFAULT ',';
  DECLARE seplength INTEGER DEFAULT CHAR_LENGTH(sep);

  SET want = _fixCSL(want);

  DROP TEMPORARY TABLE IF EXISTS `want`;
  CREATE TEMPORARY TABLE `tap`.`want` (ident VARCHAR(64) PRIMARY KEY)
    ENGINE MEMORY CHARSET utf8 COLLATE utf8_general_ci;

  WHILE want != '' > 0 DO
    SET @val = TRIM(SUBSTRING_INDEX(want, sep, 1));
    SET @val = uqi(@val);
    IF  @val <> '' THEN
      INSERT IGNORE INTO `want` VALUE(@val);
    END IF;
    SET want = SUBSTRING(want, CHAR_LENGTH(@val) + seplength + 1);
  END WHILE;
END //

DROP PROCEDURE IF EXISTS _populate_have //
CREATE PROCEDURE _populate_have(IN have TEXT)
DETERMINISTIC MODIFIES SQL DATA
COMMENT 'Create a temp table and populate with comma-separated data'
BEGIN
  DECLARE sep       CHAR(1) DEFAULT ',';
  DECLARE seplength INTEGER DEFAULT CHAR_LENGTH(sep);

  SET have = _fixCSL(have);

  DROP TEMPORARY TABLE IF EXISTS `have`;
  CREATE TEMPORARY TABLE `tap`.`have` (ident VARCHAR(64) PRIMARY KEY)
    ENGINE MEMORY CHARSET utf8 COLLATE utf8_general_ci;

  WHILE have != '' > 0 DO
    SET @val = TRIM(SUBSTRING_INDEX(have, sep, 1));
    SET @val = uqi(@val);
    IF  @val <> '' THEN
      INSERT IGNORE INTO `have` VALUE(@val);
    END IF;
    SET have = SUBSTRING(have, CHAR_LENGTH(@val) + seplength + 1);
  END WHILE;
END //


DROP FUNCTION IF EXISTS _missing //
CREATE FUNCTION _missing(have TEXT)
RETURNS TEXT
DETERMINISTIC CONTAINS SQL
COMMENT 'Internal function to identify items listed want list but not in have input'
BEGIN
  DECLARE ret TEXT;

  SET @have = REPLACE(have,'`','');

  SELECT GROUP_CONCAT(qi(`ident`)) INTO ret
  FROM `want`
-- test @have in a null safe manner
  WHERE NOT COALESCE(FIND_IN_SET(`ident`, @have),0);

  RETURN COALESCE(ret, '');
END //

DROP FUNCTION IF EXISTS _extra //
CREATE FUNCTION _extra(want TEXT)
RETURNS TEXT
DETERMINISTIC CONTAINS SQL
COMMENT 'Internal function to identify existing objects not in the want list'
BEGIN
  DECLARE ret TEXT;

  SET @want = REPLACE(want,'`','');

  SELECT GROUP_CONCAT(qi(`ident`)) INTO ret
  FROM `have`
  WHERE NOT COALESCE(FIND_IN_SET(`ident`, @want),0);

  RETURN COALESCE(ret, '');
END //


/***********************************************************************************/

DELIMITER ;
