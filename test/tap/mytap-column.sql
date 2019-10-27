USE tap;

DELIMITER //

/****************************************************************************/

-- internal function to check

DROP FUNCTION IF EXISTS _has_column  //
CREATE FUNCTION _has_column(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
READS SQL DATA
BEGIN
  DECLARE ret BOOLEAN;

  SELECT 1 INTO ret
  FROM `information_schema`.`columns`
  WHERE `table_schema` = sname
  AND `table_name` = tname
  AND `column_name` = cname;

  RETURN coalesce(ret, 0);
END //


-- has_column(schema, table, column, description)
DROP FUNCTION IF EXISTS has_column //
CREATE FUNCTION has_column(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
CONTAINS SQL
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Column ',
      quote_ident(tname), '.', quote_ident(cname), ' should exist');
  END IF;

  IF NOT _has_table(sname, tname) THEN
    RETURN CONCAT(ok(FALSE,description), '\n',
      diag(CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
        ' does not exist')));
  END IF;

  RETURN ok(_has_column(sname, tname, cname), description);
END //


-- hasnt_column(schema, table, column, description)
DROP FUNCTION IF EXISTS hasnt_column //
CREATE FUNCTION hasnt_column(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
CONTAINS SQL
BEGIN
  IF description = '' THEN
    SET description = concat('Column ',
      quote_ident(tname), '.', quote_ident(cname), ' should not exist');
  END IF;

  IF NOT _has_table(sname, tname) THEN
    RETURN CONCAT(ok(FALSE,description), '\n',
      diag(CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
        ' does not exist')));
  END IF;

RETURN ok(NOT _has_column(sname, tname, cname), description);
END //


/****************************************************************************/

-- NULLABLE
-- _col_nullable(schema, table, column)
DROP FUNCTION IF EXISTS _col_nullable //
CREATE FUNCTION _col_nullable(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64))
RETURNS VARCHAR(3)
DETERMINISTIC
READS SQL DATA
BEGIN
  DECLARE ret VARCHAR(3);

  SELECT `is_nullable` INTO ret
  FROM `information_schema`.`columns`
  WHERE `table_schema` = sname
  AND `table_name` = tname
  AND `column_name` = cname;

  RETURN ret;
END //


-- col_is_null(schema, table, column)
DROP FUNCTION IF EXISTS col_is_null //
CREATE FUNCTION col_is_null(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
CONTAINS SQL
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Column ',
      quote_ident(tname), '.', quote_ident(cname), ' should allow NULL');
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE,description), '\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN eq(_col_nullable(sname, tname, cname),'YES', description);
END //


-- col_not_null(schema, table, column, description)
DROP FUNCTION IF EXISTS col_not_null //
CREATE FUNCTION col_not_null(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
CONTAINS SQL
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Column ',
      quote_ident(tname), '.', quote_ident(cname), ' should be NOT NULL');
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE,description), '\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN eq(_col_nullable(sname, tname, cname), 'NO', description);
END //


/****************************************************************************/

-- _col_has_primary_key (schema, table, column)

DROP FUNCTION IF EXISTS _col_has_primary_key //
CREATE FUNCTION _col_has_primary_key(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
READS SQL DATA
BEGIN
  DECLARE ret BOOLEAN;

  SELECT 1 INTO ret
  FROM `information_schema`.`columns`
  WHERE `table_schema` = sname
  AND `table_name` = tname
  AND `column_name` = cname
  AND `column_key` = 'PRI';

  RETURN coalesce(ret, false);
END //

-- col_has_primary_key (schema, table, column)
DROP FUNCTION IF EXISTS col_has_primary_key //
CREATE FUNCTION col_has_primary_key(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
CONTAINS SQL
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Column ',
      quote_ident(tname), '.', quote_ident(cname), ' should be a Primary Key (or part thereof)');
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE,description), '\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN ok(_col_has_primary_key(sname, tname, cname), description);
END //

-- col_hasnt_primary_key(schema, table, column)
DROP FUNCTION IF EXISTS col_hasnt_primary_key //
CREATE FUNCTION col_hasnt_primary_key(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
CONTAINS SQL
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Column ',
      quote_ident(tname), '.', quote_ident(cname), ' should not be a Primary Key (or part thereof)');
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE,description), '\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN ok(NOT _col_has_primary_key(sname, tname, cname), description);
END //

/****************************************************************************/

-- _col_has_index_key (schema, table, column)

DROP FUNCTION IF EXISTS _col_has_index_key //
CREATE FUNCTION _col_has_index_key(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
READS SQL DATA
BEGIN
  DECLARE ret BOOLEAN;

  SELECT 1 INTO ret
  FROM `information_schema`.`statistics`
  WHERE `table_schema` = sname
  AND `table_name` = tname
  AND `column_name` = cname
  AND `index_name` <> 'PRIMARY'
  LIMIT 1;

  RETURN coalesce(ret, false);
END //

-- col_has_index_key (schema, table, column)
DROP FUNCTION IF EXISTS col_has_index_key //
CREATE FUNCTION col_has_index_key(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
CONTAINS SQL
BEGIN
  IF description = '' THEN
    SET description = concat('Column ',
      quote_ident(tname), '.', quote_ident(cname), ' should have Index Key');
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE,description), '\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN ok(_col_has_index_key(sname, tname, cname), description);
END //

-- col_hasnt_index_key(schema, table, column)
DROP FUNCTION IF EXISTS col_hasnt_index_key //
CREATE FUNCTION col_hasnt_index_key(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
CONTAINS SQL
BEGIN
  IF description = '' THEN
    SET description = concat('Column ',
        quote_ident(tname), '.', quote_ident(cname), ' should not have Index Key');
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE,description), '\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN ok(NOT _col_has_index_key(sname, tname, cname), description);
END //


/****************************************************************************/

-- _col_has_unique_index (schema, table, column )

DROP FUNCTION IF EXISTS _col_has_unique_index //
CREATE FUNCTION _col_has_unique_index (sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
READS SQL DATA
BEGIN
  DECLARE ret BOOLEAN;

  SELECT true into ret
  FROM `information_schema`.`statistics`
  WHERE `table_schema` = sname
  AND `table_name` = tname
  AND `column_name` = cname
  AND `index_name` <> 'PRIMARY'
  AND `non_unique` = 0
  limit 1; /* only use the first entry */

  RETURN coalesce(ret, false);
END //

-- col_has_unique_index ( schema, table, column, keyname )
DROP FUNCTION IF EXISTS col_has_unique_index //
CREATE FUNCTION col_has_unique_index (sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
READS SQL DATA
BEGIN
  IF description = '' THEN
    SET description = concat('Column ',
      quote_ident(tname), '.', quote_ident(cname), ' should have unique INDEX');
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE,description), '\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN ok(_col_has_unique_index(sname, tname, cname), description);
END //

-- col_hasnt_unique_index( schema, table, column, keyname )
DROP FUNCTION IF EXISTS col_hasnt_unique_index //
CREATE FUNCTION col_hasnt_unique_index (sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
READS SQL DATA
BEGIN
  IF description = '' THEN
    SET description = concat('Column ',
      quote_ident(tname), '.', quote_ident(cname), ' should not have unique INDEX');
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE,description), '\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN ok(NOT _col_has_unique_index(sname, tname, cname), description);
END //

/****************************************************************************/
-- _col_has_non_unique_index (schema, table, column )

DROP FUNCTION IF EXISTS _col_has_non_unique_index //
CREATE FUNCTION _col_has_non_unique_index(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
READS SQL DATA
BEGIN
  DECLARE ret BOOLEAN;

  SELECT true into ret
  FROM `information_schema`.`statistics`
  WHERE `table_schema` = sname
  AND `table_name` = tname
  AND `column_name` = cname
  AND `index_name` <> 'PRIMARY'
  AND `non_unique` = 1
  limit 1; /* only use the first entry */

  RETURN coalesce(ret, false);
END //

-- col_has_non_unique_index ( schema, table, column, keyname )
DROP FUNCTION IF EXISTS col_has_non_unique_index //
CREATE FUNCTION col_has_non_unique_index(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
READS SQL DATA
BEGIN
  IF description = '' THEN
    SET description = concat('Column ',
      quote_ident(tname), '.', quote_ident(cname), ' should have non unique INDEX');
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE,description), '\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN ok( _col_has_non_unique_index(sname, tname, cname), description);
END //

-- col_hasnt_non_unique_index( schema, table, column, keyname )
DROP FUNCTION IF EXISTS col_hasnt_non_unique_index //
CREATE FUNCTION col_hasnt_non_unique_index(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
READS SQL DATA
BEGIN
  IF description = '' THEN
    SET description = concat('Column ',
       quote_ident(tname), '.', quote_ident(cname), ' should not have non unique INDEX');
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE,description), '\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN ok(NOT _col_has_non_unique_index(sname, tname, cname), descriptio);
END //

/****************************************************************************/
-- _col_has_named_index (schema, table, column)

DROP FUNCTION IF EXISTS _col_has_named_index //
CREATE FUNCTION _col_has_named_index(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), kname VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
READS SQL DATA
BEGIN
  DECLARE ret BOOLEAN;

  SELECT 1 INTO ret
  FROM `information_schema`.`statistics`
  WHERE `table_schema` = sname
  AND `table_name` = tname
  AND `column_name` = cname
  AND `index_name` = kname;

  RETURN COALESCE(ret, 0);
END //

-- col_has_named_index (schema, table, column, keyname)
DROP FUNCTION IF EXISTS col_has_named_index //
CREATE FUNCTION col_has_named_index(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), kname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
NO SQL
BEGIN
  SET kname := COALESCE(kname, cname); -- use the column name as index name if nothing is given

  IF description = '' THEN
    SET description = concat('Column ', quote_ident(tname), '.', quote_ident(cname),
      ' should have Index Key ', quote_ident(kname));
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE,description), '\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
' does not exist')));
  END IF;

  RETURN ok(_col_has_named_index(sname, tname, cname, kname), description);
END //

-- col_hasnt_named_index(schema, table, column, keyname)
DROP FUNCTION IF EXISTS col_hasnt_named_index //
CREATE FUNCTION col_hasnt_named_index(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), kname TEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
CONTAINS SQL
BEGIN
  SET kname := COALESCE(kname, cname); -- use the column name as index name if nothing is given
  IF description = '' THEN
    SET description = CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
      ' should not have INDEX Key ', quote_ident(kname));
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE,description), '\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN ok(NOT _col_has_named_index(sname, tname, cname, kname), description);
END //


/****************************************************************************/
-- _col_has_pos_in_named_index (schema, table, column, position)

DROP FUNCTION IF EXISTS _col_has_pos_in_named_index //
CREATE FUNCTION _col_has_pos_in_named_index(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), kname VARCHAR(64), pos INT)
RETURNS BOOLEAN
DETERMINISTIC
READS SQL DATA
BEGIN
  DECLARE ret BOOLEAN;

  SELECT 1 INTO ret
  FROM `information_schema`.`statistics`
  WHERE `table_schema` = sname
  AND `table_name` = tname
  AND `column_name` = cname
  AND `index_name` = kname
  AND `seq_in_index` = pos;

  RETURN coalesce(ret, 0);
END //


-- col_has_pos_in_named_index (schema, table, column, keyname, position)
DROP FUNCTION IF EXISTS col_has_pos_in_named_index //
CREATE FUNCTION col_has_pos_in_named_index(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), kname VARCHAR(64), pos INT, description TEXT)
RETURNS TEXT
DETERMINISTIC
CONTAINS SQL
BEGIN
  SET kname := COALESCE(kname, cname); -- use the column name as index name if nothing is given

  IF description = '' THEN
    SET description = concat('Column ',
      quote_ident(tname), '.', quote_ident(cname), ' should have position ',
        pos, ' in Index ', quote_ident(kname));
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE,description), '\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN ok(_col_has_pos_in_named_index(sname, tname, cname, kname, pos), description);
END //


-- col_hasnt_pos_in_named_index(schema, table, column, keyname, position)
DROP FUNCTION IF EXISTS col_hasnt_pos_in_named_index //
CREATE FUNCTION col_hasnt_pos_in_named_index(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), kname VARCHAR(64), pos INT, description TEXT)
RETURNS TEXT
DETERMINISTIC
CONTAINS SQL
BEGIN
  SET kname := COALESCE(kname, cname); -- use the column name as index name if nothing is given

  IF description = '' THEN
    SET description = CONCAT('Column ',
      quote_ident(tname), '.', quote_ident(cname), ' should not have position ',
        pos, ' in INDEX ', quote_ident(kname));
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE,description), '\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN ok(NOT _col_has_pos_in_named_index(sname, tname, cname, kname, pos), description);
END //

/****************************************************************************/
-- _col_has_type (schema, table, column, type)
-- This is the COLUMN type not the DATA type
-- so, VARCHAR(64) rather than VARCHAR

DROP FUNCTION IF EXISTS _col_has_type //
CREATE FUNCTION _col_has_type(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), ctype LONGTEXT)
RETURNS BOOLEAN
DETERMINISTIC
READS SQL DATA
BEGIN
  DECLARE ret BOOLEAN;

  SELECT 1 INTO ret
  FROM `information_schema`.`columns`
  WHERE `table_schema` = sname
  AND `table_name` = tname
  AND `column_name` = cname
  AND `column_type` = ctype;

  RETURN COALESCE(ret, 0);
END //

/*
 column_type is a mysql extension which includes the full definition of a column
*/
DROP FUNCTION IF EXISTS col_has_type //
CREATE FUNCTION col_has_type(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), ctype LONGTEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
NO SQL
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' should have Column Type ', qv(ctype));
    END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE,description), '\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN ok(_col_has_type(sname, tname, cname, ctype), description);
END //


/*************************************************************************************/

-- data type
DROP FUNCTION IF EXISTS _data_type //
CREATE FUNCTION _data_type(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64))
RETURNS LONGTEXT
DETERMINISTIC
READS SQL DATA
BEGIN
  DECLARE ret LONGTEXT;

  SELECT `data_type` INTO ret
  FROM `information_schema`.`columns`
  WHERE `table_schema` = sname
  AND `table_name` = tname
  AND `column_name` = cname;

  RETURN COALESCE(ret, NULL);
END //

-- col_has_type is not available in pgTAP. The convention would have
-- col_type_is which would output expected and actual for failed tests
-- Variations on a theme. This could be an alias to col_has_type but
-- instead uses the eq function rather that the ok function. Either way,
-- it comes top the same thing.
DROP FUNCTION IF EXISTS col_data_type_is //
CREATE FUNCTION col_data_type_is(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), dtype LONGTEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
CONTAINS SQL
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
      ' should have Data Type ', qv(dtype));
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE,description),'\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN eq(_data_type(sname, tname, cname), dtype, description);
END //


-- column type
DROP FUNCTION IF EXISTS _column_type //
CREATE FUNCTION _column_type(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64))
RETURNS LONGTEXT
DETERMINISTIC
READS SQL DATA
BEGIN
  DECLARE ret LONGTEXT;

  SELECT `column_type` INTO ret
  FROM `information_schema`.`columns`
  WHERE `table_schema` = sname
  AND `table_name` = tname
  AND `column_name` = cname;

  RETURN COALESCE(ret, NULL);
END //

-- col_column_type is not available in pgTAP. The convention would have
-- column_type_is which would output expected and actual for failed tests
DROP FUNCTION IF EXISTS col_column_type_is //
CREATE FUNCTION col_column_type_is(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), ctype LONGTEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
CONTAINS SQL
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
      ' should have Column Type ', qv(ctype));
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE,description),'\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN eq(_column_type(sname, tname, cname), ctype, description);
END //


/****************************************************************************/

-- _col_has_default (schema, table, column)

-- note: MySQL 5.5x does not distinguish between 'no default' and
-- 'null as default' and 'empty string as default'

DROP FUNCTION IF EXISTS _col_has_default //
CREATE FUNCTION _col_has_default(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
READS SQL DATA
BEGIN
  DECLARE ret BOOLEAN;

  SELECT 1 INTO ret
  FROM `information_schema`.`columns`
  WHERE `table_schema` = sname
  AND `table_name` = tname
  AND `column_name` = cname
  AND `column_default` IS NOT NULL;

  RETURN coalesce(ret, 0);
END //

DROP FUNCTION IF EXISTS col_has_default //
CREATE FUNCTION col_has_default(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
CONTAINS SQL
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Column ',
      quote_ident(tname), '.', quote_ident(cname), ' should have a default');
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE,description),'\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN ok(_col_has_default(sname, tname, cname), description);
END //

DROP FUNCTION IF EXISTS col_hasnt_default //
CREATE FUNCTION col_hasnt_default(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
CONTAINS SQL
BEGIN
  IF description = '' THEN
   SET description = CONCAT('Column ',
      quote_ident(tname), '.', quote_ident(cname), ' should not have a default');
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE,description),'\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN ok(NOT _col_has_default(sname, tname, cname), description);
END //

/****************************************************************************/


DROP FUNCTION IF EXISTS _col_default//
CREATE FUNCTION _col_default(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64))
RETURNS LONGTEXT
DETERMINISTIC
READS SQL DATA
BEGIN
  DECLARE ret LONGTEXT;

  SELECT `column_default` INTO ret
  FROM `information_schema`.`columns`
  WHERE `table_schema` = sname
  AND `table_name` = tname
  AND `column_name` = cname;

  RETURN ret ;
END //

DROP FUNCTION IF EXISTS col_default_is //
CREATE FUNCTION col_default_is(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), cdefault LONGTEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
CONTAINS SQL
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
      ' should have Default ', qv(cdefault));
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE,description),'\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN eq(_col_default(sname, tname, cname), cdefault, description);
END //



/****************************************************************************/
-- note: in MySQL 5.5x 'extra' default to ''

DROP FUNCTION IF EXISTS _col_extra_is //
CREATE FUNCTION _col_extra_is(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64))
RETURNS VARCHAR(30)
DETERMINISTIC
READS SQL DATA
BEGIN
  DECLARE ret VARCHAR(30);

  SELECT `extra` INTO ret
  FROM `information_schema`.`columns`
  WHERE `table_schema` = sname
  AND `table_name` = tname
  AND `column_name` = cname;

  RETURN ret;
END //

DROP FUNCTION IF EXISTS col_extra_is //
CREATE FUNCTION col_extra_is(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), cextra VARCHAR(30), description TEXT)
RETURNS TEXT
DETERMINISTIC
CONTAINS SQL
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' should have Extra ', quote_ident(cextra));
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
       diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
         ' does not exist')));
  END IF;

  RETURN eq(_col_extra_is(sname, tname, cname), cextra, description);
END //


/****************************************************************************/

-- COLUMN CHARACTER SET
-- Character set can be set on a col so should test individually too.
-- CHARSET is a reserved word in mysql and will be familiar to those
-- coming from a PHP background so include both forms.
-- _is style test should return expected and found values on failure

DROP FUNCTION IF EXISTS _col_charset //
CREATE FUNCTION _col_charset(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64))
RETURNS VARCHAR(32)
DETERMINISTIC
READS SQL DATA
BEGIN
  DECLARE ret VARCHAR(32);

  SELECT `character_set_name` INTO ret
  FROM `information_schema`.`columns`
  WHERE `table_schema` = sname
  AND `table_name` = tname
  AND `column_name` = cname;

  RETURN COALESCE(ret, NULL);
END //


DROP FUNCTION IF EXISTS col_charset_is //
CREATE FUNCTION col_charset_is(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), cset VARCHAR(32), description TEXT)
RETURNS TEXT
DETERMINISTIC
CONTAINS SQL
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
      ' should have Character Set ' , quote_ident(cset));
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN eq(_col_charset(sname, tname, cname), cset, description);
END //

-- alias
DROP FUNCTION IF EXISTS col_character_set_is //
CREATE FUNCTION col_character_set_is(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), cset VARCHAR(32), description TEXT)
RETURNS TEXT
DETERMINISTIC
CONTAINS SQL
BEGIN
  RETURN col_charset_is(sname, tname, cname, cset, description);
END //


/****************************************************************************/
-- COLUMN COLLATION

DROP FUNCTION IF EXISTS _col_collation //
CREATE FUNCTION _col_collation(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64))
RETURNS VARCHAR(32)
DETERMINISTIC
READS SQL DATA
BEGIN
  DECLARE ret VARCHAR(32);

  SELECT `collation_name` INTO ret
  FROM `information_schema`.`columns`
  WHERE `table_schema` = sname
  AND `table_name` = tname
  AND `column_name` = cname;

  RETURN COALESCE(ret, NULL);
END //


DROP FUNCTION IF EXISTS col_collation_is //
CREATE FUNCTION col_collation_is(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), ccoll VARCHAR(32), description TEXT)
RETURNS TEXT
DETERMINISTIC
CONTAINS SQL
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Column ', quote_ident(tname), '.',
      quote_ident(cname), ' should have collation ' , quote_ident(ccoll));
  END IF;

  IF NOT _has_column(sname, tname, cname)THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Column ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN eq(_col_collation(sname, tname, cname), ccoll, description);
END //


DROP FUNCTION IF EXISTS columns_are //
CREATE FUNCTION columns_are(sname VARCHAR(64), tname VARCHAR(64), want TEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
 
  SET @want = want;
  SET @have = (SELECT GROUP_CONCAT('`',column_name,'`')
               FROM `information_schema`.`columns`
	       WHERE `table_schema` = sname
	       AND `table_name` = tname);

  IF description = '' THEN
    SET description = CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
      ' should have the correct Columns');
  END IF;

  IF NOT _has_table(sname,tname) THEN
  RETURN CONCAT(ok(FALSE, description), '\n',
    diag(CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
      ' does not exist')));
  END IF;

  CALL _populate_want(@want);
  CALL _populate_have(@have);

  SET @missing = (SELECT _missing(@have)); 
  SET @extras  = (SELECT _extra(@want));

  RETURN _are('columns', @extras, @missing, description);

END //


DELIMITER ;
