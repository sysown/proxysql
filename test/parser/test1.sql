SELECT 1;
SELECT * FROM db.tablename1 WHERE ta = 123;
SELECT t2.* FROM db.tablename1 t2 WHERE ta = 123 AND id IN (1,2);
SELECT 1 from table1 WHERE id=123 + 3 - 5 and id2 = 3;
SELECT random_stuff from table1 WHERE id=123 + 3 - 5 and id2 = 3 FOR UPDATE;
INSERT INTO tablenameAA (colA, colB, colC) VALUES (1,'random_stuff',"random_stuff");
INSERT INTO tablenameAA (colA, colB, colC) VALUES (1,'random_stuff',"random_stuff") ON DUPLICATE KEY invalid_sql_query;
UPDATE OR IGNORE TABLE whatever SET wat=123 , whi = 123+123 , wha = 'hello world';
SELECT col1 AS col1 , t1.long_column_name1 AS long_column_name1, t1.long_column_name1 AS long_column_name1, t1.long_column_name1 AS long_column_name1, t1.long_column_name1 AS long_column_name1, t1.long_column_name1 AS long_column_name1, t1.long_column_name1 AS long_column_name1, t1.long_column_name1 AS long_column_name1, t.long_column_name AS long_column_name , t.long_column_name AS long_column_name , t.long_column_name AS long_column_name FROM myrandom_table t JOIN another_random_table u JOIN yet_another_table y ON (t.whatever = u.blah);
