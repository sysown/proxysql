# Enable ParserSQL-based SET parser for both protocols
SET mysql-set_parser_algorithm=3;
SET pgsql-set_parser_algorithm=3;
LOAD MYSQL VARIABLES TO RUNTIME;
LOAD PGSQL VARIABLES TO RUNTIME;
SAVE MYSQL VARIABLES TO DISK;
SAVE PGSQL VARIABLES TO DISK;
