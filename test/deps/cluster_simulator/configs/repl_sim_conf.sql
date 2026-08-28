# Configure DEBUGDB_DISK
SET admin-debug_output=2;
SET admin-debug='true';

LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;

UPDATE debug_levels SET verbosity=7 WHERE module IN ('debug_mysql_com');

LOAD DEBUG TO RUNTIME;
SAVE DEBUG TO DISK;
