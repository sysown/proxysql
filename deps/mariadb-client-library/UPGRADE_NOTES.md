Please note that upgrading `mariadb-connector-c` can require some changes
in `include/MySQL_Data_Stream.h` where we define `P_MARIADB_TLS` as a copy
of `MARIADB_TLS` . If `MARIADB_TLS` is changed, `P_MARIADB_TLS` must be
updated too.
