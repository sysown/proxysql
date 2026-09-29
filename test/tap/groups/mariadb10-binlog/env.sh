# Environment settings for mariadb10-binlog group
# This group uses infra-dbdeployer-mariadb10-binlog, which runs a real MariaDB
# behind a real proxysql_binlog_reader (release 2.5.0, the first with MariaDB GTID
# support). The reader connects over TLS, as on the MySQL binlog infras.
export INFRA_TYPE="infra-dbdeployer-mariadb10-binlog"
export DEFAULT_MYSQL_INFRA="infra-dbdeployer-mariadb10-binlog"
