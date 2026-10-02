# Environment settings for mariadb10-binlog group
# This group uses infra-dbdeployer-mariadb10-binlog, which runs a real MariaDB
# behind a real proxysql_binlog_reader (release 2.5.0, the first with MariaDB GTID
# support). The reader connects over TLS, as on the MySQL binlog infras.
export INFRA_TYPE="infra-dbdeployer-mariadb10-binlog"
export DEFAULT_MYSQL_INFRA="infra-dbdeployer-mariadb10-binlog"

# test_gtid_from_ok-t is deliberately NOT in this group. It drives its whole
# scenario off MySQL's @@GLOBAL.session_track_gtids, which MariaDB 10.11 does
# not implement; the test probes for it, finds it absent, and then fails hard
# with 11 of its 14 cases unrun rather than skipping. It still runs on the
# MySQL binlog groups (legacy-binlog-g1, mysql84/90/95-binlog-g1, mysql84-g5).
# Its MariaDB counterpart is test_gtid_from_ok_mariadb-t, which covers
# ProxySQL's own 'last_gtid' tracking and the MariaDB update_gtid_from_ok path.
