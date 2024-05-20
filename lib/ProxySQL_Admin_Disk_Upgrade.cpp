#include "cpp.h"
#include "ProxySQL_Admin_Tables_Definitions.h"

void ProxySQL_Admin::disk_upgrade_mysql_query_rules() {
	// this function is called only for configdb table
	// it is responsible to upgrade table mysql_query_rules if its structure is from a previous version
	int rci;
	configdb->execute("PRAGMA foreign_keys = OFF");
	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_1_0);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.1.0 of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v110
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_v110");
		// rename current table to add suffix _v110
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v110");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id,active,username,schemaname,flagIN,match_digest,match_pattern,negate_match_pattern,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,delay,error_msg,apply) SELECT rule_id,active,username,schemaname,flagIN,match_digest,match_pattern,negate_match_pattern,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,delay,error_msg,apply FROM mysql_query_rules_v110");
	}
	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_2_0a);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.2.0a of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v120a
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_v120a");
		// rename current table to add suffix _v120a
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v120a");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id,active,username,schemaname,flagIN,match_digest,match_pattern,negate_match_pattern,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,delay,error_msg,mirror_flagOUT,mirror_hostgroup,apply) SELECT rule_id,active,username,schemaname,flagIN,match_digest,match_pattern,negate_match_pattern,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,delay,error_msg,mirror_flagOUT,mirror_hostgroup,apply FROM mysql_query_rules_v120a");
	}
	// upgrade related to issue #643 , adding comment in mysql_query_rules table
	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_2_0g);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.2.0g of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v120g
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_v120g");
		// rename current table to add suffix _v120g
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v120g");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,log,apply) SELECT rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,log,apply FROM mysql_query_rules_v120g");
	}
	// upgrade related to issue #643 , adding comment in mysql_query_rules table
	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_2_2);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.2.2 of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v122
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_v122");
		// rename current table to add suffix _v122
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v122");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,log,apply,comment) SELECT rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,log,apply,comment FROM mysql_query_rules_v122");
	}
	// upgrade related to issue #643 , adding comment in mysql_query_rules table
	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_3_1);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.3.1 of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v131
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_v131");
		// rename current table to add suffix _v131
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v131");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,sticky_conn,multiplex,log,apply,comment) SELECT rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,sticky_conn,multiplex,log,apply,comment FROM mysql_query_rules_v131");
	}

	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_4_0a);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.4.0a of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v140a
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_v140a");
		// rename current table to add suffix _v140a
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v40a");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,re_modifiers,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,sticky_conn,multiplex,log,apply,comment) SELECT rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,re_modifiers,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,sticky_conn,multiplex,log,apply,comment FROM mysql_query_rules_v140a");
	}

	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_4_0b);
	if (rci) { // note: upgrade from V1_4_0a or V1_4_0b is the same
		// upgrade is required
		proxy_warning("Detected version v1.4.0b of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v140b
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_v140b");
		// rename current table to add suffix _v140b
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v140b");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,re_modifiers,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,sticky_conn,multiplex,log,apply,comment) SELECT rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,re_modifiers,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,sticky_conn,multiplex,log,apply,comment FROM mysql_query_rules_v140b");
	}

	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_4_1);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.4.1 of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v141
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_v141");
		// rename current table to add suffix _v141
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v141");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,re_modifiers,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,sticky_conn,multiplex,log,apply,comment) SELECT rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,re_modifiers,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,sticky_conn,multiplex,log,apply,comment FROM mysql_query_rules_v141");
	}
	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V2_0_0a);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v2.0.0a of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v200a
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_200a");
		// rename current table to add suffix _v200a
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v200a");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment) SELECT rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment FROM mysql_query_rules_v200a");
	}
	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V2_0_0b);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v2.0.0b of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v200b
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_200b");
		// rename current table to add suffix _v200b
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v200b");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment) SELECT rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment FROM mysql_query_rules_v200b");
	}
	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V2_0_0c);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v2.0.0c of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v200c
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_200c");
		// rename current table to add suffix _v200c
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v200c");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment) SELECT rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment FROM mysql_query_rules_v200c");
	}
	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V2_0_0d);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v2.0.0d of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v200d
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_200d");
		// rename current table to add suffix _v200d
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v200d");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment) SELECT rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment FROM mysql_query_rules_v200d");
	}
	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V2_0_0e);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v2.1.0e of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v200e
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_200e");
		// rename current table to add suffix _v200e
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v200e");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment) SELECT rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment FROM mysql_query_rules_v200e");
	}
	configdb->execute("PRAGMA foreign_keys = ON");
}

void ProxySQL_Admin::disk_upgrade_scheduler() {
	// this function is called only for configdb table
	// it is responsible to upgrade table scheduler if its structure is from a previous version
	int rci;
	configdb->execute("PRAGMA foreign_keys = OFF");
	rci=configdb->check_table_structure((char *)"scheduler",(char *)ADMIN_SQLITE_TABLE_SCHEDULER_V1_2_0);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.2.0 of table scheduler\n");
		proxy_warning("ONLINE UPGRADE of table scheduler in progress\n");
		// drop any existing table with suffix _v120
		configdb->execute("DROP TABLE IF EXISTS scheduler_v120");
		// rename current table to add suffix _v120
		configdb->execute("ALTER TABLE scheduler RENAME TO scheduler_v120");
		// create new table
		configdb->build_table((char *)"scheduler",(char *)ADMIN_SQLITE_TABLE_SCHEDULER,false);
		// copy fields from old table
		configdb->execute("INSERT INTO scheduler (id,interval_ms,filename,arg1,arg2,arg3,arg4,arg5) SELECT id,interval_ms,filename,arg1,arg2,arg3,arg4,arg5 FROM scheduler_v120");
	}
	rci=configdb->check_table_structure((char *)"scheduler",(char *)ADMIN_SQLITE_TABLE_SCHEDULER_V1_2_2a);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.2.2a of table scheduler\n");
		proxy_warning("ONLINE UPGRADE of table scheduler in progress\n");
		// drop any existing table with suffix _v122a
		configdb->execute("DROP TABLE IF EXISTS scheduler_v122a");
		// rename current table to add suffix _v122a
		configdb->execute("ALTER TABLE scheduler RENAME TO scheduler_v122a");
		// create new table
		configdb->build_table((char *)"scheduler",(char *)ADMIN_SQLITE_TABLE_SCHEDULER,false);
		// copy fields from old table
		configdb->execute("INSERT INTO scheduler (id,interval_ms,filename,arg1,arg2,arg3,arg4,arg5,comment) SELECT id,interval_ms,filename,arg1,arg2,arg3,arg4,arg5,comment FROM scheduler_v122a");
	}
	rci=configdb->check_table_structure((char *)"scheduler",(char *)ADMIN_SQLITE_TABLE_SCHEDULER_V1_2_2b);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.2.2b of table scheduler\n");
		proxy_warning("ONLINE UPGRADE of table scheduler in progress\n");
		// drop any existing table with suffix _v122b
		configdb->execute("DROP TABLE IF EXISTS scheduler_v122b");
		// rename current table to add suffix _v122b
		configdb->execute("ALTER TABLE scheduler RENAME TO scheduler_v122b");
		// create new table
		configdb->build_table((char *)"scheduler",(char *)ADMIN_SQLITE_TABLE_SCHEDULER,false);
		// copy fields from old table
		configdb->execute("INSERT INTO scheduler (id,active,interval_ms,filename,arg1,arg2,arg3,arg4,arg5,comment) SELECT id,active,interval_ms,filename,arg1,arg2,arg3,arg4,arg5,comment FROM scheduler_v122b");
	}

	configdb->execute("PRAGMA foreign_keys = ON");
}

void ProxySQL_Admin::disk_upgrade_mysql_servers() {
	// this function is called only for configdb table
	// it is responsible to upgrade table mysql_servers if its structure is from a previous version
	int rci;
	configdb->execute("PRAGMA foreign_keys = OFF");
	rci=configdb->check_table_structure((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V1_1_0);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.1.0 of table mysql_servers\n");
		proxy_warning("ONLINE UPGRADE of table mysql_servers in progress\n");
		// drop any existing table with suffix _v110
		configdb->execute("DROP TABLE IF EXISTS mysql_servers_v110");
		// rename current table to add suffix _v110
		configdb->execute("ALTER TABLE mysql_servers RENAME TO mysql_servers_v110");
		// create new table
		configdb->build_table((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS,false);
		// fix bug #1224
		configdb->execute("UPDATE mysql_servers_v110 SET weight = 10000000 WHERE weight > 10000000");
		// fix bug #962
		configdb->execute("UPDATE mysql_servers_v110 SET compression = 1 WHERE compression > 0");
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_servers (hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag) SELECT hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag FROM mysql_servers_v110");
	}
	rci=configdb->check_table_structure((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V1_2_0e);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.2.0 of table mysql_servers\n");
		proxy_warning("ONLINE UPGRADE of table mysql_servers in progress\n");
		// drop any existing table with suffix _v120
		configdb->execute("DROP TABLE IF EXISTS mysql_servers_v120");
		// rename current table to add suffix _v120
		configdb->execute("ALTER TABLE mysql_servers RENAME TO mysql_servers_v120");
		// create new table
		configdb->build_table((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS,false);
		// fix bug #1224
		configdb->execute("UPDATE mysql_servers_v120 SET weight = 10000000 WHERE weight > 10000000");
		// fix bug #962
		configdb->execute("UPDATE mysql_servers_v120 SET compression = 1 WHERE compression > 0");
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_servers (hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms) SELECT hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms FROM mysql_servers_v120");
	}
	rci=configdb->check_table_structure((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V1_2_2);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.2.2 of table mysql_servers\n");
		proxy_warning("ONLINE UPGRADE of table mysql_servers in progress\n");
		//drop any existing table with suffix _v122
		configdb->execute("DROP TABLE IF EXISTS mysql_servers_v122");
		// rename current table to add suffix _v122
		configdb->execute("ALTER TABLE mysql_servers RENAME TO mysql_servers_v122");
		// create new table
		configdb->build_table((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS,false);
		// fix bug #1224
		configdb->execute("UPDATE mysql_servers_v122 SET weight = 10000000 WHERE weight > 10000000");
		// fix bug #962
		configdb->execute("UPDATE mysql_servers_v122 SET compression = 1 WHERE compression > 0");
		// copy fields from old table
		configdb->execute("INSERT OR IGNORE INTO mysql_servers (hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment) SELECT hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM mysql_servers_v122");
	}
	rci=configdb->check_table_structure((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V1_4_4); // 1.4.4 has the same column of 1.2.2
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.4.4 (pre-2.0.0) of table mysql_servers\n");
		proxy_warning("ONLINE UPGRADE of table mysql_servers in progress\n");
		//drop any existing table with suffix _v144
		configdb->execute("DROP TABLE IF EXISTS mysql_servers_v144");
		// rename current table to add suffix _v144
		configdb->execute("ALTER TABLE mysql_servers RENAME TO mysql_servers_v144");
		// create new table
		configdb->build_table((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS,false);
		// fix bug #1224
		configdb->execute("UPDATE mysql_servers_v144 SET weight = 10000000 WHERE weight > 10000000");
		// fix bug #962
		configdb->execute("UPDATE mysql_servers_v144 SET compression = 1 WHERE compression > 0");
		// copy fields from old table
		configdb->execute("INSERT OR IGNORE INTO mysql_servers (hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment) SELECT hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM mysql_servers_v144");
	}
	rci=configdb->check_table_structure((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V2_0_0a);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version 2.0.0a of table mysql_servers\n");
		proxy_warning("ONLINE UPGRADE of table mysql_servers in progress\n");
		//drop any existing table with suffix _v200a
		configdb->execute("DROP TABLE IF EXISTS mysql_servers_v200a");
		// rename current table to add suffix _v200a
		configdb->execute("ALTER TABLE mysql_servers RENAME TO mysql_servers_v200a");
		// create new table
		configdb->build_table((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS,false);
		// fix bug #1224
		configdb->execute("UPDATE mysql_servers_v200a SET weight = 10000000 WHERE weight > 10000000");
		// fix bug #962
		configdb->execute("UPDATE mysql_servers_v200a SET compression = 1 WHERE compression > 0");
		// copy fields from old table
		configdb->execute("INSERT OR IGNORE INTO mysql_servers SELECT * FROM mysql_servers_v200a");
	}
	rci=configdb->check_table_structure((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V2_0_0b);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version 2.0.0b of table mysql_servers\n");
		proxy_warning("ONLINE UPGRADE of table mysql_servers in progress\n");
		//drop any existing table with suffix _v200b
		configdb->execute("DROP TABLE IF EXISTS mysql_servers_v200b");
		// rename current table to add suffix _v200b
		configdb->execute("ALTER TABLE mysql_servers RENAME TO mysql_servers_v200b");
		// create new table
		configdb->build_table((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS,false);
		// fix bug #1224
		configdb->execute("UPDATE mysql_servers_v200b SET weight = 10000000 WHERE weight > 10000000");
		// fix bug #962
		configdb->execute("UPDATE mysql_servers_v200b SET compression = 1 WHERE compression > 0");
		// copy fields from old table
		configdb->execute("INSERT OR IGNORE INTO mysql_servers SELECT * FROM mysql_servers_v200b");
	}
	rci=configdb->check_table_structure((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V2_0_0c);
	if (rci) {
		// upgrade is required to fix issue #1923
		proxy_warning("Detected version 2.0.0c (pre-2.0.11) of table mysql_servers\n");
		proxy_warning("ONLINE UPGRADE of table mysql_servers in progress\n");
		//drop any existing table with suffix _v200c
		configdb->execute("DROP TABLE IF EXISTS mysql_servers_v200c");
		// rename current table to add suffix _v200c
		configdb->execute("ALTER TABLE mysql_servers RENAME TO mysql_servers_v200c");
		// create new table
		configdb->build_table((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS,false);
		configdb->execute("INSERT OR IGNORE INTO mysql_servers SELECT * FROM mysql_servers_v200c");
	}
	rci=configdb->check_table_structure((char *)"mysql_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS_V1_0); // issue #643
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.0 of table mysql_replication_hostgroups\n");
		proxy_warning("ONLINE UPGRADE of table mysql_replication_hostgroups in progress\n");
		// drop any existing table with suffix _v100
		configdb->execute("DROP TABLE IF EXISTS mysql_replication_hostgroups_v100");
		// rename current table to add suffix _v100
		configdb->execute("ALTER TABLE mysql_replication_hostgroups RENAME TO mysql_replication_hostgroups_v100");
		// create new table
		configdb->build_table((char *)"mysql_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_replication_hostgroups (writer_hostgroup,reader_hostgroup) SELECT writer_hostgroup , reader_hostgroup FROM mysql_replication_hostgroups_v100");
	}
	rci=configdb->check_table_structure((char *)"mysql_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS_V1_2_2); // issue #1304
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.2.2 (pre-1.4.5) of table mysql_replication_hostgroups\n");
		proxy_warning("ONLINE UPGRADE of table mysql_replication_hostgroups in progress\n");
		// drop any existing table with suffix _v122
		configdb->execute("DROP TABLE IF EXISTS mysql_replication_hostgroups_v122");
		// rename current table to add suffix _v122
		configdb->execute("ALTER TABLE mysql_replication_hostgroups RENAME TO mysql_replication_hostgroups_v122");
		// create new table
		configdb->build_table((char *)"mysql_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_replication_hostgroups (writer_hostgroup,reader_hostgroup,comment) SELECT writer_hostgroup , reader_hostgroup , COALESCE(comment,'') FROM mysql_replication_hostgroups_v122");
	}
	rci=configdb->check_table_structure((char *)"mysql_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS_V1_4_5); // issue #1304
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.4.5 (pre-2.0.0) of table mysql_replication_hostgroups\n");
		proxy_warning("ONLINE UPGRADE of table mysql_replication_hostgroups in progress\n");
		// drop any existing table with suffix _v145
		configdb->execute("DROP TABLE IF EXISTS mysql_replication_hostgroups_v145");
		// rename current table to add suffix _v145
		configdb->execute("ALTER TABLE mysql_replication_hostgroups RENAME TO mysql_replication_hostgroups_v145");
		// create new table
		configdb->build_table((char *)"mysql_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_replication_hostgroups (writer_hostgroup,reader_hostgroup,comment) SELECT writer_hostgroup , reader_hostgroup , comment FROM mysql_replication_hostgroups_v145");
	}
	rci=configdb->check_table_structure((char *)"mysql_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS_V2_0_0); // issue #2186
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v2.0.0 (pre-2.0.8) of table mysql_replication_hostgroups\n");
		proxy_warning("ONLINE UPGRADE of table mysql_replication_hostgroups in progress\n");
		// drop any existing table with suffix _v200
		configdb->execute("DROP TABLE IF EXISTS mysql_replication_hostgroups_v200");
		// rename current table to add suffix _v200
		configdb->execute("ALTER TABLE mysql_replication_hostgroups RENAME TO mysql_replication_hostgroups_v200");
		// create new table
		configdb->build_table((char *)"mysql_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_replication_hostgroups SELECT * FROM mysql_replication_hostgroups_v200");
	}

	// upgrade mysql_group_replication_hostgroups
	rci=configdb->check_table_structure((char *)"mysql_group_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_GROUP_REPLICATION_HOSTGROUPS_V1_4);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.4 (pre-2.0.0) of mysql_group_replication_hostgroups\n");
		proxy_warning("ONLINE UPGRADE of table mysql_group_replication_hostgroups in progress\n");
		// drop any existing table with suffix _v14
		configdb->execute("DROP TABLE IF EXISTS mysql_group_replication_hostgroups_v14");
		// rename current table to add suffix _v14
		configdb->execute("ALTER TABLE mysql_group_replication_hostgroups RENAME TO mysql_group_replication_hostgroups_v14");
		// create new table
		configdb->build_table((char *)"mysql_group_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_GROUP_REPLICATION_HOSTGROUPS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_group_replication_hostgroups SELECT * FROM mysql_group_replication_hostgroups_v14");
	}


	// upgrade mysql_galera_hostgroups
	rci=configdb->check_table_structure((char *)"mysql_galera_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_GALERA_HOSTGROUPS_V2_0_0a);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v2.0.0a (pre-2.0.0b) of mysql_galera_hostgroups\n");
		proxy_warning("ONLINE UPGRADE of table mysql_galera_hostgroups in progress\n");
		// drop any existing table with suffix _v200a
		configdb->execute("DROP TABLE IF EXISTS mysql_galera_hostgroups_v200a");
		// rename current table to add suffix _v200a
		configdb->execute("ALTER TABLE mysql_galera_hostgroups RENAME TO mysql_galera_hostgroups_v200a");
		// create new table
		configdb->build_table((char *)"mysql_galera_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_GALERA_HOSTGROUPS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_galera_hostgroups SELECT * FROM mysql_galera_hostgroups_v200a");
	}

	// upgrade mysql_aws_aurora_hostgroups
	rci=configdb->check_table_structure((char *)"mysql_aws_aurora_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_AWS_AURORA_HOSTGROUPS_V2_0_8);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version pre-v2.0.9 of mysql_aws_aurora_hostgroups\n");
		proxy_warning("ONLINE UPGRADE of table mysql_aws_aurora_hostgroups in progress\n");
		// drop mysql_aws_aurora_hostgroups table with suffix _v208
		configdb->execute("DROP TABLE IF EXISTS mysql_aws_aurora_hostgroups_v208");
		// rename current table to add suffix _v208
		configdb->execute("ALTER TABLE mysql_aws_aurora_hostgroups RENAME TO mysql_aws_aurora_hostgroups_v208");
		// create new table
		configdb->build_table((char *)"mysql_aws_aurora_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_AWS_AURORA_HOSTGROUPS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_aws_aurora_hostgroups (writer_hostgroup, reader_hostgroup, active, aurora_port, domain_name, "
					      "max_lag_ms, check_interval_ms, check_timeout_ms, writer_is_also_reader, new_reader_weight, comment) "
					      "SELECT writer_hostgroup, reader_hostgroup, active, aurora_port, domain_name, max_lag_ms, check_interval_ms, "
					      "check_timeout_ms, writer_is_also_reader, new_reader_weight, comment FROM mysql_aws_aurora_hostgroups_v208");
	}

	// upgrade mysql_hostgroup_attributes
	rci=configdb->check_table_structure((char *)"mysql_hostgroup_attributes",(char *)ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ATTRIBUTES_V2_5_0);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version pre-v2.5.2 of mysql_hostgroup_attributes\n");
		proxy_warning("ONLINE UPGRADE of table mysql_hostgroup_attributes in progress\n");
		// drop mysql_hostgroup_attributes table with suffix _v250
		configdb->execute("DROP TABLE IF EXISTS mysql_hostgroup_attributes_v250");
		// rename current table to add suffix _v250
		configdb->execute("ALTER TABLE mysql_hostgroup_attributes RENAME TO mysql_hostgroup_attributes_v250");
		// create new table
		configdb->build_table((char *)"mysql_hostgroup_attributes",(char *)ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ATTRIBUTES,false);
		// copy fields from old table
		configdb->execute(
			"INSERT INTO mysql_hostgroup_attributes ("
				" hostgroup_id, max_num_online_servers, autocommit, free_connections_pct, init_connect, multiplex,"
				" connection_warming, throttle_connections_per_sec, ignore_session_variables, comment"
			") SELECT"
				" hostgroup_id, max_num_online_servers, autocommit, free_connections_pct, init_connect, multiplex,"
				" connection_warming, throttle_connections_per_sec, ignore_session_variables, comment"
			" FROM mysql_hostgroup_attributes_v250"
		);
	}
	rci = configdb->check_table_structure((char*)"mysql_hostgroup_attributes", (char*)ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ATTRIBUTES_V2_5_2);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version pre-v2.6.0 of mysql_hostgroup_attributes\n");
		proxy_warning("ONLINE UPGRADE of table mysql_hostgroup_attributes in progress\n");
		// drop mysql_hostgroup_attributes table with suffix _v252
		configdb->execute("DROP TABLE IF EXISTS mysql_hostgroup_attributes_v252");
		// rename current table to add suffix _v252
		configdb->execute("ALTER TABLE mysql_hostgroup_attributes RENAME TO mysql_hostgroup_attributes_v252");
		// create new table
		configdb->build_table((char*)"mysql_hostgroup_attributes", (char*)ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ATTRIBUTES, false);
		// copy fields from old table
		configdb->execute(
			"INSERT INTO mysql_hostgroup_attributes ("
			" hostgroup_id, max_num_online_servers, autocommit, free_connections_pct, init_connect, multiplex,"
			" connection_warming, throttle_connections_per_sec, ignore_session_variables, servers_defaults, comment"
			") SELECT"
			" hostgroup_id, max_num_online_servers, autocommit, free_connections_pct, init_connect, multiplex,"
			" connection_warming, throttle_connections_per_sec, ignore_session_variables, servers_defaults, comment"
			" FROM mysql_hostgroup_attributes_v252"
		);
	}
	configdb->execute("PRAGMA foreign_keys = ON");

}


void ProxySQL_Admin::disk_upgrade_mysql_users() {
	// this function is called only for configdb table
	// it is responsible to upgrade table mysql_users if its structure is from a previous version
	int rci;
	configdb->execute("PRAGMA foreign_keys = OFF");
	// change transaction_persistent=1 by default . See #793
	rci=configdb->check_table_structure((char *)"mysql_users",(char *)ADMIN_SQLITE_TABLE_MYSQL_USERS_V1_3_0);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version pre-1.4 of table mysql_users\n");
		proxy_warning("ONLINE UPGRADE of table mysql_users in progress\n");
		// drop any existing table with suffix _v130
		configdb->execute("DROP TABLE IF EXISTS mysql_users_v130");
		// rename current table to add suffix _v130
		configdb->execute("ALTER TABLE mysql_users RENAME TO mysql_users_v130");
		// create new table
		configdb->build_table((char *)"mysql_users",(char *)ADMIN_SQLITE_TABLE_MYSQL_USERS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) SELECT * FROM mysql_users_v130");
	}
	// adding mysql_users.commment . See #1633
	rci=configdb->check_table_structure((char *)"mysql_users",(char *)ADMIN_SQLITE_TABLE_MYSQL_USERS_V1_4_0);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version pre-2.0 of table mysql_users\n");
		proxy_warning("ONLINE UPGRADE of table mysql_users in progress\n");
		// drop any existing table with suffix _v140
		configdb->execute("DROP TABLE IF EXISTS mysql_users_v140");
		// rename current table to add suffix _v140
		configdb->execute("ALTER TABLE mysql_users RENAME TO mysql_users_v140");
		// create new table
		configdb->build_table((char *)"mysql_users",(char *)ADMIN_SQLITE_TABLE_MYSQL_USERS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) SELECT * FROM mysql_users_v140");
	}
	// adding mysql_users.attributes. See #3083
	rci=configdb->check_table_structure((char *)"mysql_users",(char *)ADMIN_SQLITE_TABLE_MYSQL_USERS_V2_0_0);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version pre-2.1.0 of table mysql_users\n");
		proxy_warning("ONLINE UPGRADE of table mysql_users in progress\n");
		// drop any existing table with suffix _v210
		configdb->execute("DROP TABLE IF EXISTS mysql_users_v200");
		// rename current table to add suffix _v210
		configdb->execute("ALTER TABLE mysql_users RENAME TO mysql_users_v200");
		// create new table
		configdb->build_table((char *)"mysql_users",(char *)ADMIN_SQLITE_TABLE_MYSQL_USERS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections,comment) SELECT * FROM mysql_users_v200");
	}
	configdb->execute("PRAGMA foreign_keys = ON");
}


void ProxySQL_Admin::disk_upgrade_rest_api_routes() {
	int rci;
	configdb->execute("PRAGMA foreign_keys = OFF");

	rci=configdb->check_table_structure((char *)"restapi_routes",(char *)ADMIN_SQLITE_TABLE_RESTAPI_ROUTES_V2_0_15);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version pre-2.1.0 of table restapi_routes\n");
		proxy_warning("ONLINE UPGRADE of table restapi_routes in progress\n");
		// drop any existing table with suffix _v2015
		configdb->execute("DROP TABLE IF EXISTS restapi_routes_v2015");
		// rename current table to add suffix _v2015
		configdb->execute("ALTER TABLE restapi_routes RENAME TO restapi_routes_v2015");
		// create new table
		configdb->build_table((char *)"restapi_routes",(char *)ADMIN_SQLITE_TABLE_RESTAPI_ROUTES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO restapi_routes(id,active,timeout_ms,method,uri,script,comment) SELECT id,active,interval_ms,method,uri,script,comment FROM restapi_routes_v2015");
	}

	configdb->execute("PRAGMA foreign_keys = ON");
}
