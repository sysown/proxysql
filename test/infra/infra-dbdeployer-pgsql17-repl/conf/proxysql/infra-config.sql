-- ProxySQL PostgreSQL Server Configuration for infra-dbdeployer-pgsql17-repl.
--
-- Unlike the static-split reference (infra-pgsql17-repl/conf/proxysql/infra-config.sql),
-- this is the AUTOMATIC rw-split path: all three backends start in the WRITER
-- hostgroup and the monitor demotes read-only replicas to the reader hostgroup
-- via pg_is_in_recovery() (pgsql_replication_hostgroups, check_type='read_only').
--
-- Backends are reached exclusively through Toxiproxy (bootstrapped by
-- ./bin/toxiproxy-bootstrap.sh): toxiproxy.${INFRA_ID} ports 6001/6002/6003 ->
-- dbdeployer1.${INFRA_ID}:16710/16711/16712 (primary/replica1/replica2).
--
-- NOTE: this template is eval-expanded by ./bin/docker-proxy-post.bash, which
-- can run either from docker-compose-init.bash (INFRA exported = this infra
-- directory's basename) or from control/ensure-infras.bash's already-running
-- reconfigure path (which does NOT reliably export INFRA -- it is only set
-- from INFRA_TYPE, itself populated later by the group's env.sh).
-- INFRA_ID (the per-test-run instance id, e.g. sdd-sp2) IS reliably present
-- in every invocation path, and docker-compose.yml registers the
-- toxiproxy.${INFRA_ID} / dbdeployer1.${INFRA_ID} network aliases specifically
-- so downstream SP-2 tasks (harness/ProxySQL) resolve the backend -- so this
-- config addresses backends and tags comments via ${INFRA_ID}, not ${INFRA}.
--
-- CAUTION for future edits: this whole file is run through a shell eval to
-- expand the template placeholders above, so any double quote character or
-- any dollar-sign token in a comment (not just the intended placeholders)
-- gets interpreted by that eval too. Keep comments free of both.
DELETE FROM pgsql_servers WHERE comment LIKE '%${INFRA_ID}%';

-- All three backends in the WRITER hostgroup, addressed via Toxiproxy.
INSERT INTO pgsql_servers (hostgroup_id, hostname, port, max_connections, comment) VALUES
  (${WHG}, 'toxiproxy.${INFRA_ID}', 6001, 200, 'pg_primary ${INFRA_ID}'),
  (${WHG}, 'toxiproxy.${INFRA_ID}', 6002, 200, 'pg_replica1 ${INFRA_ID}'),
  (${WHG}, 'toxiproxy.${INFRA_ID}', 6003, 200, 'pg_replica2 ${INFRA_ID}');

-- Automatic writer/reader assignment via pg_is_in_recovery().
DELETE FROM pgsql_replication_hostgroups WHERE writer_hostgroup=${WHG};
INSERT INTO pgsql_replication_hostgroups (writer_hostgroup, reader_hostgroup, check_type, comment)
  VALUES (${WHG}, ${RHG}, 'read_only', 'pg auto rw-split ${INFRA_ID}');

LOAD PGSQL SERVERS TO RUNTIME;   -- loads replication_hostgroups too
SAVE PGSQL SERVERS TO DISK;

DELETE FROM pgsql_users WHERE comment LIKE '%${INFRA_ID}%';

-- Superuser row, mirroring the reference infra (postgres/${ROOT_PASSWORD},
-- the role the entrypoint gives a known password so ProxySQL can log in).
REPLACE INTO pgsql_users (username, password, active, default_hostgroup, comment) VALUES
  ('postgres', '${ROOT_PASSWORD}', 1, ${WHG}, '${INFRA_ID}');
-- Application user.
REPLACE INTO pgsql_users (username, password, active, default_hostgroup, comment) VALUES
  ('testuser', 'testuser', 1, ${WHG}, '${INFRA_ID}');

LOAD PGSQL USERS TO RUNTIME;
SAVE PGSQL USERS TO DISK;

-- Read/write split query rules (route SELECTs to the reader HG, SELECT ... FOR
-- UPDATE and everything else stays on the writer HG).
DELETE FROM pgsql_query_rules WHERE destination_hostgroup IN (${WHG}, ${RHG});
INSERT INTO pgsql_query_rules (rule_id, active, match_digest, destination_hostgroup, apply) VALUES
  (${WHG}01, 1, '^SELECT.*FOR UPDATE', ${WHG}, 1),
  (${RHG}01, 1, '^SELECT', ${RHG}, 1);
LOAD PGSQL QUERY RULES TO RUNTIME;
SAVE PGSQL QUERY RULES TO DISK;

-- Enable the monitor (drives the automatic split) against the 'monitor' role
-- provisioned by the entrypoint (monitor/monitor, LOGIN). Shorten the
-- read_only check interval to 1000ms (still within [100, 7*24*3600*1000],
-- see PgSQL_Thread.cpp VariablesPointers_int) so demotion happens fast in tests.
UPDATE global_variables SET variable_value='true'    WHERE variable_name='pgsql-monitor_enabled';
UPDATE global_variables SET variable_value='monitor' WHERE variable_name IN ('pgsql-monitor_username','pgsql-monitor_password');
UPDATE global_variables SET variable_value='1000'    WHERE variable_name='pgsql-monitor_read_only_interval';
LOAD PGSQL VARIABLES TO RUNTIME;
SAVE PGSQL VARIABLES TO DISK;
