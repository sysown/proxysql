#include "duckdb_replica_test_utils.h"

using namespace duckdb_replica_test;

namespace {
bool run(Fixture& f) {
	if (!check(f.bootstrap(),
			   "start an isolated child ProxySQL with private ports and file-backed DuckDB"))
		return false;
	if (!check(f.source_setup() && f.configure(),
			   "create a large two-table source fixture and dedicated replication account"))
		return false;
	if (!check(query(f.admin, "START DUCKDB REPLICA") && f.copying(),
			   "observe positive snapshot progress before concurrent writes"))
		return false;
	if (!check(query(f.source, "BEGIN") &&
				   query(f.source, "UPDATE " + f.table("a_bulk") +
									   " SET val=11,note='updated during snapshot' WHERE id=1") &&
				   query(f.source, "DELETE FROM " + f.table("a_bulk") + " WHERE id=2") &&
				   query(f.source, "INSERT INTO " + f.table("a_bulk") +
									   " VALUES(200001,12,'inserted during snapshot')") &&
				   query(f.source, "UPDATE " + f.table("z_tail") +
									   " SET val=13,note='same source transaction' WHERE id=1") &&
				   query(f.source, "INSERT INTO " + f.table("z_tail") +
									   " VALUES(5,15,'insert in not-yet-copied table')") &&
				   query(f.source, "COMMIT") &&
				   cell(f.admin, "SELECT state FROM stats_duckdb_replica") == "snapshotting",
			   "commit insert/update/delete across both tables while snapshot is still copying"))
		return false;
	if (!check(f.matches(), "snapshot plus binlog catch-up contains concurrent changes exactly "
							"once with matching checkpoint"))
		return false;

	if (!check(query(f.admin, "STOP DUCKDB REPLICA") && query(f.admin, "RESET DUCKDB REPLICA") &&
				   query(f.admin, "UPDATE disk.duckdb_replica_sources SET enabled=0") &&
				   query(f.admin, "START DUCKDB REPLICA") && f.copying() && f.crash(),
			   "SIGKILL the owned ProxySQL after an incomplete snapshot has copied rows"))
		return false;
	if (!check(query(f.source, "INSERT INTO " + f.table("z_tail") +
								   " VALUES(2,21,'committed while replica was dead')") &&
				   f.start() &&
				   cell(f.admin, "SELECT state FROM stats_duckdb_replica") == "stopped" &&
				   cell(f.duck, "SELECT COUNT(*) FROM system.information_schema.tables WHERE "
								"table_catalog='replica' AND (table_schema='proxysql_replica' OR "
								"table_schema=" +
									quote(f.schema) + ")") == "0",
			   "opening crashed snapshot files exposes no partial tables, manifest or checkpoint"))
		return false;
	if (!check(query(f.admin, "UPDATE duckdb_replica_sources SET enabled=1") &&
				   query(f.admin, "SAVE DUCKDB REPLICA TO DISK") &&
				   query(f.admin, "START DUCKDB REPLICA") && f.matches(),
			   "fresh snapshot after crash includes offline changes and converges exactly"))
		return false;

	if (!check(query(f.source, "UPDATE " + f.table("a_bulk") + " SET val=val+3 WHERE id=1") &&
				   f.matches(),
			   "persist a recognizable applied batch before the next crash"))
		return false;
	const Rows committed = f.position();
	if (!check(query(f.source, "BEGIN") &&
				   query(f.source,
						 "INSERT INTO " + f.table("z_tail") + " VALUES(3,99,'must roll back')") &&
				   f.crash() && query(f.source, "ROLLBACK") &&
				   query(f.source,
						 "INSERT INTO " + f.table("z_tail") + " VALUES(4,31,'offline backlog')") &&
				   f.privilege("REVOKE RELOAD ON *.* FROM " + quote(f.account) + "@'%'") &&
				   f.start() && f.matches(),
			   "SIGKILL recovery auto-resumes without snapshot privilege, catches offline commits "
			   "and excludes rollback"))
		return false;
	if (!check(!committed.empty() && f.position() != committed &&
				   cell(f.duck,
						"SELECT COUNT(*) FROM " + f.table("z_tail", true) + " WHERE id=3") == "0",
			   "recovered checkpoint advances with the new data and rolled-back row stays absent"))
		return false;

	// Persist disabled startup without changing the running replica: inspect
	// recovered storage before another applier can hide a partial commit.
	Rows before_data;
	const Rows before_position = f.position();
	if (!check(
			f.read_data(f.duck, true, before_data) &&
				query(f.admin, "UPDATE disk.duckdb_replica_sources SET enabled=0") &&
				kill(f.pid, SIGSTOP) == 0 &&
				query(f.source, "UPDATE " + f.table("a_bulk") + " SET val=val+7 WHERE id<=10000"),
			"queue a large committed transaction while the owned ProxySQL is paused"))
		return false;
	// The child is paused, so its last published position remains durable.
	Rows target_data;
	if (!f.read_data(f.source, false, target_data))
		return false;
	const Rows target_position = f.source_position();
	if (!check(kill(f.pid, SIGCONT) == 0 && wait_for([&] {
				   return cell(f.source,
							   "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE USER=" +
								   quote(f.account) +
								   " AND COMMAND LIKE 'Binlog Dump%' AND STATE LIKE '%waiting for "
								   "more updates%'") == "1";
			   }) &&
				   cell(f.duck, "SELECT val FROM " + f.table("a_bulk", true) + " WHERE id=1") ==
					   "14" &&
				   f.crash(),
			   "SIGKILL during large transaction catch-up before it becomes visible"))
		return false;
	if (!check(f.start(), "restart with applier disabled to inspect crash-recovered storage"))
		return false;
	Rows recovered;
	if (!check(
			f.read_data(f.duck, true, recovered) &&
				(recovered == before_data || recovered == target_data),
			"crash recovery exposes the complete old or new transaction, never a partial row set"))
		return false;
	if (!check(((recovered == before_data && f.position() == before_position) ||
				(recovered == target_data && f.position() == target_position)),
			   "recovered checkpoint commits together with the recovered transaction"))
		return false;
	return check(
		query(f.admin, "UPDATE duckdb_replica_sources SET enabled=1") &&
			query(f.admin, "SAVE DUCKDB REPLICA TO DISK") &&
			query(f.admin, "START DUCKDB REPLICA") && f.matches(),
		"resume the recovered backlog and converge without missing rows or duplicate primary keys");
}
} // namespace

int main() {
	CommandLine cl;
	if (cl.getEnv())
		return EXIT_FAILURE;
	plan(NO_PLAN);
	{
		Fixture fixture(cl);
		fixture.complete = run(fixture);
		ok(fixture.complete, "crash recovery and concurrent snapshot scenario completed");
	}
	return exit_status();
}
