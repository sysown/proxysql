from multiprocessing.pool import ThreadPool
import random

from proxysql_base_test import ProxySQLBaseTest

class AdminTablesTest(ProxySQLBaseTest):

	def test_monitor_tables_locking_errors(self):
		"""Test that intensive read/write operations to the MySQL Monitor tables
		do not trigger locking errors.

		This test will be successful if there will be no generated error at
		the end.
		"""

		# Setting these variables will cause the Monitor to connect more
		# frequently to the backend hosts to check their health, thus increasing
		# the probability of locking errors to appear.
		self.run_query_proxysql_admin("UPDATE global_variables SET variable_value=100 WHERE variable_name='mysql-monitor_connect_interval'")
		self.run_query_proxysql_admin("UPDATE global_variables SET variable_value=100 WHERE variable_name='mysql-monitor_ping_interval'")
		self.run_query_proxysql_admin("LOAD MYSQL VARIABLES TO RUNTIME")

		queries = []
		q1 = "select * from monitor.mysql_server_connect_log ORDER BY RANDOM() LIMIT 10"
		q2 = "select * from monitor.mysql_server_ping_log ORDER BY RANDOM() LIMIT 10"
		for _ in xrange(10000):
			queries.append(random.choice([q1, q2]))

		pool = ThreadPool(processes=5)
		pool.map(self.run_query_proxysql_admin, queries)

		# If we reached this point without an error, it means that the test
		# has passed.
		self.assertEqual(1, 1)