import MySQLdb

from proxysql_base_test import ProxySQLBaseTest

class OneBackendTest(ProxySQLBaseTest):

	DOCKER_COMPOSE_FILE = "./scenarios/1backend"

	def test_select_strings_returns_correct_result(self):

		rows = ProxySQLBaseTest.run_query_proxysql("SELECT * FROM strings", "test")
		self.assertEqual(set([row[0] for row in rows]),
						 set(['a', 'ab', 'abc', 'abcd']))