import MySQLdb

from proxysql_base_test import ProxySQLBaseTest

class OneBackendTest(ProxySQLBaseTest):

	def _test_select_strings_returns_correct_result(self):

		rows = self.run_query_proxysql("SELECT * FROM strings", "test")
		self.assertEqual(set([row[0] for row in rows]),
						 set(['a', 'ab', 'abc', 'abcd']))

	def test_select_strings_returns_correct_result(self):
		self.run_in_docker_scenarios(self._test_select_strings_returns_correct_result)