import MySQLdb

from proxysql_base_test import ProxySQLBaseTest

class OneBackendTest(ProxySQLBaseTest):

	DOCKER_COMPOSE_FILE = "./docker/1backend"

	def test_select_strings_returns_correct_result(self):
		proxy_connection = MySQLdb.connect("127.0.0.1",
											ProxySQLBaseTest.PROXYSQL_RW_USERNAME,
											ProxySQLBaseTest.PROXYSQL_RW_PASSWORD,
											port=ProxySQLBaseTest.PROXYSQL_RW_PORT)
		cursor = proxy_connection.cursor()
		cursor.execute("USE test")
		cursor.execute("SELECT * FROM strings")
		rows = cursor.fetchall()
		self.assertEqual(set([row[0] for row in rows]),
						 set(['a', 'ab', 'abc', 'abcd']))
		cursor.close()
		proxy_connection.close()