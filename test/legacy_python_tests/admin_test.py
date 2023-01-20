from proxysql_base_test import ProxySQLBaseTest

from MySQLdb import OperationalError

class AdminTest(ProxySQLBaseTest):

	def test_stop_main_thread(self):
		try:
			# This test will just assert that PROXYSQL STOP works correctly
			# Since September 2015, the behaviour has been changed - PROXYSQL STOP
			# executes faster and immediately shuts down the connections, thus this
			# test is expected to raise OperationalError
			self.run_query_proxysql_admin("PROXYSQL STOP")
			self.assertEqual(0, 1)
		except OperationalError:
			self.assertEqual(1, 1)