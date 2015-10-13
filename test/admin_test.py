from proxysql_base_test import ProxySQLBaseTest

from MySQLdb import OperationalError
from nose.tools import raises

class AdminTest(ProxySQLBaseTest):

	SCENARIO = "./scenarios/1backend"

	@raises(OperationalError)
	def test_stop_main_thread(self):
		# This test will just assert that PROXYSQL STOP works correctly
		# Since September 2015, the behaviour has been changed - PROXYSQL STOP
		# executes faster and immediately shuts down the connections, thus this
		# test is expected to raise OperationalError
		ProxySQLBaseTest.run_query_proxysql_admin("PROXYSQL STOP")