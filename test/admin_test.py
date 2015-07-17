from proxysql_base_test import ProxySQLBaseTest

class AdminTest(ProxySQLBaseTest):

	SCENARIO = "./scenarios/1backend"

	def test_stop_main_thread(self):
		# This test will just assert that PROXYSQL STOP works correctly
		ProxySQLBaseTest.run_query_proxysql_admin("PROXYSQL STOP")