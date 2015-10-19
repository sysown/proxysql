from proxysql_base_test import ProxySQLBaseTest

class SysBenchTest(ProxySQLBaseTest):

	def test_proxy_doesnt_crash_under_mild_sysbench_load(self):
		ProxySQLBaseTest.run_sysbench_proxysql()