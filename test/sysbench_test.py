from proxysql_base_test import ProxySQLBaseTest

class SysBenchTest(ProxySQLBaseTest):

	DOCKER_COMPOSE_FILE = "./scenarios/1backend"

	def test_proxy_doesnt_crash_under_mild_sysbench_load(self):
		self.run_sysbench_proxysql()