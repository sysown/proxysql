import MySQLdb
from MySQLdb import OperationalError
from nose.tools import raises

from proxysql_base_test import ProxySQLBaseTest

class ReplicationTopologyAwareness(ProxySQLBaseTest):

	def _start_replication(self):
		master_container = self.get_mysql_containers(hostgroup=0)[0]
		slave_containers = self.get_mysql_containers(hostgroup=1)
		proxysql_container = self.get_proxysql_container()

		# connect the slaves to the master
		for slave_container_id in slave_containers:
			env = self.get_environment_variables_from_container(slave_container_id)
			# master will have a local (hostname, port) address using which the
			# slave can access it. 
			master_local_hostname = env['BACKEND1HOSTGROUP0_PORT_3306_TCP_ADDR']
			master_local_port = env['BACKEND1HOSTGROUP0_PORT_3306_TCP_PORT']
			config = self.get_tests_config()
			username = config.get('ProxySQL', 'username')
			password = config.get('ProxySQL', 'password')
			args = (master_local_hostname, master_local_port, username, password)
			q = "CHANGE MASTER TO MASTER_HOST='%s', MASTER_PORT=%s, MASTER_USER='%s', MASTER_PASSWORD='%s', MASTER_AUTO_POSITION = 1" % args
			self.run_query_mysql_container(q, 'information_schema', slave_container_id)
			self.run_query_mysql_container('START SLAVE', 'information_schema', slave_container_id)

	def _test_promoting_slave_to_master_correctly_updates_admin_tables(self):
		self._start_replication()
		import pdb; pdb.set_trace()

	def test_promoting_slave_to_master_correctly_updates_admin_tables(self):
		self.run_in_docker_scenarios(self._test_promoting_slave_to_master_correctly_updates_admin_tables,
									scenarios=['5backends-replication'])