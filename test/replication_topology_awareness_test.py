import MySQLdb
from MySQLdb import OperationalError
from nose.tools import raises
import random
import time

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

			slave_caught_up = False
			while not slave_caught_up:
				slave_status = self.run_query_mysql_container(
					'SHOW SLAVE STATUS',
					'information_schema',
					slave_container_id
				)
				slave_caught_up = slave_status[0][44].startswith(
												'Slave has read all relay log')

	def _test_insert_sent_through_proxysql_is_visible_in_slave_servers(self):
		self._start_replication()

		random_string = ''.join(random.choice(['a', 'b', 'c', 'd', 'e']) for _ in xrange(10))
		q = "INSERT INTO strings(value) VALUES('%s')" % random_string
		self.run_query_proxysql(q, "test")

		# Give slaves the time to catch up
		time.sleep(5)

		slave_containers = self.get_mysql_containers(hostgroup=1)
		for slave_container_id in slave_containers:
			q = "SELECT * FROM strings"
			rows = self.run_query_mysql_container("SELECT * FROM strings",
													"test",
													slave_container_id)
			self.assertEqual(set([row[0] for row in rows]),
						 	set(['a', 'ab', 'abc', 'abcd', random_string]))

	def test_insert_sent_through_proxysql_is_visible_in_slave_servers(self):
		self.run_in_docker_scenarios(self._test_insert_sent_through_proxysql_is_visible_in_slave_servers,
									scenarios=['5backends-replication'])