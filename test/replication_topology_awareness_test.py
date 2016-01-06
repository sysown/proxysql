import MySQLdb
from MySQLdb import OperationalError
from nose.tools import raises
import random
import time

from proxysql_base_test import ProxySQLBaseTest

"""
class ReplicationTopologyAwareness(ProxySQLBaseTest):

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

	def _test_promote_slave_to_master_reflected_in_proxysql_admin_tables(self):
		self._start_replication()
		time.sleep(5)
		self._promote_first_slave_to_master()
		self._check_slave_promotion_reflected_in_proxysql_admin()

	def test_promote_slave_to_master_reflected_in_proxysql_admin_tables(self):
		self.run_in_docker_scenarios(self._test_promote_slave_to_master_reflected_in_proxysql_admin_tables,
									scenarios=['5backends-replication'])

	def _wait_for_slave_to_catch_up(self, slave_container_id):
		# Wait for the slave to catch up with the master
		slave_caught_up = False
		while not slave_caught_up:
			slave_status = self.run_query_mysql_container(
				'SHOW SLAVE STATUS',
				'information_schema',
				slave_container_id
			)
			slave_caught_up = slave_status[0][44].startswith(
											'Slave has read all relay log')

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
			self.run_query_mysql_container('SET GLOBAL read_only=ON', 'information_schema', slave_container_id)
			self._wait_for_slave_to_catch_up(slave_container_id)

		# Let ProxySQL know that:
		# - the readers (slaves) are in hostgroup 1
		# - the writer (master) is in hostgroup 0
		self.run_query_proxysql_admin("INSERT INTO mysql_replication_hostgroups(writer_hostgroup, reader_hostgroup) VALUES(0, 1)")

	def _promote_first_slave_to_master(self):
		# Following steps from https://dev.mysql.com/doc/refman/5.6/en/replication-solutions-switch.html

		# Send STOP SLAVE IO_THREAD to all slave
		master_container = self.get_mysql_containers(hostgroup=0)[0]
		slave_containers = self.get_mysql_containers(hostgroup=1)
		for slave_container_id in slave_containers:
			self.run_query_mysql_container('STOP SLAVE IO_THREAD',
											'information_schema',
											slave_container_id)
			self._wait_for_slave_to_catch_up(slave_container_id)

		# Find out from the metadata which of the slaves is the one to be
		# promoted as a master
		first_slave = None
		for slave_container_id in slave_containers:
			meta = self.docker_inspect(slave_container_id)
			if 'NEW_MASTER=True' in meta['Config']['Env']:
				first_slave = slave_container_id
				first_slave_ip = meta['NetworkSettings']['IPAddress']

		# Promote slave1 to a master
		self.run_query_mysql_container('SET GLOBAL read_only=OFF',
										'information_schema',
										first_slave)
		self.run_query_mysql_container('STOP SLAVE',
										'information_schema',
										first_slave)
		self.run_query_mysql_container('RESET MASTER',
										'information_schema',
										first_slave)

		# Point the other slaves to the newly elected master
		for slave_container_id in slave_containers:
			if slave_container_id == first_slave:
				continue

			self.run_query_mysql_container('STOP SLAVE',
											'information_schema',
											slave_container_id)
			self.run_query_mysql_container("CHANGE MASTER TO MASTER_HOST = '%s'" % first_slave_ip,
											'information_schema',
											slave_container_id)
			self.run_query_mysql_container('START SLAVE',
											'information_schema',
											slave_container_id)

		# Point the old master to the new master (that was previously a slave)
		config = self.get_tests_config()
		username = config.get('ProxySQL', 'username')
		password = config.get('ProxySQL', 'password')
		self.run_query_mysql_container('SET GLOBAL read_only=ON',
										'information_schema',
										master_container)
		q = "CHANGE MASTER TO MASTER_HOST = '%s', MASTER_PORT = 3306, MASTER_USER = '%s', MASTER_PASSWORD = '%s', MASTER_AUTO_POSITION = 1"
		self.run_query_mysql_container(q % (first_slave_ip, username, password),
										'information_schema',
										master_container)
		self.run_query_mysql_container('RESET SLAVE',
										'information_schema',
										master_container)
		self.run_query_mysql_container('START SLAVE',
										'information_schema',
										master_container)

		# Wait for the slaves to catch up with the new master
		new_slaves = set(slave_containers)
		new_slaves.remove(first_slave)
		new_slaves.add(master_container)
		for slave_container_id in new_slaves:
			self._wait_for_slave_to_catch_up(slave_container_id)

	def _check_slave_promotion_reflected_in_proxysql_admin(self):
		# Determine mapping from container IDs to IPs
		old_master_container = self.get_mysql_containers(hostgroup=0)[0]
		old_slave_containers = self.get_mysql_containers(hostgroup=1)
		slave_ips = set()
		old_master_ip = self.docker_inspect(old_master_container)['NetworkSettings']['IPAddress']
		slave_ips.add(old_master_ip)
		for slave_container_id in old_slave_containers:
			meta = self.docker_inspect(slave_container_id)
			slave_ip = meta['NetworkSettings']['IPAddress']
			if 'NEW_MASTER=True' in meta['Config']['Env']:
				master_ip = slave_ip
			else:
				slave_ips.add(slave_ip)

		rows = self.run_query_proxysql_admin("SELECT * FROM mysql_servers")
		hostgroups = {}
		for row in rows:
			hostgroups[row[1]] = int(row[0])

		# First slave is now a master, thus should be present in the writer hostgroup
		self.assertEqual(hostgroups[master_ip], 0)

		# The old master, and the other slaves should still be in the slave hostgroup
		for ip in slave_ips:
			self.assertEqual(hostgroups[ip], 1)
"""