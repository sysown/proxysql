import re
import subprocess
import time
from unittest import TestCase

from docker import Client
from docker.utils import kwargs_from_env
import MySQLdb

class ProxySQLBaseTest(TestCase):

	DOCKER_COMPOSE_FILE = None
	PROXYSQL_ADMIN_PORT = 6032
	PROXYSQL_ADMIN_USERNAME = "admin"
	PROXYSQL_ADMIN_PASSWORD = "admin"
	PROXYSQL_RW_PORT = 6033
	PROXYSQL_RW_USERNAME = "root"
	PROXYSQL_RW_PASSWORD = "root"

	@classmethod
	def _startup_docker_services(cls):
		# We have to perform docker-compose build + docker-compose up,
		# instead of just doing the latter because of a bug which will give a
		# 500 internal error for the Docker bug. When this is fixed, we should
		# remove this first extra step.
		subprocess.call(["docker-compose", "build"], cwd=cls.DOCKER_COMPOSE_FILE)
		subprocess.call(["docker-compose", "up", "-d"], cwd=cls.DOCKER_COMPOSE_FILE)

	@classmethod
	def _shutdown_docker_services(cls):
		subprocess.call(["docker-compose", "stop"], cwd=cls.DOCKER_COMPOSE_FILE)
		subprocess.call(["docker-compose", "rm", "--force"], cwd=cls.DOCKER_COMPOSE_FILE)

	@classmethod
	def _get_proxysql_container(cls):
		containers = Client(**kwargs_from_env()).containers()
		for container in containers:
			if 'proxysql' in container['Image']:
				return container

	@classmethod
	def _get_mysql_containers(cls):
		result = []
		containers = Client(**kwargs_from_env()).containers()
		for container in containers:
			if 'proxysql' not in container['Image']:
				result.append(container)
		return result

	@classmethod
	def _populate_mysql_containers_with_dump(cls):
		mysql_containers = cls._get_mysql_containers()
		# We have already added the SQL dump to the container by using
		# the ADD mysql command in the Dockerfile for mysql -- check it
		# out. The standard agreed location is at /tmp/schema.sql.
		#
		# Unfortunately we can't do this step at runtime due to limitations
		# on how transfer between host and container is supposed to work by
		# design. See the Dockerfile for MySQL for more details.
		for mysql_container in mysql_containers:
			container_id = mysql_container['Names'][0][1:]
			subprocess.call(["docker", "exec", container_id, "bash", "/tmp/import_schema.sh"])

	@classmethod
	def _extract_hostgroup_from_container_name(cls, container_name):
		service_name = container_name.split('_')[1]
		return int(re.search(r'BACKEND(\d+)HOSTGROUP(\d+)', service_name).group(2))

	@classmethod
	def _extract_port_number_from_uri(cls, uri):
		return int(uri.split(':')[2])

	@classmethod
	def _get_environment_variables_from_container(cls, container_name):
		output = Client(**kwargs_from_env()).execute(container_name, 'env')
		result = {}
		lines = output.split('\n')
		for line in lines:
			line = line.strip()
			if len(line) == 0:
				continue
			(k, v) = line.split('=')
			result[k] = v
		return result

	@classmethod
	def _populate_proxy_configuration_with_backends(cls):
		proxysql_container = cls._get_proxysql_container()
		mysql_containers = cls._get_mysql_containers()
		environment_variables = cls._get_environment_variables_from_container(
											 proxysql_container['Names'][0][1:])

		proxy_admin_connection = MySQLdb.connect("127.0.0.1",
												cls.PROXYSQL_ADMIN_USERNAME,
												cls.PROXYSQL_ADMIN_PASSWORD,
												port=cls.PROXYSQL_ADMIN_PORT)
		cursor = proxy_admin_connection.cursor()

		for mysql_container in mysql_containers:
			container_name = mysql_container['Names'][0][1:].upper()
			port_uri = environment_variables['%s_PORT' % container_name]
			port_no = cls._extract_port_number_from_uri(port_uri)
			ip = environment_variables['%s_PORT_%d_TCP_ADDR' % (container_name, port_no)]
			hostgroup = cls._extract_hostgroup_from_container_name(container_name)
			cursor.execute("INSERT INTO mysql_servers(hostgroup_id, hostname, port, status) "
							"VALUES(%d, '%s', %d, 'ONLINE')" %
							(hostgroup, ip, port_no))

		cursor.execute("LOAD MYSQL SERVERS TO RUNTIME")
		cursor.close()
		proxy_admin_connection.close()

	@classmethod
	def setUpClass(cls):
		cls._shutdown_docker_services()
		cls._startup_docker_services()

		# TODO(andrei): figure out a more reliable method to wait for
		# MySQL to start up within the container. Otherwise, there will be
		# an error when we try to initialize the MySQL instance with the dump.
		time.sleep(30)
		cls._populate_mysql_containers_with_dump()

		cls._populate_proxy_configuration_with_backends()

	@classmethod
	def tearDownClass(cls):
		cls._shutdown_docker_services()

	