import subprocess
import time
from unittest import TestCase

from docker import Client
from docker.utils import kwargs_from_env
import MySQLdb

class ProxySQLTest(TestCase):

	DOCKER_COMPOSE_FILE = "./docker/1backend"

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
			if 'proxysql' in container['image']:
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
	def _populate_proxy_configuration_with_backends(cls):
		pass

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
		pass

	def test_asd(self):
		self.assertEqual(1, 1)

	def test_asdf(self):
		self.assertEqual(1, 1)