import copy
import hashlib
import os
from os import path
import random
import re
import shutil
import subprocess
import tempfile
import time

from docker import Client
from docker.utils import kwargs_from_env
from jinja2 import Template
import MySQLdb

from proxysql_tests_config import ProxySQL_Tests_Config

class DockerFleet(object):

	def __init__(self, config_overrides = {}):
		self.config_overrides = config_overrides

	def _get_dockerfiles_for(self, token):
		"""Retrieves the list of Dockerfiles for a given type of machine.

		The available types are: proxysql and mysql.
		"""
		files = {}
		dockerfiles_path = os.path.dirname(__file__) + "/../docker/images/%s" % token
		for item in os.listdir(dockerfiles_path):
			dir_path = dockerfiles_path + os.sep + item
			if path.isdir(dir_path):
				dockerfile = dir_path + os.sep + "Dockerfile"
				if path.isfile(dockerfile):
					files[item] = {
						"dir": dir_path,
						"dockerfile": dockerfile
					}
		return files

	def get_dockerfiles_for_proxysql(self):
		"""Retrieves the list of Dockerfiles available to build ProxySQL."""
		return self._get_dockerfiles_for('proxysql')

	def get_dockerfiles_for_mysql(self):
		"""Retrieves the list of Dockerfiles available to build MySQL."""
		return self._get_dockerfiles_for('mysql')

	def build_images(self):
		"""Builds docker images for all the Dockerfiles available for
		ProxySQL/MySQL."""
		proxysql_dockerfiles = self.get_dockerfiles_for_proxysql()
		mysql_dockerfiles = self.get_dockerfiles_for_mysql()

		for label, info in proxysql_dockerfiles.iteritems():
			subprocess.call(["docker", "rmi", "-f", "proxysql:%s" % label])
			subprocess.call(["docker", "build", "-t", "proxysql:%s" % label, "."], cwd=info["dir"])

		for label, info in mysql_dockerfiles.iteritems():
			subprocess.call(["docker", "rmi", "-f", "proxysql:%s" % label])
			subprocess.call(["docker", "build", "-t", "proxysql:%s" % label, "."], cwd=info["dir"])

	def get_docker_images(self, filters):
		# docker images --filter "label=vendor=proxysql" --filter "label=com.proxysql.purpose=testing"
		args = ["docker", "images"]
		for k, v in filters.iteritems():
			args.append("--filter")
			args.append("label=%s=%s" % (k, v))
		p = subprocess.Popen(args, stdout=subprocess.PIPE)
		out, _ = p.communicate()
		lines = out.split('\n')
		nonemtpy_lines = [l for l in lines if len(l.strip()) > 0]
		results = nonemtpy_lines[1:]
		images = []
		for (i, r) in enumerate(results):
			tokens = r.split(' ')
			nonempty_tokens = [t for t in tokens if len(t.strip()) > 0]
			images.append(nonempty_tokens[1])
		return images

	def get_docker_scenario_templates(self):
		"""Retrieve the list of docker templates that will be used to generate
		scenarios.

		Why do we need templates for scenarios? Because the scenario will be
		the same, the only difference will be the configuration of the machines
		involved (for example, it might be a different operating system).
		"""
		files = {}
		dockercompose_path = os.path.dirname(__file__) + "/../docker/scenarios"
		for item in os.listdir(dockercompose_path):
			dir_path = dockercompose_path + os.sep + item
			if path.isdir(dir_path):
				dockercomposefile = dir_path + os.sep + "docker-compose.yml"
				if path.isfile(dockercomposefile):
					files[item] = {
						"dir": dir_path,
						"dockercomposefile": dockercomposefile
					}
					with open (dockercomposefile, "r") as myfile:
						files[item]["contents"] = data=myfile.read()
		return files

	def generate_scenarios(self, filters={}):
		# We have 2 types of docker images - for testing and for packaging.
		# We will only use the ones for testing, because the others won't have
		# a running daemon inside.
		image_filters = copy.deepcopy(filters)
		image_filters['vendor'] = 'proxysql'
		image_filters['com.proxysql.purpose'] = 'testing'

		proxysql_filters = copy.deepcopy(image_filters)
		proxysql_filters['com.proxysql.type'] = 'proxysql'

		mysql_filters = copy.deepcopy(image_filters)
		mysql_filters['com.proxysql.type'] = 'proxysql'

		unique_scenarios = {}

		proxysql_images = self.get_docker_images(proxysql_filters)
		mysql_images = self.get_docker_images(mysql_filters)
		scenario_templates = self.get_docker_scenario_templates()

		for scenario_label, scenario_info in scenario_templates.iteritems():
			for proxysql_image in proxysql_images:
				for mysql_image in mysql_images:
					template = Template(scenario_info['contents'])
					scenario = template.render({
						'proxysql_image': proxysql_image,
						'mysql_image': mysql_image
					})
					m = hashlib.md5()
					m.update(scenario)
					digest = m.digest()
					if digest not in unique_scenarios:
						unique_scenarios[digest] = {
							'content': scenario,
							'proxysql_image': proxysql_image,
							'mysql_image': mysql_image,
							'scenario_dir': scenario_info['dir'],
							'scenario_dockercompose_file': scenario_info['dockercomposefile']
						}
		return unique_scenarios.values()

	def _wait_for_daemons_startup(self):
		# First off, wait for all the MySQL backends to have initialized
		mysql_credentials = self.get_all_mysql_connection_credentials()
		for credential in mysql_credentials:
			self.wait_for_mysql_connection_ok(**credential)

		# Afterwards, wait for the main ProxySQL thread to start responding to
		# MySQL queries. Note that we have chosen such a query that gets handled
		# directly by the proxy. That makes sure that tests are running
		# correctly even when there's something broken inside ProxySQL.
		proxysql_credentials = self.get_proxysql_connection_credentials()
		self.wait_for_mysql_connection_ok(**proxysql_credentials)
		proxysql_admin_credentials = self.get_proxysql_admin_connection_credentials()
		self.wait_for_mysql_connection_ok(**proxysql_admin_credentials)

		# Extra sleep at the end, because if the test tries to shut down
		# ProxySQL too close to its startup, problems may arise
		time.sleep(5)

	def _create_folder_to_share_proxysql_code_with_container(self):
		try:
			if os.path.exists('/tmp/proxysql-tests'):
				shutil.rmtree('/tmp/proxysql-tests/')
		except:
			pass

		os.mkdir('/tmp/proxysql-tests')
		os.system("cp -R " + os.path.dirname(__file__) + "/../* /tmp/proxysql-tests")

	def _delete_folder_with_shared_proxysql_code(self):
		shutil.rmtree('/tmp/proxysql-tests/')

	def _stop_existing_docker_containers(self):
		"""Stops any proxysql-related docker containers running on this host.

		Warning: this means that if you are running the tests and using this
		host to operate a production instance of ProxySQL using Docker, it
		will be stopped. Unfortunately, there is no easy way to differentiate
		between the two.
		"""
		args = ["docker", "ps", "--filter", "label=vendor=proxysql"]
		p = subprocess.Popen(args, stdout=subprocess.PIPE)
		out, _ = p.communicate()
		lines = out.split('\n')
		nonemtpy_lines = [l for l in lines if len(l.strip()) > 0]
		results = nonemtpy_lines[1:]
		images = []
		for (i, r) in enumerate(results):
			tokens = r.split(' ')
			nonempty_tokens = [t for t in tokens if len(t.strip()) > 0]
			images.append(nonempty_tokens[0])
		
		for image in images:
			subprocess.call(["docker", "kill", image])

	def start_temp_scenario(self, scenario, copy_folder=True):
		self._stop_existing_docker_containers()
		if copy_folder:
			self._create_folder_to_share_proxysql_code_with_container()

		dirname = tempfile.mkdtemp('-proxysql-tests')
		filename = "%s/docker-compose.yml" % dirname
		with open(filename, "wt") as f:
			f.write(scenario['content'])
		subprocess.call(["docker-compose", "up", "-d"], cwd=dirname)

		self._wait_for_daemons_startup()
		self._populate_mysql_containers_with_dump()
		self._populate_proxy_configuration_with_backends()

		return dirname

	def stop_temp_scenario(self, path_to_scenario, delete_folder=True):
		# Shut down ProxySQL cleanly
		try:
			cls.run_query_proxysql_admin("PROXYSQL SHUTDOWN")
		except:
			# This will throw an exception because it will forcefully shut down
			# the connection with the MySQL client.
			pass

		subprocess.call(["docker-compose", "stop"], cwd=path_to_scenario)
		if delete_folder:
			self._delete_folder_with_shared_proxysql_code()

	def get_proxysql_container(self):
		"""Out of all the started docker containers, select the one which
		represents the proxy instance.

		Note that this only supports one proxy instance for now. This method
		relies on interogating the Docker daemon via its REST API.
		"""

		containers = Client(**kwargs_from_env()).containers()
		for container in containers:
			if container.get('Labels').get('vendor') == 'proxysql':
				if container['Labels']['com.proxysql.type'] == 'proxysql':
					return container

	def get_mysql_containers(self):
		"""Out of all the started docker containers, select the ones which
		represent the MySQL backend instances.

		This method relies on interogating the Docker daemon via its REST API.
		"""

		result = []
		containers = Client(**kwargs_from_env()).containers()
		for container in containers:
			if container.get('Labels').get('vendor') == 'proxysql':
				if container['Labels']['com.proxysql.type'] == 'mysql':
					result.append(container)
		return result

	def mysql_connection_ok(self, hostname, port, username, password, schema):
		"""Checks whether the MySQL server reachable at (hostname, port) is
		up or not. This is useful for waiting for ProxySQL/MySQL containers to
		start up correctly (meaning that the daemons running inside them have
		started to be able to respond to queries).
		"""
		try:
			db = MySQLdb.connect(host=hostname,
									user=username,
									passwd=password,
									db=schema,
									port=int(port))
			cursor = db.cursor() 
			cursor.execute("select @@version_comment limit 1")
			results = cursor.fetchone()
			# Check if anything at all is returned
			if results:
				return True
			else:
				return False
		except MySQLdb.Error, e:
			pass

		return False

	def wait_for_mysql_connection_ok(self, hostname, port, username, password,
									max_retries=500, time_between_retries=1):

		retries = 0
		result = False

		while (not result) and (retries < max_retries):
			result = self.mysql_connection_ok(
				hostname=hostname,
				port=port,
				username=username,
				password=password,
				schema="information_schema"
			)
			if not result:
				retries += 1
				time.sleep(1)
				print("Trying again to connect to %s:%s (retries=%d)" % (hostname, port, retries))

		return result

	def _extract_hostgroup_from_container_name(self, container_name):
		"""MySQL backend containers are named using a naming convention:
		backendXhostgroupY, where X and Y can be multi-digit numbers.
		This extracts the value of the hostgroup from the container name.

		I made this choice because I wasn't able to find another easy way to
		associate arbitrary metadata with a Docker container through the
		docker compose file.
		"""

		service_name = container_name.split('_')[1]
		return int(re.search(r'BACKEND(\d+)HOSTGROUP(\d+)', service_name).group(2))

	def get_all_mysql_connection_credentials(self, hostgroup=None):
		# Figure out which are the containers for the specified hostgroup
		mysql_backends = self.get_mysql_containers()
		mysql_backends_in_hostgroup = []
		for backend in mysql_backends:
			container_name = backend['Names'][0][1:].upper()
			backend_hostgroup = self._extract_hostgroup_from_container_name(container_name)

			mysql_port_exposed=False
			if not backend.get('Ports'):
				continue
			for exposed_port in backend.get('Ports', []):
				if exposed_port['PrivatePort'] == 3306:
					mysql_port_exposed = True

			if ((backend_hostgroup == hostgroup) or (hostgroup is None)) and mysql_port_exposed:
				mysql_backends_in_hostgroup.append(backend)

		config = ProxySQL_Tests_Config(overrides=self.config_overrides)
		hostname = config.get('ProxySQL', 'hostname')
		username = config.get('ProxySQL', 'username')
		password = config.get('ProxySQL', 'password')

		result = []
		for container in mysql_backends_in_hostgroup:
			for exposed_port in container.get('Ports', []):
				if exposed_port['PrivatePort'] == 3306:
					mysql_port = exposed_port['PublicPort']
					result.append({
						'hostname': hostname,
						'port': mysql_port,
						'username': username,
						'password': password
					})
		return result

	def get_mysql_connection_credentials(self, hostgroup=0):
		
		credentials = self.get_all_mysql_connection_credentials(hostgroup=hostgroup)

		if len(credentials) == 0:
			raise Exception('No backends with a publicly exposed port were '
							'found in hostgroup %d' % hostgroup)

		return random.choice(credentials)

	def get_proxysql_connection_credentials(self):
		config = ProxySQL_Tests_Config(overrides=self.config_overrides) 
		return {
			"hostname": config.get("ProxySQL", "hostname"),
			"port": config.get("ProxySQL", "port"),
			"username": config.get("ProxySQL", "username"),
			"password": config.get("ProxySQL", "password")
		}

	def get_proxysql_admin_connection_credentials(self):
		config = ProxySQL_Tests_Config(overrides=self.config_overrides) 
		return {
			"hostname": config.get("ProxySQL", "hostname"),
			"port": config.get("ProxySQL", "admin_port"),
			"username": config.get("ProxySQL", "admin_username"),
			"password": config.get("ProxySQL", "admin_password")
		}

	def _populate_mysql_containers_with_dump(self):
		"""Populates the started MySQL backend containers with the specified
		SQL dump file.

		The reason for doing this __after__ the containers are started is
		because we want to keep them as generic as possible.
		"""

		mysql_containers = self.get_mysql_containers()
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

	def _populate_proxy_configuration_with_backends(self):
		"""Populate ProxySQL's admin information with the MySQL backends
		and their associated hostgroups.

		This is needed because I do not want to hardcode this into the ProxySQL
		config file of the test scenario, as it leaves more room for quick
		iteration.

		In order to configure ProxySQL with the correct backends, we are using
		the MySQL admin interface of ProxySQL, and inserting rows into the
		`mysql_servers` table, which contains a list of which servers go into
		which hostgroup.
		"""
		config = ProxySQL_Tests_Config(overrides=self.config_overrides)
		proxysql_container = self.get_proxysql_container()
		mysql_containers = self.get_mysql_containers()
		environment_variables = self._get_environment_variables_from_container(
											 proxysql_container['Names'][0][1:])

		proxy_admin_connection = MySQLdb.connect(config.get('ProxySQL', 'hostname'),
												config.get('ProxySQL', 'admin_username'),
												config.get('ProxySQL', 'admin_password'),
												port=int(config.get('ProxySQL', 'admin_port')))
		cursor = proxy_admin_connection.cursor()

		for mysql_container in mysql_containers:
			container_name = mysql_container['Names'][0][1:].upper()
			port_uri = environment_variables['%s_PORT' % container_name]
			port_no = self._extract_port_number_from_uri(port_uri)
			ip = environment_variables['%s_PORT_%d_TCP_ADDR' % (container_name, port_no)]
			hostgroup = self._extract_hostgroup_from_container_name(container_name)
			cursor.execute("INSERT INTO mysql_servers(hostgroup_id, hostname, port, status) "
							"VALUES(%d, '%s', %d, 'ONLINE')" %
							(hostgroup, ip, port_no))

		cursor.execute("LOAD MYSQL SERVERS TO RUNTIME")
		cursor.close()
		proxy_admin_connection.close()

	def _extract_port_number_from_uri(self, uri):
		"""Given a Docker container URI (exposed as an environment variable by
		the host linking mechanism), extract the TCP port number from it."""
		return int(uri.split(':')[2])

	def _get_environment_variables_from_container(self, container_name):
		"""Retrieve the environment variables from the given container.

		This is useful because the host linking mechanism will expose
		connectivity information to the linked hosts by the use of environment
		variables.
		"""

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

	def run_query_proxysql(self, query, db, 
							hostname=None, port=None,
							username=None, password=None,
							return_result=True):
		"""Run a query against the ProxySQL proxy and optionally return its
		results as a set of rows."""
		credentials = self.get_proxysql_connection_credentials()
		proxy_connection = MySQLdb.connect(hostname or credentials['hostname'],
											username or credentials['username'],
											password or credentials['password'],
											port=int(port or credentials['port']),
											db=db)
		cursor = proxy_connection.cursor()
		cursor.execute(query)
		if return_result:
			rows = cursor.fetchall()
		cursor.close()
		proxy_connection.close()
		if return_result:
			return rows

	def run_query_proxysql_admin(self, query, return_result=True):
		"""Run a query against the ProxySQL admin.

		Note: we do not need to specify a db for this query, as it's always
		against the "main" database.
		TODO(andrei): revisit db assumption once stats databases from ProxySQL
		are accessible via the MySQL interface.
		"""
		credentials = self.get_proxysql_admin_connection_credentials()
		proxy_connection = MySQLdb.connect(credentials['hostname'],
											credentials['username'],
											credentials['password'],
											port=int(credentials['port']),
											db='main')
		cursor = proxy_connection.cursor()
		cursor.execute(query)
		if return_result:
			rows = cursor.fetchall()
		cursor.close()
		proxy_connection.close()
		if return_result:
			return rows

	def run_query_mysql(self, query, db, return_result=True, hostgroup=0,
					    username=None, password=None):
		"""Run a query against the MySQL backend and optionally return its
		results as a set of rows.

		IMPORTANT: since the queries are actually ran against the MySQL backend,
		that backend needs to expose its MySQL port to the outside through
		docker compose's port mapping mechanism.

		This will actually parse the docker-compose configuration file to
		retrieve the available backends and hostgroups and will pick a backend
		from the specified hostgroup."""

		credentials = self.get_mysql_connection_credentials(hostgroup=hostgroup)
		mysql_connection = MySQLdb.connect(host=credentials['hostname'],
											user=username or credentials['username'],
											passwd=password or credentials['password'],
											port=int(credentials['port']),
											db=db)
		cursor = mysql_connection.cursor()
		cursor.execute(query)
		if return_result:
			rows = cursor.fetchall()
		cursor.close()
		mysql_connection.close()
		if return_result:
			return rows
