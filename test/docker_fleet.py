import copy
import hashlib
import os
from os import path
import subprocess
import tempfile

from jinja2 import Template

class DockerFleet(object):

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
						unique_scenarios[digest] = scenario
		return unique_scenarios

	def start_temp_scenario(self, scenario):
		dirname = tempfile.mkdtemp('-proxysql-tests')
		filename = "%s/docker-compose.yml" % dirname
		with open(filename, "wt") as f:
			f.write(scenario)
		subprocess.call(["docker-compose", "up", "-d"], cwd=dirname)
		return dirname

	def stop_temp_scenario(self, path_to_scenario):
		subprocess.call(["docker-compose", "stop"], cwd=path_to_scenario)