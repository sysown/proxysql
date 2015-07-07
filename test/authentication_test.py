import MySQLdb
from MySQLdb import OperationalError
from nose.tools import raises

from proxysql_base_test import ProxySQLBaseTest

class AuthenticationTest(ProxySQLBaseTest):

	DOCKER_COMPOSE_FILE = "./scenarios/1backend"

	def test_existing_user_with_correct_password_works(self):
		version1 = ProxySQLBaseTest.run_query_mysql(
								"SELECT @@version_comment LIMIT 1", "test",
								return_result=True,
								username="john", password="doe")

		version2 = ProxySQLBaseTest.run_query_proxysql(
								"SELECT @@version_comment LIMIT 1", "test",
								return_result=True,
								username="john", password="doe")

		self.assertEqual(version1, version2)

	@raises(OperationalError)
	def test_existing_user_with_correct_password_but_not_registerd_within_proxysql_does_not_work(self):
		version1 = ProxySQLBaseTest.run_query_proxysql(
								"SELECT @@version_comment LIMIT 1", "test",
								return_result=True,
								username="danny", password="white")

	@raises(OperationalError)
	def test_existing_user_with_incorrect_password_does_not_work(self):
		version = ProxySQLBaseTest.run_query_proxysql(
								"SELECT @@version_comment LIMIT 1", "test",
								return_result=True,
								username="john", password="doe2")

	@raises(OperationalError)
	def test_inexisting_user_with_random_password_does_not_work(self):
		version = ProxySQLBaseTest.run_query_proxysql(
								"SELECT @@version_comment LIMIT 1", "test",
								return_result=True,
								username="johnny", password="randomdoe")