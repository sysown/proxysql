# How are the tests built?

First off, a few words about how the infrastructure of the tests looks like.

Tests are written in Python, and the services needed for running a test
(a ProxySQL instance and one or more MySQL instances) are specified in a
docker-compose.yml file and are started by using Docker's docker-compose.

Tests are ran using nosetests (https://nose.readthedocs.org/en/latest/),
Python's de facto leader in terms of how tests are written and ran. The command
to run the tests is, from the root of the repository:

```python
nosetests --nocapture
```

The "--nocapture" flag is present in order to have detailed output on what is
going on. Otherwise, the output will be suppressed by nosetests to give you only
a high-level report of how many tests passed and failed.

# Where can I find the tests?

Tests are grouped in scenarios. A __scenario__ specifies a configuration of
ProxySQL and MySQL backends, together with initial data to populate the MySQL
instances (a text file containing SQL queries).

The folder "scenarios" found in the root folder of the repository contains
these scenarios. There is a "base" folder with common utilities, and then there
is one folder for each scenario. For example, "1backend" is the name for the
scenario of 1 ProxySQL proxy, and 1 MySQL backend.

To create such a scenario, the simplest way to go about, is to copy-paste the
"1backend" scenario and modify it. Some of the important things to modify:
- docker-compose.yml. This is where the list of services is described, and
  where you actuall specify how many MySQL backends there are, and which ports
  they expose and how. Be careful, there is a naming convention
- mysql/schema.sql. This is where the MySQL backends get populated

# How do I write a test?

It's pretty simple. Once you have a working scenario, you write a class in
the top-level "test" folder, which inherits from ProxySQLBaseTest. One such
example is one_backend_test.py. The only thing which you should specify is
the docker-compose filename, and then start querying both the proxy and the
MySQL backends and testing assertions by using the `run_query_proxysql` and
`run_query_mysql' class methods.