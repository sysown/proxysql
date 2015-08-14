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

# How do I run the tests locally?

1) install vagrant on the machine where you'll be running the tests

2) vagrant box add ubuntu-14.04 ubuntu-14.04.box
(The ubuntu-14.04.box file is obtained from https://github.com/jose-lpa/packer-ubuntu_14.04/releases/download/v2.0/ubuntu-14.04.box)

# This will actually install what is needed on the Vagrant box
3) cd proxysql/test; vagrant up; vagrant ssh -c "cd /opt/proxysql; nosetests --nocapture"; vagrant halt

# How do I run the tests on a machine without internet connectivity?

For that you need to prepare a Virtual box .box file with the latest state of
the code and the packages from a machine that has internet connectivity and
copy it over to the machine with no connectivity.

To prepare the .box file:

1) clone proxysql test repo locally, let's assume it's in ~/proxysql

2) cd ~/proxysql/test; vagrant up

This will update the machine with the latest master code. If you need to be
testing a different branch, you will have to do an extra step (step 3):

3) vagrant ssh -c "cd /opt/proxysql/test; git checkout my-branch; git pull origin my-branch; sudo pip install -r requirements.txt"

This will fetch the code for the given branch __and__ install the necessary
packages for running the tests on that branch (if there are any new packages).

4) Package it all in a .box file

vagrant package --output proxysql-tests.box

This will generate a big .box file, approximately 1.1GB as of the writing of
this document. This file can be run without having internet connectivity.

5) Copy the proxysql-tests.box to the machine where you want to run the tests

6) vagrant box add proxysql-tests proxysql-tests.box (from the directory where
you copied the .box file and where you are planning to run the tests)

7) vagrant init proxysql-tests; vagrant up

8) vagrant up; vagrant ssh -c "cd /opt/proxysql; nosetests --nocapture"; vagrant halt

to actually run the tests.

NB: we are assuming that the only useful output from running the tests is
stdout. As we will add more tests to the test suite, this section will be
refined on how to retrieve the results as well.
