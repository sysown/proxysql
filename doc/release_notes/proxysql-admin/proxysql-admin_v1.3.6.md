# proxysql-admin v1.3.6

Release date : May 12, 2017

### Usability improvement

* Improved proxysql-admin mysql connection error message.
* Made --write-node optional with singlewrite mode.
* Added notes in /etc/proxysql-admin.cnf for each of the parameters.
* Added writer node sanity check with wsrep_incoming_addresses

### Bug fixes

* Fixed PQA-145 : proxysql-admin --quick-demo mode does not set auto-configure

