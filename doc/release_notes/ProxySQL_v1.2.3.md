# ProxySQL v1.2.3

Release date: 2016-09-20

## Performance improvement

None


## Usability improvement

* Admin: introduced new table `runtime_mysql_users` [#691](../../../../issues/691)
* Compile: new packages avaiable for Fedora24
* Compile: new packages avaiable for Ubuntu16
* Doc: updated documentation on passwords
* General: added suppot for systemd (yet not included in binaries)


## New features

* Admin: introduced new variable `admin-hash_passwords` to automatically hash mysql passwords [#676](../../../../issues/676)
* Query Cache: aggressive memory purging when 90% of memory limit is reached [#690](../../../../issues/690)
* Query Processor: added parsing for several SQL commands


## Bug fixes

* Mirroring: fixes several bugs related to errors handling
* Mirroring: fixes crashing bug
* Query Cache: memory used was computed incorrectly
* Connection Pool: a failed `CHANGE_USER` could cause a crash [#682](../../../../issues/682)


## Contributors

Thanks to contributors, in alphabetical order:
* @dveeden
