# ProxySQL v1.2.4

Release date: 2016-09-29

## Performance improvement

None

## Usability improvement

* Admin: Report in error log if unable to read config file [#705](../../../../issues/705)
* Admin: Allow GO clients to connect to Admin interface using user "stats" [#708](../../../../issues/708)
* Monitor: added [diamond Collector](../../diamond/) to export to graphite or similar

## New features

* Admin: introduced new variable status related to connection pool usage [#703](../../../../issues/703)
* Protocol: filters SHOW WARNINGS , [#696](../../../../issues/696)

## Bug fixes

* Mirroring: crashing bug on mirrorred traffic and show mysql status [#699](../../../../issues/699)
* Connection Pool: SSL did not work with RDS , [#700](../../../../issues/700)
* Protocol: in some case, compressed packets were being corrupted [#297](../../../../issues/297)
* Monitor: rows were not deleted from monitor tables [#704](../../../../issues/704)
