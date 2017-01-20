## ProxySQL v1.3.3

Release date: 2016-12-29

Stable release v1.3.3 , released on 2017-01-20

Compared to v1.3.2, has the following bugs fixed / enhancements:

* MySQL Protocol: handle for mysql [bug 66884](https://bugs.mysql.com/bug.php?id=66884) that could cause infinite loop [#873](../../../../issues/873)
* MySQL Protocol: improved SSL connection over slow network, workaround for bug CONC-225 [#883](../../../../issues/833)
* Query routing: in some circumstances `transaction_persistent` could disable routing after commit #889](../../../../issues/889)
* Admin: `Latency_us` was incorrectly named `Latency_ms` [#882](../../../../issues/882)
* Admin: improved scalability on access to `mysql_servers`
* General: improved sypport for systemd
* General: init script returns codes for LSB compliance
* MySQL Protocol: removed assert() for unknown commands, and replaced with an error [#859](../../../../issues/859)
* MySQL Protocol: return an error for `COM_PROCESS_KILL`, deprecated command [#858](../../../../issues/858)
