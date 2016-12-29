## ProxySQL v1.3.1

Release date: 2016-12-12

Stable release v1.3.1 , released on 2016-12-12

Compared to v1.3.0h, has the following bugs fixed / enhancements:

* Prepared statements: memory leak on error during STMT_EXECUTE [#796](../../../../issues/796)
* Monitor: incorrectly reported timeout on check read_only [#836](../../../../issues/836)
* Monitor: crashing bug [#715](../../../../issues/715)
* MySQL Protocol: handles charset = 0 [#810](../../../../issues/810)
* MySQL Protocol: disables multiplexing for SET FOREIGN_KEY_CHECKS [#835](../../../../issues/835)
* MySQL Protocol: disables multiplexing for SET UNIQUE_CHECKS [#835](../../../../issues/835)
