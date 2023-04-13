In ProxySQL 2.0.4 , libssl was upgrade from 1.1.0h to 1.1.1b .

In ProxySQL 2.0.7 , libssl was downgraded back to 1.1.0h . See [bug 2244](https://github.com/sysown/proxysql/issues/2244) .

In ProxySQL 2.1.1 , libssl was upgraded to version 1.1.1j

In ProxySQL 2.4.0 , libssl was upgraded from version 1.1.1j to 3.0.2

In ProxySQL 2.4.8 , libssl was upgraded from version 3.0.2 to 3.0.8

In ProxySQL 2.5.x , libssl was upgraded from version 3.0.8 to 3.1.0


Do not upgrade without extensive testing.

See note about `struct bio_st` in MySQL_Data_Stream.cpp .

Run `verify-bio_st-match.sh` to confirm compatibility.
