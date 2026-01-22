## Coredumper Support

[Coredumper][1] is a library that allows to generate coredumps of a running program, without terminating it.
ProxySQL has builtin support for [coredumper][1] for the following architectures `support x86-32, x86-64, ARM,
and MIPS on Linux`.

This feature is accessed through the [Admin interface][2], via the commands:

- `PROXYSQL COREDUMP $filepath`
- `PROXYSQL COMPRESSEDCOREDUMP $filepath`

Both commands will write a memory dump of ProxySQL into the supplied `filepath`:

```
mysql> PROXYSQL COMPRESSEDCOREDUMP /tmp/proxydump;
```

The `COMPRESSEDCOREDUMP` writes the coredump already compressed as its name suggest.

## Coredump Filters - Development Purposes

ProxySQL also has the ability to trigger coredumps on demand when certain lines of code are hit. This is done
via `coredump_filters`. This feature is mostly used for development purposes, and also to generate debug
builds that can assist with issues investigations.

[1]: https://code.google.com/archive/p/google-coredumper/
[2]: https://proxysql.com/documentation/the-admin-schemas/
