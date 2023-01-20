# Debug Filters

When ProxySQL is compiled with debug option, debugging information are dumped onto standard error.
Because debugging can be very verbose, in 2.0.13 we introduced debug filters.

The new table created is `debug_filters` , present both in `main` and `disk`.
There is no equivalent `runtime_debug_filters`.

The commands responsible for handling with `debug_levels` are also used for `debug_filters`:
* `(LOAD|SAVE) DEBUG (FROM|TO) (RUNTIME|MEMORY|DISK)`


Table definition:

```
Admin> SHOW CREATE TABLE debug_filters\G
*************************** 1. row ***************************
       table: debug_filters
Create Table: CREATE TABLE debug_filters (
    filename VARCHAR NOT NULL,
    line INT NOT NULL,
    funct VARCHAR NOT NULL,
    PRIMARY KEY (filename, line, funct) )
1 row in set (0.00 sec)
```

Columns:
* `filename`: the source code filename, for example `MySQL_Thread.cpp`
* `line` : the line number in the source file, for example `1234` . `0` means any line.
* `funct` : the function name without parenthesis, for example `run` . Empty value is allowed.

When debug is writing a new debugging entry, if first checks what was loaded at runtime from `debug_filters`.
The debugging information is filtered if:

* an entry for `filename`+`line`+`funct` exists
* an entry for `filename`+`line` exists (empty `funct`)
* an entry for `filename`+`0`+`funct` exists (line `0` means any line in the given `funct`)
* an entry for `filename`+`0` exists (empty `funct`, any line)
