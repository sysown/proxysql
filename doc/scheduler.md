# Scheduler

Scheduler is a feature introduced in v1.2.0h.

Scheduler is a cron-like implementation integrated inside ProxySQL with millisecond granularity. It is possible to be configured only though the Admin interface: configuration from config file is not supported yet.

The current implementation is suppsted by two tables:
```sql
Admin> SHOW TABLES LIKE '%scheduler%';
+-------------------+
| tables            |
+-------------------+
| scheduler         |
| runtime_scheduler |
+-------------------+
2 rows in set (0.00 sec)
```

To enter into details:
* table `scheduler` is where the scheduler can be configured
* table `runtime_scheduler` is the runtime representation (read only) of the scheduler

Table `scheduler` has the following structure:

```sql
Admin> SHOW CREATE TABLE scheduler\G
*************************** 1. row ***************************
       table: scheduler
Create Table: CREATE TABLE scheduler (
id INTEGER NOT NULL,
interval_ms INTEGER CHECK (interval_ms>=100 AND interval_ms<=100000000) NOT NULL,
filename VARCHAR NOT NULL,
arg1 VARCHAR,
arg2 VARCHAR,
arg3 VARCHAR,
arg4 VARCHAR,
arg5 VARCHAR,
PRIMARY KEY(id))
1 row in set (0.00 sec)
```

In details:
* `id` : unique identifier of the scheduler job
* `interval_ms` : how often (in millisecond) the job will be started. Minimum interval_ms is 100 milliseconds
* `filename` : full path of the executable to be executed
* `arg1` to `arg5` : arguments (maximum 5) that can be passed to the job

As for the rest of configuration tables in ProxySQL, after editing the data in this table, configuration needs to be loaded at runtime to be effective, and saved to disk to be persistent.
For this reason ProxySQL has new commands to support Scheduler:
* `LOAD SCHEDULER TO RUNTIME` and `LOAD SCHEDULER FROM MEMORY` : load the configuration from `main`.`scheduler` to runtime, and becomes effective;
* `LOAD SCHEDULER TO MEMORY` and `LOAD SCHEDULER FROM DISK` : load the configuration from `disk`.`scheduler` to `main`.`scheduler`;
* `SAVE SCHEDULER FROM RUNTIME` and `SAVE SCHEDULER TO MEMORY` : save the configuration from runtime to `main`.`scheduler`;
* `SAVE SCHEDULER FROM MEMORY` and `SAVE SCHEDULER TO DISK` : save the configuration from `main`.`scheduler` to `disk`.`scheduler`, and becomes persistent across restart.

The scheduler is implemented calling `fork()` and then `excve()`. If `execve()` fails, the error is reported into error log.
