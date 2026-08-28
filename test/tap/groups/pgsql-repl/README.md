# PostgreSQL Primary-Replica Infra

## Images build

```bash
docker build -t postgres-tc:17 .
```

This step is automatically performed by `docker-compose-init.bash`. Images should be reused between
executions.

## Start / Stop

To start the infra just execute the group startup script:

```bash
pre-proxysql.bash
```

To stop the infra just execute the group shutdown script:

```bash
post-proxysql.bash
```

## Folder structure

* `conf`: Config files for both infra and `ProxySQL`.
* `scripts`: Collection of scripts used to prepare the infra.
