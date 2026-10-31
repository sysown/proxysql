# Replication & shunning test suite (vendored)

Lift-and-shift vendor of `proxysql_repl_tests/` + `infra-docker-hoster/` + `env.sh`
from the private `ProxySQL/jenkins-build-scripts` repo, so CI no longer needs the
cross-org `GH_TOKEN_PROXYSQL` PAT to run these tests.

- `proxysql_repl_tests/` — self-contained bash suite: MySQL replication topology
  (own docker-compose.yml + conf/), `exec_repl_test.sh` (replication),
  `exec_shun_test.sh` (shunning), Debezium CDC checks, data-checksum assertions.
- `infra-docker-hoster/` — docker-hoster (container-hostname DNS) used by the suite.
- `env.sh` — path/config plumbing; CI sets JENKINS_SCRIPTS_PATH to this dir and
  WORKSPACE to the proxysql checkout.

Run by `ci-repltests.yml` / `ci-shuntest.yml` on the GH-Actions branch.
