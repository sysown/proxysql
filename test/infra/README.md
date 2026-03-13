# ProxySQL Unified CI Infrastructure

This directory contains the self-contained infrastructure configurations and control scripts for the ProxySQL **Unified CI System**. It enables high-concurrency, isolated test environments using **Docker-outside-of-Docker (DooD)** and **Pure Network Isolation**.
## 0. Pre-requirement: Building the CI Base Image

The ProxySQL control plane and test runner use a standardized toolbelt image: `proxysql-ci-base:latest`. This image must be built locally before starting any infrastructure:

```bash
cd test/infra/docker-base
docker build --network host -t proxysql-ci-base:latest .
cd ../../../
```

**Note:** Using `--network host` is recommended if you encounter DNS resolution hangs during the build process.

