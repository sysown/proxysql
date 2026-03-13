# K8s Auth Plugin

Kubernetes ServiceAccount authentication plugin for ProxySQL.

## Overview

Validates Kubernetes ServiceAccount JWT tokens via the K8s TokenReview API. Clients send their JWT token as the MySQL password.

## Configuration

### Environment Variables

Override in-cluster defaults:

| Variable | Default | Description |
|----------|---------|-------------|
| `K8S_API_SERVER` | `https://kubernetes.default.svc` | K8s API server URL |
| `K8S_CA_PATH` | `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` | Path to CA cert |
| `K8S_TOKEN_PATH` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Path to ProxySQL's SA token |

### ProxySQL Config

```
mysql_variables=
{
    auth_plugins="/path/to/auth_k8s.so"
}
```

### User Setup

```sql
INSERT INTO mysql_users (username, password, attributes, frontend, backend)
VALUES ('k8s-user', '',
        '{"auth_plugin": "k8s", "backend_username": "dbuser"}',
        1, 0);
LOAD MYSQL USERS TO RUNTIME;
```

### Attributes

| Attribute | Required | Description |
|-----------|----------|-------------|
| `auth_plugin` | Yes | Must be `"k8s"` |
| `backend_username` | No | Backend MySQL user to map to |

## Kubernetes RBAC

ProxySQL's ServiceAccount needs `tokenreviews` permission:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: tokenreview
rules:
- apiGroups: ["authentication.k8s.io"]
  resources: ["tokenreviews"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: proxysql-tokenreview
subjects:
- kind: ServiceAccount
  name: proxysql
  namespace: default
roleRef:
  kind: ClusterRole
  name: tokenreview
  apiGroup: rbac.authorization.k8s.io
```

## Building

```bash
cd plugins/MySQL_AuthPlugin/k8s
make
```

## Dependencies

- libcurl (for HTTP requests)
- nlohmann/json (included in ProxySQL deps)
