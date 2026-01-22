# PROXY Protocol Support in ProxySQL

ProxySQL supports the PROXY protocol, which enables the preservation of original client connection information
when traffic passes through proxies, load balancers, or TCP intermediaries. This is essential for accurate
logging, security, and auditing purposes.

## Overview

The PROXY protocol is a network protocol that carries connection information (client IP address, source port,
etc.) through proxy systems. When a client connects to ProxySQL through a load balancer or proxy that supports
the PROXY protocol, ProxySQL can extract the original client information and use it for logging, security
checks, and routing decisions.

### Why Use PROXY Protocol?

-   **Accurate Logging**: Preserve real client IP addresses instead of proxy IP addresses
-   **Security**: Apply security rules based on actual client locations
-   **Auditing**: Maintain complete audit trails with original client information
-   **Compliance**: Meet regulatory requirements for client identification

## PROXY Protocol Versions

ProxySQL supports **PROXY protocol version 1** with the following address families:

-   **TCP4**: IPv4 connections
-   **TCP6**: IPv6 connections

### PROXY Header Format (Version 1)

```
PROXY TCP4 255.255.255.255 192.168.1.1 12345 3306\r\n
PROXY TCP6 ::ffff:255.255.255.255 ::ffff:192.168.1.1 12345 3306\r\n
```

PROXY protocol v1 header structure:

-   `PROXY`: Protocol signature
-   `TCP4/TCP6`: Address family
-   `client_address`: Original client IP address
-   `proxy_address`: Proxy/load balancer IP address
-   `client_port`: Original client port
-   `proxy_port`: Proxy/load balancer port
-   `\r\n`: Protocol termination

## Configuration

### mysql-proxy_protocol_networks Variable

The `mysql-proxy_protocol_networks` variable controls which networks are allowed to send PROXY protocol
headers. This is a critical security feature that prevents malicious clients from spoofing client information.

**Syntax:**

```sql
SET mysql-proxy_protocol_networks = 'network_list';
LOAD MYSQL VARIABLES TO RUNTIME;
```

**Network List Format:**

-   Empty string `''`: Disable PROXY protocol (default)
-   Asterisk `'*'`: Accept PROXY headers from any network
-   Comma-separated CIDR notation: `'192.168.1.0/24,10.0.0.0/8'`
-   IPv4 and IPv6 subnets supported

**Configuration Examples:**

```sql
-- Disable PROXY protocol (default, most secure)
SET mysql-proxy_protocol_networks = '';
LOAD MYSQL VARIABLES TO RUNTIME;

-- Accept from any network (least secure)
SET mysql-proxy_protocol_networks = '*';
LOAD MYSQL VARIABLES TO RUNTIME;

-- Accept from specific IPv4 networks
SET mysql-proxy_protocol_networks = '192.168.1.0/24,10.0.0.0/8,172.16.0.0/12';
LOAD MYSQL VARIABLES TO RUNTIME;

-- Accept from specific IPv6 networks
SET mysql-proxy_protocol_networks = '2001:db8::/32,fe80::/10';
LOAD MYSQL VARIABLES TO RUNTIME;

-- Mixed IPv4 and IPv6 networks
SET mysql-proxy_protocol_networks = '192.168.1.0/24,2001:db8::/32';
LOAD MYSQL VARIABLES TO RUNTIME;
```

**Security Best Practices:**

-   Always specify specific networks instead of using `'*'`
-   List only trusted proxy/load balancer IP ranges
-   Regularly review and update network lists
-   Use the smallest possible subnets for security

## Integration with Load Balancers

### HAProxy Configuration

```haproxy
frontend mysql_frontend
    bind *:3306
    mode tcp
    option tcplog
    default_backend mysql_servers

backend mysql_servers
    mode tcp
    balance roundrobin
    server proxysql1 10.0.1.100:6033 check
    server proxysql2 10.0.1.101:6033 check
    option tcp-check
    send-proxy
```

### AWS Network Load Balancer

AWS NLB supports PROXY protocol, but ProxySQL only supports PROXY protocol v1. Configure NLB to use PROXY
protocol v1:

```bash
# Note: AWS NLB defaults to PROXY protocol v2, but ProxySQL only supports v1
# You may need to use a TCP proxy like HAProxy in front of ProxySQL
# or configure the NLB target group appropriately
```

## Information Preservation

When PROXY protocol headers are successfully processed, ProxySQL preserves the following information:

### Client Information (Available for Logging)

-   **Original client IP address**: The real client's IP, not the proxy's IP
-   **Original client port**: The client's source port
-   **Connection metadata**: Timestamp and connection details

### Proxy Information

-   **Proxy IP address**: The load balancer or proxy IP
-   **Proxy port**: The proxy's listening port
-   **Protocol version**: PROXY v1 details

### PROXY Protocol Information Access

PROXY protocol information is available through ProxySQL's administrative interfaces when
`mysql-show_processlist_extended` is enabled:

```sql
-- Enable extended processlist information
SET mysql-show_processlist_extended = 1;
LOAD MYSQL VARIABLES TO RUNTIME;

-- Query PROXY protocol information
SELECT ThreadID, user, cli_host, extended_info FROM stats_mysql_processlist WHERE extended_info IS NOT NULL;
```

## Troubleshooting

### Common Issues

#### 1. PROXY Headers Not Accepted

**Problem**: Connections with PROXY headers are rejected **Solution**: Verify `mysql-proxy_protocol_networks`
includes the proxy's IP address

```sql
SHOW VARIABLES LIKE 'proxy_protocol_networks';
```

#### 2. Invalid PROXY Header Format

**Problem**: PROXY headers are malformed and rejected **Solution**: Ensure your load balancer sends properly
formatted PROXY v1 headers

#### 3. Connection Timeouts

**Problem**: Connections timeout when PROXY protocol is enabled **Solution**: Check network connectivity
between proxy and ProxySQL

### Debug Information

Enable detailed logging for PROXY protocol debugging:

```sql
-- Check current PROXY configuration
SHOW VARIABLES LIKE 'proxy_protocol_networks';

-- Monitor connection attempts
SELECT * FROM stats_mysql_connection_pool;
```

### Testing PROXY Protocol

Use netcat to test PROXY protocol headers:

```bash
# Test with PROXY header
echo -e "PROXY TCP4 192.168.1.100 10.0.1.50 54321 3306\r\nSELECT 1" | nc proxysql_server 6033

# Test without PROXY header
echo "SELECT 1" | nc proxysql_server 6033
```

### Performance Considerations

-   **Minimal Overhead**: PROXY protocol processing adds negligible latency
-   **Memory Usage**: Small memory footprint for PROXY information storage
-   **Network Impact**: PROXY headers add approximately 100 bytes per connection

## Security Considerations

### Critical Security Rules

1. **Network Whitelisting**: Always specify trusted networks in `mysql-proxy_protocol_networks`
2. **Never Use Wildcards**: Avoid using `'*'` in production environments
3. **Regular Audits**: Review network configurations periodically
4. **Monitoring**: Monitor for unexpected connection patterns

### Protection Against Spoofing

The `mysql-proxy_protocol_networks` variable prevents clients from directly sending PROXY headers with spoofed
information. Only connections from the specified networks are allowed to include PROXY protocol data.

### Logging and Auditing

PROXY protocol information appears in:

-   Connection logs with real client IPs
-   JSON exports with complete connection metadata
-   Statistics and monitoring data
-   Audit trails for compliance requirements

## Use Case Examples

### 1. Web Application with Load Balancer

```sql
-- Web application behind load balancer
SET mysql-proxy_protocol_networks = '10.0.0.0/8';  -- Load balancer network
LOAD MYSQL VARIABLES TO RUNTIME;
```

Benefits:

-   Accurate client IP logging for security analysis
-   Geolocation-based content delivery
-   Compliance with data protection regulations

### 2. Multi-Tenant SaaS Platform

```sql
-- Multiple load balancers in different regions
SET mysql-proxy_protocol_networks = '10.0.1.0/24,10.0.2.0/24,10.0.3.0/24';
LOAD MYSQL VARIABLES TO RUNTIME;
```

Benefits:

-   Per-tenant security policies based on client location
-   Regional compliance and data residency requirements
-   Accurate billing and usage tracking

### 3. High-Availability Database Cluster

```sql
-- HAProxy with health checks and failover
SET mysql-proxy_protocol_networks = '192.168.100.0/24';
LOAD MYSQL VARIABLES TO RUNTIME;
```

Benefits:

-   Client session persistence across failover events
-   Accurate connection tracking and monitoring
-   Simplified debugging of connection issues

## Compatibility

### Supported Load Balancers

-   **HAProxy**: Full PROXY protocol v1 support
-   **AWS Network Load Balancer**: PROXY protocol v1 (requires additional configuration)
-   **NGINX**: PROXY protocol support with proper configuration
-   **Envoy Proxy**: PROXY protocol support

### Backend Database Compatibility

The PROXY protocol functionality is handled entirely by ProxySQL at the connection layer, so the backend
database version (MySQL, MariaDB, Percona Server) does not affect PROXY protocol support. All database
versions work transparently with PROXY protocol enabled connections.

## Related Variables

-   `mysql-proxy_protocol_networks`: Networks allowed to send PROXY headers (this page)
-   `mysql-use_tcp_keepalive`: Enable TCP keepalive for connections (critical for load balancer environments)
-   `mysql-tcp_keepalive_time`: TCP keepalive timeout interval (configure to match load balancer timeouts)

**Important Note:** Load balancers often close idle connections, so it's critical to enable TCP keepalive and
configure `mysql-tcp_keepalive_time` with an appropriate value to prevent connection drops. Recommended
settings depend on your load balancer's timeout configuration.
