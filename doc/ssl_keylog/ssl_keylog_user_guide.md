# SSL/TLS Key Logging - User Guide

## What is SSL/TLS Key Logging?

SSL/TLS key logging is a debugging feature that allows ProxySQL to write TLS encryption secrets to a file. These secrets can be used by network analysis tools like **Wireshark** to decrypt and inspect TLS traffic.

### Why Would You Use This?

This feature is primarily useful for:

- **Debugging TLS connection issues** between clients and ProxySQL
- **Analyzing encrypted traffic** without modifying application code
- **Troubleshooting TLS handshake problems**
- **Performance analysis** of TLS connections
- **Security auditing** of TLS configurations

### Important Security Warning

> **WARNING:** The key log file contains cryptographic secrets that can decrypt ALL TLS traffic. Anyone with access to this file can decrypt your encrypted communications.
>
> **Only enable this feature for debugging purposes.** Disable it in production environments.

---

## Variable Names: Important Distinction

ProxySQL variables belong to **modules**. When referencing a variable from the SQL interface, you must prefix it with the module name.

### SQL Interface (Runtime)

From the ProxySQL admin interface, use the **module prefix**:

```sql
-- Correct: uses admin- prefix for admin module variables
SET admin-ssl_keylog_file = '/var/log/proxysql/sslkeys.txt';

-- Also correct
SET admin-ssl_keylog_file = 'sslkeys.txt';

-- Disable key logging
SET admin-ssl_keylog_file = '';

-- Apply to runtime
LOAD ADMIN VARIABLES TO RUNTIME;
```

### Configuration File

In the configuration file (e.g., `/etc/proxysql.cnf`), variables are grouped by module section:

```ini
# Configuration file format
admin_variables=
{
    admin_credentials="admin:admin"
    mysql_ifaces="0.0.0.0:6032"
    
    # NO prefix needed in config file - already in admin section
    ssl_keylog_file='/var/log/proxysql/sslkeys.txt'
}

mysql_variables=
{
    threads=4
    max_connections=2048
    # ... other mysql variables
}
```

**Key Points:**
- In **SQL commands**: Use `SET admin-ssl_keylog_file = '...'` (with prefix)
- In **config files**: Use `ssl_keylog_file='...'` (no prefix, inside `admin_variables` section)

---

## How to Enable SSL Key Logging

### Method 1: Using SQL Commands (Runtime)

Connect to the ProxySQL admin interface (default port 6032):

```bash
mysql -h 127.0.0.1 -P 6032 -u admin -padmin
```

Then set the variable:

```sql
-- Enable key logging with absolute path
SET admin-ssl_keylog_file = '/var/log/proxysql/sslkeys.txt';

-- Apply to runtime immediately
LOAD ADMIN VARIABLES TO RUNTIME;

-- Verify it's set
SELECT * FROM global_variables WHERE variable_name = 'admin-ssl_keylog_file';
```

### Method 2: Using Configuration File

Edit your ProxySQL configuration file (typically `/etc/proxysql.cnf`):

```ini
admin_variables=
{
    admin_credentials="admin:admin"
    mysql_ifaces="0.0.0.0:6032"
    
    # Add this line
    ssl_keylog_file='/var/log/proxysql/sslkeys.txt'
}
```

Then restart ProxySQL:

```bash
sudo systemctl restart proxysql
# or
sudo service proxysql restart
```

---

## Path Resolution

The `ssl_keylog_file` variable accepts two types of paths:

| Path Type | Format | Example | Resolved To |
|-----------|--------|---------|-------------|
| **Absolute** | Starts with `/` | `/var/log/proxysql/keys.txt` | `/var/log/proxysql/keys.txt` |
| **Relative** | No leading `/` | `sslkeys.txt` | `$DATADIR/sslkeys.txt` |

**Example:**

```sql
-- If ProxySQL data directory is /var/lib/proxysql
SET admin-ssl_keylog_file = 'debug/sslkeys.txt';
-- Resolves to: /var/lib/proxysql/debug/sslkeys.txt
```

---

## Verifying Key Logging

After enabling key logging and generating TLS traffic, verify the key log file:

```bash
# Check if file exists
ls -la /var/log/proxysql/sslkeys.txt

# View contents (should contain secrets!)
cat /var/log/proxysql/sslkeys.txt
```

The file should contain lines like:

```
CLIENT_RANDOM 3a4b5c6d7e8f0123456789abcdef... 48_byte_secret_here...
```

---

## Disabling SSL Key Logging

### Using SQL Commands

```sql
-- Set to empty string to disable
SET admin-ssl_keylog_file = '';

-- Apply to runtime
LOAD ADMIN VARIABLES TO RUNTIME;
```

### Using Configuration File

Remove or comment out the `ssl_keylog_file` line in your config file and restart ProxySQL.

---

## Log Rotation

ProxySQL supports rotating the SSL key log file using the `PROXYSQL FLUSH LOGS` command:

```sql
PROXYSQL FLUSH LOGS;
```

This command:
1. Closes the current key log file
2. Reopens the file for appending

**Note:** The file is reopened in append mode, so existing contents will be preserved. If you want to start with a fresh file, rename/move the old file manually before running `FLUSH LOGS`.

### Manual Log Rotation Example

```bash
# 1. Rename the current key log file
mv /var/log/proxysql/sslkeys.txt /var/log/proxysql/sslkeys.txt.old

# 2. Tell ProxySQL to create a new file
mysql -h 127.0.0.1 -P 6032 -u admin -padmin -e "PROXYSQL FLUSH LOGS;"

# 3. Secure the old file
chmod 600 /var/log/proxysql/sslkeys.txt.old
```

---

## Analyzing TLS Traffic with Key Logs

In production environments, you typically don't run Wireshark directly on the server. Instead, you:

1. Capture traffic to a pcap file using `tcpdump`
2. Copy both the pcap file and key log file to an analysis system
3. Analyze offline using Wireshark (GUI) or tshark (command-line)

### Production Capture Workflow

#### Step 1: Capture Traffic with tcpdump

On the ProxySQL server, capture network traffic to a pcap file:

```bash
# Capture on the interface ProxySQL is listening on (e.g., eth0)
# Replace 6033 with your ProxySQL MySQL port
sudo tcpdump -i eth0 -w /tmp/proxysql_debug.pcap port 6033

# Or capture traffic between specific hosts
sudo tcpdump -i eth0 -w /tmp/proxysql_debug.pcap host client_ip and host proxysql_ip

# Run for a specific duration
sudo timeout 60 tcpdump -i eth0 -w /tmp/proxysql_debug.pcap port 6033
```

**Notes:**
- Use `-i any` to capture on all interfaces if unsure
- The `-w` flag writes to pcap format (binary)
- Capture size is limited by disk space - monitor with `df -h`

#### Step 2: Collect Files for Analysis

Copy both the pcap file and the key log file to your analysis system:

```bash
# On the ProxySQL server
scp /tmp/proxysql_debug.pcap user@analysis-system:/path/to/analysis/
scp /var/log/proxysql/sslkeys.txt user@analysis-system:/path/to/analysis/

# Or archive them together
tar czf proxysql_debug.tar.gz /tmp/proxysql_debug.pcap /var/log/proxysql/sslkeys.txt
```

**Security:** Use secure copy (scp/sftp) and ensure the key log file is transmitted securely, as it contains cryptographic secrets.

#### Step 3: Analyze with Wireshark (GUI)

On your analysis system with Wireshark installed:

1. **Configure TLS key log:**
   - Open Wireshark
   - Go to **Edit → Preferences → Protocols → TLS** (or **SSL** in older versions)
   - Set **"(Pre)-Master-Secret log filename"** to the key log file path

2. **Open the pcap file:**
   - File → Open → Select `proxysql_debug.pcap`
   - Wireshark will decrypt TLS traffic using the key log file

3. **Filter decrypted traffic:**
   ```
   # Show only MySQL packets
   mysql
   
   # Show TLS handshake
   tls.handshake.type == 1
   
   # Show decrypted application data
   tls.app_data
   ```

4. **View decrypted content:**
   - Right-click on a TLS packet → **Follow → TCP Stream**
   - Or right-click → **Follow → TLS Stream** (Wireshark 3.0+)

#### Step 4: Analyze with tshark (Command-Line)

**tshark** is Wireshark's command-line counterpart - useful for servers or headless analysis.

```bash
# Read pcap with TLS decryption using key log file
tshark -r /tmp/proxysql_debug.pcap \
  -o tls.keylog_file:/path/to/sslkeys.txt \
  -Y "tls" \
  -V

# Show only MySQL packets
tshark -r /tmp/proxysql_debug.pcap \
  -o tls.keylog_file:/path/to/sslkeys.txt \
  -Y "mysql"

# Export decrypted TLS payloads to JSON
tshark -r /tmp/proxysql_debug.pcap \
  -o tls.keylog_file:/path/to/sslkeys.txt \
  -T json \
  -Y "tls.app_data" \
  > decrypted.json

# Show summary of decrypted connections
tshark -r /tmp/proxysql_debug.pcap \
  -o tls.keylog_file:/path/to/sslkeys.txt \
  -q -z tls,tree
```

**Common tshark filters for ProxySQL debugging:**

```bash
# Show TLS handshake details
tshark -r proxysql_debug.pcap -o tls.keylog_file:sslkeys.txt -Y "tls.handshake"

# Show all TLS app data (decrypted MySQL queries/responses)
tshark -r proxysql_debug.pcap -o tls.keylog_file:sslkeys.txt -Y "tls.app_data" -V

# Convert to readable text format
tshark -r proxysql_debug.pcap -o tls.keylog_file:sslkeys.txt -T fields \
  -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
  -e tls.app_data.data

# Statistics: TLS sessions by cipher suite
tshark -r proxysql_debug.pcap -o tls.keylog_file:sslkeys.txt -q -z tls,ctext
```

### Alternative: Live Capture with tshark

If you need to monitor traffic in real-time (not recommended for production debugging):

```bash
# Live capture with TLS decryption
sudo tshark -i eth0 -f "port 6033" \
  -o tls.keylog_file:/var/log/proxysql/sslkeys.txt \
  -Y "tls.app_data" \
  -V
```

**Note:** This still requires running on the ProxySQL server. For production, prefer the tcpdump → offline analysis workflow.

---

## Configuration File Reference

### Sample Configuration with Key Logging

```ini
# /etc/proxysql.cnf

datadir="/var/lib/proxysql"

admin_variables=
{
    admin_credentials="admin:admin"
    mysql_ifaces="0.0.0.0:6032"
    
    # Enable SSL key logging for debugging
    ssl_keylog_file='/var/log/proxysql/sslkeys.txt'
}

mysql_variables=
{
    threads=4
    max_connections=2048
    interfaces="0.0.0.0:6033"
    default_schema="information_schema"
    # ... other mysql variables
}
```

---

## Troubleshooting

### Variable Not Found Error

**Problem:** `ERROR 1045 (28000): Unknown variable 'admin-ssl_keylog_file'`

**Solution:** 
- Make sure you're connected to the admin interface (port 6032, not 6033)
- Check that you're using the correct prefix: `admin-ssl_keylog_file`

### File Not Created

**Problem:** The key log file is not being created.

**Solutions:**
1. Check that the directory exists and is writable:
   ```bash
   ls -la /var/log/proxysql
   ```
2. Check ProxySQL error logs for permission errors
3. Verify the variable is set:
   ```sql
   SELECT * FROM global_variables WHERE variable_name = 'admin-ssl_keylog_file';
   ```

### No Secrets in File

**Problem:** File exists but is empty or has no secrets.

**Solutions:**
1. Verify TLS is actually being used:
   ```sql
   -- Check if connections are using TLS
   SELECT * FROM stats_mysql_connection_pool;
   ```
2. Make sure clients are connecting with SSL/TLS
3. Check that `admin-ssl_keylog_file` is loaded into runtime:
   ```sql
   LOAD ADMIN VARIABLES TO RUNTIME;
   ```

### tcpdump Permission Denied

**Problem:** `tcpdump: snaplen: ioctl: Permission denied`

**Solution:** Run tcpdump with sudo:
```bash
sudo tcpdump -i eth0 -w /tmp/capture.pcap port 6033
```

---

## Best Practices

### Security

1. **Never enable in production** unless actively debugging
2. **Set restrictive file permissions:**
   ```bash
   chmod 600 /var/log/proxysql/sslkeys.txt
   chown proxysql:proxysql /var/log/proxysql/sslkeys.txt
   ```
3. **Securely delete old key log files:**
   ```bash
   shred -u /var/log/proxysql/sslkeys.txt.old
   ```
4. **Monitor file size** - key log files can grow quickly

### Operational

1. **Use absolute paths** to avoid confusion
2. **Document when key logging is enabled** for audit purposes
3. **Rotate regularly** during long debugging sessions
4. **Disable immediately after** debugging is complete
5. **Use tcpdump for production captures** - don't run Wireshark on production servers

---

## Quick Reference

| Context | Variable Name | Example |
|---------|---------------|---------|
| **SQL commands** | `admin-ssl_keylog_file` | `SET admin-ssl_keylog_file = '/path/file.txt';` |
| **Config file** | `ssl_keylog_file` | `ssl_keylog_file='/path/file.txt'` (in `admin_variables` section) |

| Command | Description |
|---------|-------------|
| `SET admin-ssl_keylog_file = '/path/to/file.txt';` | Enable key logging |
| `SET admin-ssl_keylog_file = '';` | Disable key logging |
| `LOAD ADMIN VARIABLES TO RUNTIME;` | Apply changes |
| `PROXYSQL FLUSH LOGS;` | Rotate key log file |
| `SELECT * FROM global_variables WHERE variable_name = 'admin-ssl_keylog_file';` | Check current setting |

| Tool | Use Case |
|------|----------|
| `tcpdump` | Capture traffic to pcap file (production) |
| `tshark` | Analyze pcap files with key log (command-line) |
| `Wireshark` | Analyze pcap files with key log (GUI) |

---

## Additional Resources

- **Developer Documentation:** See `ssl_keylog_developer_guide.md` for implementation details
- **NSS Key Log Format:** https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
- **Wireshark TLS Decryption:** https://wiki.wireshark.org/TLS
- **tshark Manual:** `man tshark` or https://www.wireshark.org/docs/man-pages/tshark.html
- **ProxySQL Configuration:** https://github.com/sysown/proxysql/wiki
