# zstd - Zstandard Compression Library

This directory contains the zstd compression library used by ProxySQL for
compressed protocol support in MySQL and PostgreSQL connections.

## Source

- **Project**: https://github.com/facebook/zstd
- **Version**: 1.5.7
- **License**: BSD-3-Clause / GPL-2.0-only (dual licensed)

## Build

The library is built automatically by the ProxySQL build system:

```bash
cd deps/zstd && tar -zxf zstd-1.5.7.tar.gz
cd zstd/zstd/lib && make libzstd.a
```

## Static Linking

zstd is statically linked into ProxySQL to eliminate runtime dependencies
on system libraries. This ensures consistent behavior across different
platforms (Linux, macOS, FreeBSD).

## Usage in ProxySQL

- MySQL compressed protocol (`mysql_compression`)
- PostgreSQL compressed protocol support
- Used by `mysql_data_stream.cpp` and `MySQL_Protocol.cpp`
