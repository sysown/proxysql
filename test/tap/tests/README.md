## Warning Count Logging in ProxySQL TAP Tests

With the exception of a few, all TAP tests are now geared up to log warning count and the query that triggered the warning during its execution.

## Working

The method for extracting both the warning count and the associated query in all TAP tests involves overriding of specific APIs of MariaDB client library. This method facilitates the seamless extraction of both the warning count and the query.

## Default Settings

By default, the logging of both the warning count and the associated query is activated for all TAP tests.

However, there are specific tests where logging is intentionally disabled. If needed, you have the flexibility to disable the logging by defining the preprocessor directive 'DISABLE_WARNING_COUNT_LOGGING'.
