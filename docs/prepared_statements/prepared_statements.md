## Routing metadata changes in v2.1.0

From 1.3.0 till 2.0.x, if a prepared statement is prepared on a specific hostgroup,
it will always be executed on that same hostgroup. This behavior isn't ideal, because
it can cause queries to be executed in an unexpected hostgroup, simply because they were
initially prepared there.

```
NOTE: A concrete example of this, could be a specific statement that was prepared for a `reader
hostgroup`, and that is executed inside the `reader hostgroup` besides of being executed inside
of a transaction, because it was prepared for being executed there.
```

This behavior was changed in *v2.1.0*, since this version ProxySQL doesn't cache routing metadata for
prepared statements, and the routing is always evaluated again during COM_STMT_EXECUTE.

Original implementation shipped in *v2.1.0* had some flaws, which prevented the feature to
fully work as intended, these issues has been solved for *v2.2.0*.

One of these changes present in v2.2.0 is the inclusion of 'first_comment' in the computing
of the routing for 'COM_STMT_EXECUTE', so statements that were specifically asked to be
routed to a particular hostgroup through `hostgroup` query annotation will properly
be routed to that requested hostgroup during 'COM_STMT_EXECUTE'.

_Since the new release v2.2.0 this behavior should be fully functional, and statements should be
properly routed to the same hostgroup no matter if being 'prepared' or 'executed'_

### Technical details

From 1.3.0 till 2.0.x, when COM_STMT_PREPARE is executed and Query Processor is executed,
metadata are stored in MySQL_STMT_Global_info(). These metadata include routing information.
So when a prepared statement is prepared on a specific hostgroup, it will always be executed
on the same hostgroup.

Since v2.1.0 ProxySQL no longer caches this information, and instead re-computes it during
'COM_STMT_EXECUTE', this ways proper routing is always ensured.
