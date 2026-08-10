# Cluster Simulator Optional Comment Design

## Problem

The cluster simulator accepts `comment` in `proxysql_init_state` and
`proxysql_final_state`, but it currently turns an omitted comment into an empty
string and compares that string exactly. This differs from the documented
four-field expected-state shape and from the wildcard behavior already used
for omitted `weight`, `max_connections`, and `use_ssl` values.

The `cluster_sim_galera-g1` failure in GitHub Actions exposed the mismatch.
The initial runtime transition retained non-empty comments for only some
servers. All visible expected and actual fields matched, but the hidden comment
values caused `check_cluster_status()` to fail. The diagnostic JSON also
discarded comments, so the failure did not identify the differing field.

PR #6017 does not modify the cluster simulator or its Galera wrapper. The fix
therefore belongs in a dedicated PR based on `v3.0`.

## Contract

- `hostgroup_id`, `hostname`, `port`, and `status` remain required expected
  state fields.
- Omitted `weight`, `max_connections`, `use_ssl`, and `comment` fields are
  wildcards.
- An explicitly supplied comment, including `""`, is compared exactly.
- Runtime rows always have a specified comment because the value is selected
  from `runtime_mysql_servers`.
- Diagnostic and simulation JSON include a comment whenever the corresponding
  state carries an explicitly specified comment.
- Checksums remain diagnostic. Their existing inputs and meaning do not change.

## Representation

Extend `server_status` with a boolean recording whether `comment` was present
in the source JSON. This preserves the distinction between an omitted comment
and an explicitly empty comment without requiring C++17 `std::optional`; the
project can still compile in its C++11 fallback mode.

`extract_cluster_status()` sets the flag from `contains("comment")`.
`matching_server_status()` compares comment values only when the expected
flag is true. `cluster_status_to_json()` emits the comment only when the flag
is true.

## Testing

Add focused TAP unit coverage for the shared comparator and JSON projection:

- omitted expected comment matches a non-empty actual comment;
- explicit matching comments pass;
- explicit different comments fail;
- explicitly empty expected comment does not match a non-empty actual comment;
- JSON omits an unspecified comment and emits a specified one.

Run the focused test before implementation to capture the intended failure,
then after implementation for GREEN. Build the cluster simulator and run the
Galera simulator group in isolated infrastructure. Also run shared-comparator
coverage for another simulator family to guard against cross-family regressions.

## Non-goals

- Do not change ProxySQL runtime comment propagation.
- Do not add sleeps or hardcode infrastructure-specific comments.
- Do not change PR #6017 or its pending RSA authentication work.
- Do not redefine the cluster-state checksum as semantic equality.
