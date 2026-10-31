# test/repro

Standalone, self-verifying reproductions for specific issues.

These are **developer-facing tools**, not part of CI. They exist so that a claim
about ProxySQL's behaviour can be re-checked in one command instead of being
re-derived from the source each time. The CI artifacts are the TAP tests; where a
reproduction here has a TAP counterpart, both are listed below.

## Scripts

| Script | Issue | Exits |
|---|---|---|
| `reg_test_5363_admin_monitor_caching_sha2.bash` | [#5363](https://github.com/sysown/proxysql/issues/5363) | `0` fixed · `1` reproduced · `2` environment/baseline broken |
| `reg_test_5985_admin_caching_sha2_full_auth.bash` | [#5985](https://github.com/sysown/proxysql/issues/5985) | `0` behaves as documented · `1` assertion failed · `2` cannot be tested |

`reg_test_5363_*` distinguishes exit `1` (the reported bug reproduced, every
failure tagged `[BUG #5363]`) from exit `2` (the baseline itself failed, so the
run should not be trusted). The TAP counterpart is
`test/tap/tests/reg_test_5363_admin_monitor_caching_sha2-t.cpp` in group
`no-infra-g1`.

`reg_test_5985_*` demonstrates that caching_sha2_password full authentication
completes on the Admin interface against a hashed credential — the behaviour that
issue #5985 ask 2 assumed was broken.

## Running them

```bash
make clean && PROXYSQL31=1 make debug -j"$(nproc)"      # a DEBUG build is required
WORKSPACE=$(pwd) INFRA_ID=dev-$USER test/repro/<script>.bash
```

Both scripts refuse to run against a release build, because the isolated harness
needs debug-only admin commands.

## COLD_START

```text
COLD_START=0   (default) use the existing ProxySQL instance
COLD_START=1   destroy and recreate it first
```

`COLD_START=1` is **destructive**: it stops the ProxySQL container for
`$INFRA_ID` and deletes its persisted `proxysql.db`. Backend infrastructure and
other `INFRA_ID`s are untouched.

It matters for `reg_test_5985_*`. That script proves full authentication happened
by showing a login succeeded while `Client_Connections_sha2cached` was still `0` —
ProxySQL caches the cleartext recovered by a successful full auth and reuses it,
so a warm cache would make a passing login prove nothing. If the cache is already
warm the script exits `2` and tells you to re-run with `COLD_START=1`, rather
than reporting a pass it cannot justify.

`reg_test_5363_*` does not need it: the monitor credential is handled by
`PPHR_5passwordFalse_0()`, which never populates that cache.

## Adding a script

Keep them honest about what they prove:

- Assert the **desired** behaviour, so the script goes green when the bug is
  fixed without being edited.
- Separate "the bug reproduced" from "the environment is wrong" in the exit code.
  A reproduction that cannot tell those apart is worse than none.
- Include a control that fails if the mechanism under test is not the one being
  exercised.
- Restore any global state that was changed, including on failure paths — these
  run against a shared instance.
