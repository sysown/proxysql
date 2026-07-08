"""The differential engine.

Runs the same SQL statements against several targets (see harness.targets)
and asserts that every proxy target is byte-for-byte indistinguishable from
its FORMAT-MATCHED direct baseline: same status tag, same column names, same
type OIDs, same row values. ``compare`` returns ``(ok, detail_text)``.

Format-matched: a ``*_binary`` proxy target is compared only against
``direct_binary`` and a ``*_text`` proxy target only against ``direct_text``.
This is deliberate -- psycopg decodes text and binary wire formats through
different code paths, so a proxy-vs-direct comparison is only apples-to-apples
within the same result format.

Case metadata (parsed from ``-- key: value`` comment lines):
  ``-- skip-targets: name1 name2``  targets to exclude
  ``-- only-targets: name1 name2``  restrict to exactly these targets
  ``-- transactional: false``       parsed for completeness; the shipped
                                    pure-SELECT cases are stateless so it is
                                    not acted on here.

Native backend axis: for AVAILABLE native targets the backend mode is set via
the admin (``pgsql-use_native_backend_protocol``) before running. Unavailable
targets (the norm today -- PR #5882 unmerged) are simply not run; the test
layer surfaces them as skips. ``compare`` therefore gracefully handles absent
targets -- only the proxy targets actually present in ``results`` are checked.
"""
import re

import psycopg

from harness.targets import NATIVE_VAR, native_var_present


def _parse_meta(sql):
    skip = set()
    for m in re.findall(r"--\s*skip-targets:\s*(.+)", sql):
        skip.update(m.split())
    only = set()
    for m in re.findall(r"--\s*only-targets:\s*(.+)", sql):
        only.update(m.split())
    return skip, only


def _statements(sql):
    return [
        s.strip()
        for s in sql.split(";")
        if s.strip() and not s.strip().startswith("--")
    ]


def _parse_case_file(case_file):
    with open(case_file) as f:
        sql = f.read()
    skip, only = _parse_meta(sql)
    return _statements(sql), skip, only


def _run_on(target, stmts, admin, native_present):
    # Toggle the backend-protocol mode ONLY when the variable exists and the
    # target participates in that axis (native_backend is not None). With the
    # variable absent (today), native targets are unavailable and never reach
    # here, and libpq/direct targets need no toggle (libpq is the only mode).
    if native_present and target.native_backend is not None:
        admin.set_var(NATIVE_VAR, bool(target.native_backend))
        admin.load_vars()

    out = []
    with psycopg.connect(target.dsn, autocommit=True) as conn:
        for s in stmts:
            with conn.cursor(binary=target.binary) as cur:
                cur.execute(s)
                cols = [(d.name, d.type_code) for d in (cur.description or [])]
                rows = cur.fetchall() if cur.description else None
                out.append((cur.statusmessage, cols, rows))
    return out


def _run(stmts, targets, admin, skip, only):
    native_present = native_var_present(admin) if admin is not None else False
    results = {}
    for t in targets:
        if not t.available:
            continue
        if t.name in skip:
            continue
        if only and t.name not in only:
            continue
        results[t.name] = _run_on(t, stmts, admin, native_present)
    return results


def run_case(case_file, targets, admin=None):
    """Run every statement in ``case_file`` against all available targets."""
    stmts, skip, only = _parse_case_file(case_file)
    return _run(stmts, targets, admin, skip, only)


def run_case_sql(sql, targets, admin=None):
    """Inline-SQL variant of ``run_case`` (a SQL string, not a file)."""
    skip, only = _parse_meta(sql)
    return _run(_statements(sql), targets, admin, skip, only)


def compare(results):
    """Every proxy target must equal its format-matched direct baseline.

    Absent targets are handled gracefully: only proxy targets present in
    ``results`` are compared, each against its direct baseline (which is always
    available). Returns ``(ok, detail_text)``.
    """
    def base(name):
        return "direct_binary" if name.endswith("binary") else "direct_text"

    diffs = []
    for name in sorted(results):
        if name.startswith("direct"):
            continue
        b_name = base(name)
        b = results.get(b_name)
        if b is None:
            diffs.append(f"{name}: format-matched baseline {b_name} unavailable")
            continue
        res = results[name]
        if res != b:
            diffs.append(
                f"{name} != {b_name}\n  got:  {res}\n  base: {b}"
            )
    return (not diffs, "\n".join(diffs))
