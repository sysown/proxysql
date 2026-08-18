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
  ``-- only-targets: name1 name2``  restrict to these targets

Both target lists are matched with shell-style globs (``fnmatch``), so
``only-targets: proxy_native_*`` selects every native proxy target and a
name with no wildcard character is still an exact match.
  ``-- transactional: false``       parsed for completeness; the shipped
                                    pure-SELECT cases are stateless so it is
                                    not acted on here.

Native backend axis: for AVAILABLE native targets the backend mode is set via
the admin (``pgsql-use_native_backend_protocol``) before running, and the
GLOBAL variable's prior value is snapshotted/restored around the target loop
(see ``_run``) so one case's native-mode toggle never leaks into the next.
Unavailable targets (the norm today -- PR #5882 unmerged) are simply not run;
the test layer surfaces them as skips. ``compare`` therefore gracefully
handles absent targets -- only the proxy targets actually present in
``results`` are checked.
"""
import re
from fnmatch import fnmatchcase

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


def baseline_name(name):
    """The direct target a proxy target must be compared against.

    Single definition shared by the target filter in ``_run`` and the assertion
    in ``compare``: if the two disagreed about which baseline a proxy target
    needs, ``_run`` could omit exactly the target ``compare`` then demands.
    """
    return "direct_binary" if name.endswith("binary") else "direct_text"


def _matches_any(name, patterns):
    # Shell-style globbing, so a documented pattern such as "proxy_native_*"
    # actually selects the native targets. fnmatchcase (not fnmatch) keeps
    # matching case-sensitive and platform-independent; target names are
    # lowercase identifiers, and a plain name with no metacharacter still
    # compares as an exact match.
    return any(fnmatchcase(name, p) for p in patterns)


def _statements(sql):
    # Strip comment lines PER-LINE before the ";"-split. The previous
    # chunk-based filter (`split(";")` then drop chunks starting with "--")
    # silently discarded an ENTIRE case whose first line is a metadata
    # comment: with only one trailing ";" the whole file is a single chunk
    # beginning with "--", so the comment AND the SQL were thrown away
    # together and zero statements ran (a vacuous pass). Known limitations
    # of this simple splitter: no ";" inside string literals, and no
    # trailing "--" comments appended to statement lines.
    body = "\n".join(
        line for line in sql.splitlines()
        if not line.strip().startswith("--")
    )
    return [s.strip() for s in body.split(";") if s.strip()]


def _parse_case_file(case_file):
    with open(case_file) as f:
        sql = f.read()
    # Metadata regexes run on the ORIGINAL text (comment lines included);
    # only statement extraction works on the comment-stripped body.
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
    # Snapshot/restore NATIVE_VAR around the target loop. Dormant today (the
    # variable is absent -- PR #5882 unmerged -- so native_present is False,
    # snapshot() is never called, and this is a pure no-op: zero admin
    # round-trips beyond the native_var_present() probe already required
    # above). The day #5882 merges, native_present flips True and every
    # _run_on() call that toggles a native target's backend-protocol mode
    # (see _run_on) leaves the GLOBAL runtime variable at whatever it last
    # set it to; without restoring it here that value would leak into every
    # subsequent case run in the same process. Restoring in a ``finally``
    # guarantees the global is put back even if a target raises mid-loop.
    saved = admin.snapshot([NATIVE_VAR]) if native_present else None
    try:
        selected = [
            t for t in targets
            if t.available
            and not _matches_any(t.name, skip)
            and (not only or _matches_any(t.name, only))
        ]
        # An only/skip list that selects proxy targets but drops their direct
        # baselines would make compare() report "baseline unavailable" and fail
        # the case no matter how transparent the proxy actually is -- the
        # documented `only-targets: proxy_native_*` names no direct target at
        # all. The baselines are what the assertion is *against*, not part of
        # what is being selected, so pull each selected proxy target's
        # format-matched baseline back in regardless of the filters.
        chosen = {t.name for t in selected}
        needed = {baseline_name(t.name) for t in selected if not t.name.startswith("direct")}
        by_name = {t.name: t for t in targets}
        for name in sorted(needed - chosen):
            t = by_name.get(name)
            if t is not None and t.available:
                selected.append(t)

        results = {}
        for t in selected:
            results[t.name] = _run_on(t, stmts, admin, native_present)
        return results
    finally:
        if saved is not None:
            admin.restore(saved)


def run_case(case_file, targets, admin=None):
    """Run every statement in ``case_file`` against all available targets."""
    stmts, skip, only = _parse_case_file(case_file)
    if not stmts:
        # An empty case must be a LOUD error, never a vacuous pass: with no
        # statements every target returns [] and compare() trivially succeeds.
        raise ValueError(
            f"{case_file}: no executable statements parsed — "
            "check comment/semicolon handling"
        )
    return _run(stmts, targets, admin, skip, only)


def run_case_sql(sql, targets, admin=None):
    """Inline-SQL variant of ``run_case`` (a SQL string, not a file)."""
    skip, only = _parse_meta(sql)
    stmts = _statements(sql)
    if not stmts:
        raise ValueError(
            "inline case: no executable statements parsed — "
            "check comment/semicolon handling"
        )
    return _run(stmts, targets, admin, skip, only)


def compare(results):
    """Every proxy target must equal its format-matched direct baseline.

    Absent targets are handled gracefully: only proxy targets present in
    ``results`` are compared, each against its direct baseline (which is always
    available). Returns ``(ok, detail_text)``.
    """
    diffs = []
    for name in sorted(results):
        if name.startswith("direct"):
            continue
        b_name = baseline_name(name)
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
