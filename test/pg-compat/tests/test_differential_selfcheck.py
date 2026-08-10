"""Self-check: prove the differential engine actually DETECTS divergence.

A test oracle that can never fail is worthless. This installs a ProxySQL
query rule that rewrites the canary ``SELECT 1 AS canary`` into
``SELECT 2 AS canary`` ON THE PROXY PATH ONLY, so the proxy targets return a
row that differs from every direct backend. The engine MUST then report
``compare(...) -> not ok``. The rule is always removed in ``finally``.

Why a rewrite (replace_pattern) and not the brief's literal rule, and not an
error_msg rule -- verified live against the sdd-sp2 admin:

  * The brief's ``INSERT ... (match_digest, replace_pattern, ...)`` violates a
    ProxySQL CHECK constraint:
        CASE WHEN replace_pattern IS NULL THEN 1
             WHEN replace_pattern IS NOT NULL AND match_pattern IS NOT NULL
             THEN 1 ELSE 0 END
    i.e. a ``replace_pattern`` REQUIRES a ``match_pattern``. So we match on
    ``match_pattern`` (raw query text) instead of ``match_digest``.

  * The infra ships RW-split rules ``rule_id=1`` (``^SELECT.*FOR UPDATE``) and
    ``rule_id=101`` (``^SELECT``), both ``apply=1``. Rules evaluate in
    ascending ``rule_id``; the first ``apply=1`` match STOPS processing. So a
    high rule_id (e.g. the brief's 990001) never runs for a SELECT -- the
    reader rule at 101 fires first. The self-check rule must therefore sort
    BEFORE 101; we use ``rule_id=90``.

  * ``replace_pattern`` is preferred over ``error_msg`` because the rewrite
    keeps BOTH the proxy and direct executions succeeding, so ``compare``
    exercises its real status/column/OID/row comparison. An ``error_msg`` rule
    would make the proxy raise, aborting the run before ``compare`` is reached.

Live evidence (psql through the proxy) with rule 90 installed:
    SELECT 1 AS canary  ->  2      (rewritten)
and removed:
    SELECT 1 AS canary  ->  1
"""
import glob
import os

from harness import targets, diff

# Must sort before the infra RW-split reader rule (rule_id 101, apply=1).
SELFCHECK_RULE_ID = 90

CASES_DIR = os.path.join(os.path.dirname(__file__), "..", "cases")


def test_engine_detects_divergence(admin):
    try:
        # INSERT + LOAD inside the try so the finally ALWAYS deletes rule 90
        # and reloads, even if either setup statement fails partway (deleting
        # a rule that was never inserted is harmless).
        admin.query(
            "INSERT INTO pgsql_query_rules "
            "(rule_id,active,match_pattern,replace_pattern,re_modifiers,apply) "
            f"VALUES ({SELFCHECK_RULE_ID},1,'SELECT 1 AS canary',"
            "'SELECT 2 AS canary','CASELESS',1)"
        )
        admin.query("LOAD PGSQL QUERY RULES TO RUNTIME")
        tgts = targets.all_targets(admin)
        results = diff.run_case_sql("SELECT 1 AS canary", tgts, admin)
        ok, detail = diff.compare(results)
        assert not ok, (
            "differential engine FAILED to detect an injected rewrite "
            f"divergence; results={results}"
        )
    finally:
        admin.query(
            f"DELETE FROM pgsql_query_rules WHERE rule_id={SELFCHECK_RULE_ID}"
        )
        admin.query("LOAD PGSQL QUERY RULES TO RUNTIME")


def test_target_filter_supports_globs():
    """``only-targets``/``skip-targets`` are documented as glob patterns.

    They were matched with exact set membership, so a documented pattern such
    as ``only-targets: proxy_native_*`` matched nothing and silently skipped
    EVERY target -- a case that appears to pass while running no targets at
    all. Needs no infra: this pins the matcher itself.
    """
    assert diff._matches_any("proxy_native_binary", ["proxy_native_*"])
    assert diff._matches_any("proxy_native_text", ["proxy_native_*"])
    assert not diff._matches_any("proxy_libpq_text", ["proxy_native_*"])

    # A plain name with no metacharacter must still be an exact match.
    assert diff._matches_any("direct_text", ["direct_text"])
    assert not diff._matches_any("direct_text", ["direct_tex"])
    assert not diff._matches_any("direct_text", [])


def test_baseline_is_never_filtered_out():
    """A target filter must not drop the baseline the assertion needs.

    ``compare()`` checks each proxy target against its format-matched direct
    baseline and reports "baseline unavailable" when it is missing. Since
    ``only-targets``/``skip-targets`` name proxy targets (the documented
    example is ``proxy_native_*``), a filter applied naively removes both
    direct targets and the case then fails no matter how transparent the
    proxy is. Needs no infra: this pins the pairing rule itself.
    """
    assert diff.baseline_name("proxy_native_binary") == "direct_binary"
    assert diff.baseline_name("proxy_libpq_binary") == "direct_binary"
    assert diff.baseline_name("proxy_native_text") == "direct_text"
    assert diff.baseline_name("proxy_libpq_text") == "direct_text"


def test_file_pipeline_executes_real_statements(admin):
    """Guard against vacuous passes on the FILE-based path.

    Review of the first Task 6 iteration found ``_statements()`` discarded an
    entire case file whose first line was a metadata comment (one trailing
    ``;`` -> one chunk starting with ``--``), so ``run_case`` executed ZERO
    statements, every target returned ``[]``, and ``compare`` passed on
    ``[] == []``. The inline-SQL divergence self-check above could not catch
    that (no leading comment in its SQL). This test permanently pins the
    file-parsing pipeline: every shipped case file must parse to at least one
    statement, and running a real case file end-to-end must yield, for EVERY
    available target, a non-empty result list whose statements each returned
    at least one row (the shipped cases are pure single-row SELECTs).
    """
    case_files = sorted(glob.glob(os.path.join(CASES_DIR, "*.sql")))
    assert case_files, f"no case files found under {CASES_DIR}"

    # Every shipped case must parse to >= 1 executable statement.
    for cf in case_files:
        stmts, _, _ = diff._parse_case_file(cf)
        assert stmts, f"{os.path.basename(cf)} parsed to zero statements"

    # And a real file run must produce real, non-empty results per target.
    tgts = targets.all_targets(admin)
    results = diff.run_case(case_files[0], tgts, admin)
    available = [t.name for t in tgts if t.available]
    assert sorted(results) == sorted(available), (
        f"expected results for every available target {available}, "
        f"got {sorted(results)}"
    )
    for name, res in results.items():
        assert res, f"{name}: empty result list — no statement executed"
        for status, cols, rows in res:
            assert cols, f"{name}: statement returned no columns ({status})"
            assert rows, f"{name}: statement returned no rows ({status})"
