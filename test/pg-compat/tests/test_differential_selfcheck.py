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
from harness import targets, diff

# Must sort before the infra RW-split reader rule (rule_id 101, apply=1).
SELFCHECK_RULE_ID = 90


def test_engine_detects_divergence(admin):
    admin.query(
        "INSERT INTO pgsql_query_rules "
        "(rule_id,active,match_pattern,replace_pattern,re_modifiers,apply) "
        f"VALUES ({SELFCHECK_RULE_ID},1,'SELECT 1 AS canary',"
        "'SELECT 2 AS canary','CASELESS',1)"
    )
    admin.query("LOAD PGSQL QUERY RULES TO RUNTIME")
    try:
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
