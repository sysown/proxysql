"""Differential transparency: ProxySQL must be indistinguishable from direct PG.

Each ``cases/*.sql`` file is run against every available target and compared
against its format-matched direct baseline (see harness.diff.compare).

The two native-backend targets are unavailable while PR #5882 is unmerged.
``test_target_available`` surfaces them as explicit, reasoned pytest SKIPS
(visible in ``-v`` output) rather than silently omitting them -- and they
flip to PASS automatically once the backend variable exists, with no change
to this file.
"""
import glob
import os

import pytest

from harness import targets, diff

HERE = os.path.dirname(__file__)
CASE_FILES = sorted(glob.glob(os.path.join(HERE, "..", "cases", "*.sql")))
CASE_IDS = [os.path.basename(f) for f in CASE_FILES]

# Stable names of the full 6-target matrix (import-time safe: no admin conn).
TARGET_NAMES = [
    "proxy_libpq_text",
    "proxy_libpq_binary",
    "proxy_native_text",
    "proxy_native_binary",
    "direct_text",
    "direct_binary",
]


@pytest.mark.parametrize("case_file", CASE_FILES, ids=CASE_IDS)
def test_case_is_transparent(admin, case_file):
    tgts = targets.all_targets(admin)
    results = diff.run_case(case_file, tgts, admin)
    ok, detail = diff.compare(results)
    assert ok, f"{os.path.basename(case_file)} diverged:\n{detail}"


@pytest.mark.parametrize("target_name", TARGET_NAMES)
def test_target_available(admin, target_name):
    """One item per target; unavailable ones are skipped WITH their reason."""
    by_name = {t.name: t for t in targets.all_targets(admin)}
    t = by_name[target_name]
    if not t.available:
        pytest.skip(t.skip_reason)
