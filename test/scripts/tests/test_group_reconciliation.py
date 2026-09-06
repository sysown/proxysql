import sys
import unittest
from pathlib import Path


LIB_DIR = Path(__file__).resolve().parents[1] / "lib"
sys.path.insert(0, str(LIB_DIR))

from group_reconciliation import reconcile_group_results


class GroupReconciliationTests(unittest.TestCase):
    def test_reports_every_declared_but_undiscovered_test(self):
        declared = {f"test-{index:02d}-t" for index in range(1, 23)}
        discovered = [f"test-{index:02d}-t" for index in range(1, 17)]
        results = [(name, 0) for name in discovered]

        report = reconcile_group_results(declared, discovered, results)

        self.assertEqual(
            report.missing,
            {f"test-{index:02d}-t" for index in range(17, 23)},
        )
        self.assertFalse(report.ok)

    def test_reports_duplicate_discovered_basenames(self):
        report = reconcile_group_results(
            {"alpha-t", "beta-t"},
            ["alpha-t", "alpha-t", "beta-t"],
            [("alpha-t", 0), ("beta-t", 0)],
        )

        self.assertEqual(report.duplicates, {"alpha-t"})
        self.assertFalse(report.ok)

    def test_result_without_exit_status_is_skipped(self):
        report = reconcile_group_results(
            {"alpha-t"}, ["alpha-t"], [("alpha-t", None)]
        )

        self.assertEqual(report.skipped, {"alpha-t"})
        self.assertFalse(report.ok)

    def test_nonzero_exit_status_is_failed(self):
        report = reconcile_group_results(
            {"alpha-t"}, ["alpha-t"], [("alpha-t", 7)]
        )

        self.assertEqual(report.failed, {"alpha-t"})
        self.assertFalse(report.ok)

    def test_all_declared_tests_passing_is_clean(self):
        report = reconcile_group_results(
            {"alpha-t", "beta-t"},
            ["alpha-t", "beta-t"],
            [("alpha-t", 0), ("beta-t", 0)],
        )

        self.assertEqual(report.passed, {"alpha-t", "beta-t"})
        self.assertEqual(report.failed, set())
        self.assertEqual(report.skipped, set())
        self.assertEqual(report.missing, set())
        self.assertEqual(report.duplicates, set())
        self.assertTrue(report.ok)

    def test_selected_subset_ignores_unselected_programs(self):
        report = reconcile_group_results(
            {"alpha-t"},
            ["alpha-t", "beta-t", "beta-t"],
            [("alpha-t", 0), ("beta-t", 9), ("beta-t", 9)],
        )

        self.assertEqual(report.passed, {"alpha-t"})
        self.assertEqual(report.duplicates, set())
        self.assertTrue(report.ok)

    def test_empty_selected_subset_is_clean(self):
        report = reconcile_group_results(
            set(), ["alpha-t"], [("alpha-t", 0)]
        )

        self.assertTrue(report.ok)


if __name__ == "__main__":
    unittest.main()
