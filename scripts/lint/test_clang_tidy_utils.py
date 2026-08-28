#!/usr/bin/env python3

import importlib.util
import unittest
from pathlib import Path


def load_module():
    path = Path(__file__).with_name("clang_tidy_utils.py")
    spec = importlib.util.spec_from_file_location("clang_tidy_utils", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ClangTidyUtilsTest(unittest.TestCase):
    def test_normalize_keeps_test_diagnostic(self):
        mod = load_module()
        content = (
            "/repo/test/tap/tests/example-t.cpp:12:3: warning: sample message "
            "[bugprone-branch-clone]\n"
        )

        lines = mod.normalize_clang_tidy_content(
            content,
            repo_root="/repo",
            allowed_roots=["include", "lib", "test/tap/tests", "test/tap/tests/unit"],
        )

        self.assertEqual(
            ["/repo/test/tap/tests/example-t.cpp:12: bugprone-branch-clone - sample message"],
            lines,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
