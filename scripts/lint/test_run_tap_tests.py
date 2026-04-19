#!/usr/bin/env python3

import json
import importlib.util
import tempfile
import unittest
from pathlib import Path


def load_module():
    path = Path(__file__).with_name("run_tap_tests.py")
    spec = importlib.util.spec_from_file_location("run_tap_tests", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RunTapTestsTest(unittest.TestCase):
    def test_discover_test_sources_filters_only_tap_cpp_files(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "test/tap/tests").mkdir(parents=True)
            (root / "test/tap/tests/unit").mkdir(parents=True)
            (root / "test/tap/tests/example-t.cpp").write_text("// a\n")
            (root / "test/tap/tests/unit/unit-example-t.cpp").write_text("// b\n")
            (root / "test/tap/tests/not-a-test.cpp").write_text("// c\n")
            (root / "test/tap/tests/example-t.py").write_text("# d\n")

            files = mod.discover_test_sources(root)

        self.assertEqual(
            [
                root / "test/tap/tests/example-t.cpp",
                root / "test/tap/tests/unit/unit-example-t.cpp",
            ],
            files,
        )

    def test_build_compile_database_writes_entries_for_tap_sources(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "test/tap/tests").mkdir(parents=True)
            (root / "test/tap/tests/unit").mkdir(parents=True)
            sources = [
                root / "test/tap/tests/example-t.cpp",
                root / "test/tap/tests/unit/unit-example-t.cpp",
            ]
            for src in sources:
                src.write_text("// x\n")

            db_dir = mod.build_compile_database(root, sources)
            data = json.loads((db_dir / "compile_commands.json").read_text())

        self.assertEqual(2, len(data))
        self.assertEqual(
            {str(src) for src in sources},
            {entry["file"] for entry in data},
        )
        self.assertTrue(all(entry["directory"] == str(root) for entry in data))

    def test_build_compile_database_includes_tap_include_dirs(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "test/tap/tests").mkdir(parents=True)
            source = root / "test/tap/tests/example-t.cpp"
            source.write_text("// x\n")

            db_dir = mod.build_compile_database(root, [source])
            data = json.loads((db_dir / "compile_commands.json").read_text())

        args = data[0]["arguments"]
        self.assertIn(f"-I{root / 'test/tap/tap'}", args)
        self.assertIn(f"-I{root / 'include'}", args)
        self.assertIn(f"-I{root / 'test/tap/test_helpers'}", args)

    def test_select_test_sources_accepts_explicit_file_arguments(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "test/tap/tests").mkdir(parents=True)
            (root / "test/tap/tests/unit").mkdir(parents=True)
            top = root / "test/tap/tests/example-t.cpp"
            unit = root / "test/tap/tests/unit/unit-example-t.cpp"
            top.write_text("// a\n")
            unit.write_text("// b\n")

            selected = mod.select_test_sources(root, [str(unit)])

        self.assertEqual([unit], selected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
