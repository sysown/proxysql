import json
import re
import unittest
from pathlib import Path


TAP_ROOT = Path(__file__).resolve().parents[1]
GROUPS_JSON = TAP_ROOT / "groups" / "groups.json"
TOP_MAKEFILE = TAP_ROOT / "Makefile"
UNIT_MAKEFILE = TAP_ROOT / "tests" / "unit" / "Makefile"

UNRELATED_GENAI_UNITS = {
    "genai_plugin_anomaly_unit-t",
    "genai_plugin_backend_client_unit-t",
    "genai_plugin_load_unit-t",
}


def parse_make_list(makefile_text: str, variable: str) -> list[str]:
    lines = makefile_text.splitlines()
    values: list[str] = []
    collecting = False
    for line in lines:
        if not collecting:
            match = re.match(rf"^{re.escape(variable)}\s*:?=\s*(.*)$", line)
            if match is None:
                continue
            remainder = match.group(1)
            collecting = True
        else:
            remainder = line.strip()

        continued = remainder.endswith("\\")
        if continued:
            remainder = remainder[:-1]
        values.extend(remainder.split())
        if not continued:
            break
    return values


class AIUnitHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.groups = json.loads(GROUPS_JSON.read_text())
        cls.top_makefile = TOP_MAKEFILE.read_text()
        cls.unit_makefile = UNIT_MAKEFILE.read_text()
        cls.expected = {
            name
            for name, memberships in cls.groups.items()
            if name.startswith("genai_")
            and name.endswith("_unit-t")
            and ({"ai-g1", "ai-g2"} & set(memberships))
        }

    def test_group_contract_contains_exactly_eleven_genai_units(self):
        self.assertEqual(len(self.expected), 11)

    def test_unit_makefile_build_contract_matches_group_declarations(self):
        configured = set(
            parse_make_list(self.unit_makefile, "AI_GENAI_UNIT_TESTS")
        )
        self.assertEqual(configured, self.expected)
        self.assertTrue(configured.isdisjoint(UNRELATED_GENAI_UNITS))
        self.assertRegex(
            self.unit_makefile, r"(?m)^ai_genai_unit_tests:\s*\$\(AI_GENAI_UNIT_TESTS\)"
        )

    def test_top_level_stage_contract_is_runner_discoverable(self):
        configured = set(
            parse_make_list(self.top_makefile, "AI_GENAI_UNIT_TESTS")
        )
        self.assertEqual(configured, self.expected)
        self.assertTrue(configured.isdisjoint(UNRELATED_GENAI_UNITS))

        stage_values = parse_make_list(
            self.top_makefile, "AI_GENAI_STAGE_DIR"
        )
        self.assertEqual(len(stage_values), 1)
        self.assertRegex(Path(stage_values[0]).name, r"^tap_tests_.+")
        self.assertRegex(
            self.top_makefile, r"(?m)^ai_genai_unit_tests:\s*"
        )

    def test_built_manifest_and_stage_match_contract_when_present(self):
        stage_values = parse_make_list(
            self.top_makefile, "AI_GENAI_STAGE_DIR"
        )
        if not stage_values:
            self.fail("AI_GENAI_STAGE_DIR is not declared")

        stage_dir = TAP_ROOT / stage_values[0]
        manifest = stage_dir / "manifest.txt"
        if not manifest.exists():
            return

        manifest_names = {
            line.strip() for line in manifest.read_text().splitlines() if line.strip()
        }
        self.assertEqual(manifest_names, self.expected)
        staged_files = {path.name for path in stage_dir.iterdir() if path.is_file()}
        self.assertEqual(staged_files, self.expected | {"manifest.txt"})


if __name__ == "__main__":
    unittest.main()
