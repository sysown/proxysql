"""Exercise the no-infra checkout's root-file contract with real Git.

CHECKOUT_TEST_GIT may point at an older supported Git (e.g. 2.34.1).
The Git calls below follow the pinned actions/checkout implementation.
"""
import os
import pathlib
import subprocess
import tempfile
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[3]
GIT = os.environ.get("CHECKOUT_TEST_GIT", "git")


class SparseCheckoutTests(unittest.TestCase):
    def test_no_infra_checkout_preserves_root_assets(self):
        self.check_checkout()

    def test_reused_cone_checkout_preserves_root_assets(self):
        self.check_checkout(initial_cone=True)

    def check_checkout(self, initial_cone=False):
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci-no-infra-g1.yml").read_text())
        options = next(step["with"] for job in workflow["jobs"].values()
                       for step in job.get("steps", [])
                       if step.get("with", {}).get("path") == "proxysql")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            def git(*args):
                return subprocess.run([GIT, *args], cwd=root, check=True,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout
            git("init", "--quiet")
            files = [".gitignore", "Makefile", "include/a.h", "lib/a.cpp", "src/a.cpp",
                     "test/infra/a.sh", "test/tap/pgsql_user_sync/a.py", "test/scripts/a.py",
                     "doc/excluded.txt", "deps/excluded.txt"]
            for name in files:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n")
            git("add", ".")
            git("-c", "user.name=Checkout Test", "-c", "user.email=test@example.invalid",
                "commit", "--quiet", "-m", "fixture")
            if initial_cone:
                git("sparse-checkout", "set", "--cone", "test/infra")
            # Start from an unpopulated checkout, as checkout does after fetching.
            git("read-tree", "--empty")
            for name in files:
                (root / name).unlink(missing_ok=True)
            patterns = options["sparse-checkout"].splitlines()
            if options.get("sparse-checkout-cone-mode", True):
                git("sparse-checkout", "set", *patterns)
            else:
                git("config", "core.sparseCheckout", "true")
                path = root / git("rev-parse", "--git-path", "info/sparse-checkout").strip()
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a") as stream:
                    stream.write("\n" + "\n".join(patterns) + "\n")
            git("checkout", "--force", "HEAD")
            for name in files[:-2]:
                self.assertTrue((root / name).is_file(), f"checkout omitted required asset {name}")
            for name in files[-2:]:
                self.assertFalse((root / name).exists(), f"checkout included excluded tree {name}")


if __name__ == "__main__":
    unittest.main()
