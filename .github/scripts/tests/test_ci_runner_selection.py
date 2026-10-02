"""Run the workflow's runner selector with real gh against a local API fixture."""
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse

import yaml

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github/workflows/ci-no-infra-g1.yml"
if not WORKFLOW.is_file():
    WORKFLOW = ROOT / ".github/workflows/ci-no-infra-g1.yml"
GH = shutil.which("gh")
RUNS = "/repos/example/project/actions/runs"
POOL_JOB = {"status": "in_progress", "labels": ["self-hosted", "proxysql-ci"]}


@unittest.skipUnless(GH, "runner-selection tests require the GitHub CLI")
class RunnerSelectionTests(unittest.TestCase):
    def select(self, jobs, *, runs=None, eligible=True):
        routes = {RUNS: runs if runs is not None else [{"workflow_runs": [{"id": n} for n in jobs]}]}
        routes.update({f"{RUNS}/{n}/jobs": pages for n, pages in jobs.items()})
        unexpected = []

        class Api(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                url = urllib.parse.urlsplit(self.path)
                page = int(urllib.parse.parse_qs(url.query).get("page", ["1"])[0])
                pages = routes.get(url.path, [])
                if page < 1 or page > len(pages):
                    unexpected.append(self.path)
                    self.send_error(404)
                    return
                body = pages[page - 1]
                if isinstance(body, int):
                    self.send_error(body, "fixture API failure")
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                if page < len(pages):
                    self.send_header("Link", f'<http://127.0.0.1:{self.server.server_port}'
                                     f'{url.path}?page={page + 1}>; rel="next"')
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

            def log_message(self, *args):
                pass

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Api)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            # Redirect only the API endpoint. Real gh handles pagination, jq,
            # HTTP errors and partial output, exactly as in the workflow.
            wrapper = root / "gh"
            wrapper.write_text(f"#!{sys.executable}\n" +
                               "import os, sys\n" +
                               f"base = 'http://127.0.0.1:{server.server_port}/'\n" +
                               "args = [base + a if a.startswith('repos/') else a for a in sys.argv[1:]]\n" +
                               f"os.execv({GH!r}, [{GH!r}] + args)\n")
            wrapper.chmod(0o755)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", GH_TOKEN="fixture-only",
                       GH_ENTERPRISE_TOKEN="fixture-only", GH_NO_UPDATE_NOTIFIER="1",
                       GH_CONFIG_DIR=str(root / "gh-config"), GH_PROMPT_DISABLED="1",
                       REPO="example/project", POOL_SIZE="6", ELIGIBLE=str(eligible).lower(),
                       GITHUB_OUTPUT=str(root / "output"))
            env.pop("GH_HOST", None)
            workflow = yaml.safe_load(WORKFLOW.read_text())
            script = workflow["jobs"]["pick-runner"]["steps"][0]["run"]
            try:
                result = subprocess.run(["bash", "-c", script], cwd=root, env=env,
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(unexpected, [], result.stdout + result.stderr)
                choice = json.loads((root / "output").read_text().strip().split("=", 1)[1])
                return choice, result.stdout
            finally:
                server.shutdown()
                thread.join()
                server.server_close()

    def test_later_jobs_page_saturates_pool(self):
        choice, output = self.select({11: [{"jobs": []}, {"jobs": [POOL_JOB] * 6}]})
        self.assertEqual(choice, "ubuntu-22.04")
        self.assertIn("demand=6/6", output)

    def test_sums_job_pages_and_run_pages(self):
        choice, output = self.select(
            {11: [{"jobs": [POOL_JOB] * 2}, {"jobs": [POOL_JOB] * 2}],
             22: [{"jobs": [POOL_JOB] * 2}]},
            runs=[{"workflow_runs": [{"id": 11}]}, {"workflow_runs": [{"id": 22}]}])
        self.assertEqual(choice, "ubuntu-22.04")
        self.assertIn("demand=6/6", output)

    def test_counts_only_running_pool_jobs(self):
        choice, output = self.select({11: [{"jobs": [POOL_JOB,
            {"status": "queued", "labels": ["proxysql-ci"]},
            {"status": "completed", "labels": ["proxysql-ci"]},
            {"status": "in_progress", "labels": ["ubuntu-22.04"]}]}]})
        self.assertEqual(choice, ["self-hosted", "proxysql-ci"])
        self.assertIn("demand=1/6", output)

    def test_empty_jobs_leave_capacity_available(self):
        choice, output = self.select({11: [{"jobs": []}]})
        self.assertEqual(choice, ["self-hosted", "proxysql-ci"])
        self.assertIn("demand=0/6", output)

    def test_job_lookup_failure_spills(self):
        choice, output = self.select({11: [500]})
        self.assertEqual(choice, "ubuntu-22.04")
        self.assertIn("could not read jobs for run 11", output)

    def test_later_job_page_failure_discards_partial_count(self):
        choice, output = self.select({11: [{"jobs": [POOL_JOB]}, 500]})
        self.assertEqual(choice, "ubuntu-22.04")
        self.assertIn("could not read jobs for run 11", output)

    def test_run_lookup_failure_preserves_existing_fallback(self):
        choice, output = self.select({}, runs=[500])
        self.assertEqual(choice, ["self-hosted", "proxysql-ci"])
        self.assertIn("could not read runs", output)

    def test_ineligible_actor_uses_hosted_without_api_calls(self):
        choice, _ = self.select({}, runs=[], eligible=False)
        self.assertEqual(choice, "ubuntu-22.04")


if __name__ == "__main__":
    unittest.main()
