import pathlib
import subprocess
import unittest

import yaml


class ContributorsWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = pathlib.Path(__file__).resolve().parents[1] / "workflows" / "contributors.yml"
        # BaseLoader keeps GitHub's YAML `on` key as a string.
        cls.workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        cls.job = cls.workflow["jobs"]["update"]
        cls.steps = cls.job["steps"]

    def test_scheduled_and_manual_updates_are_upstream_only(self):
        self.assertEqual(set(self.workflow["on"]), {"schedule", "workflow_dispatch"})
        self.assertEqual(self.job["if"], "github.repository == 't8y2/dbx'")
        self.assertEqual(self.job["runs-on"], "ubuntu-latest")

    def test_token_validation_precedes_checkout(self):
        self.assertEqual(self.steps[0]["name"], "Verify push token")
        self.assertTrue(self.steps[1]["uses"].startswith("actions/checkout@"))
        self.assertEqual(
            self.steps[0]["env"]["PUSH_TOKEN"],
            self.steps[1]["with"]["token"],
        )

    def test_missing_token_fails_before_any_repository_operation(self):
        result = subprocess.run(
            ["bash", "-e", "-c", self.steps[0]["run"]],
            env={"PUSH_TOKEN": ""}, capture_output=True, text=True, timeout=5,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No owner PAT configured", result.stdout)

    def test_configured_token_passes_preflight_without_checkout(self):
        result = subprocess.run(
            ["bash", "-e", "-c", self.steps[0]["run"]],
            env={"PUSH_TOKEN": "synthetic-test-value"},
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("synthetic-test-value", result.stdout + result.stderr)

    def test_does_not_add_permissions_or_default_token_fallback(self):
        self.assertEqual(self.workflow["permissions"], {"contents": "write"})
        self.assertNotIn("permissions", self.job)
        self.assertEqual(
            self.steps[1]["with"]["token"],
            "${{ secrets.MCP_RELEASE_TOKEN || secrets.PROJECT_AUTOMATION_TOKEN }}",
        )


if __name__ == "__main__":
    unittest.main()
