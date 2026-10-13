import os
import pathlib
import subprocess
import tempfile
import unittest

import yaml


class NotificationsWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = pathlib.Path(__file__).resolve().parents[1] / "workflows" / "notify.yml"
        cls.workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        cls.job = cls.workflow["jobs"]["notify"]
        cls.steps = {step["name"]: step for step in cls.job["steps"]}

    def test_fork_events_cannot_enter_notification_job(self):
        self.assertEqual(self.job["if"], "github.repository == 't8y2/dbx'")
        self.assertEqual(
            self.workflow["on"]["pull_request_target"]["types"], ["opened", "closed"]
        )

    def run_send(self, webhook):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for name, script in {
                "curl": '#!/bin/sh\nprintf "CURL_STUB_CALLED\\n"\n',
                "jq": '#!/bin/sh\nprintf "{}\\n"\n',
            }.items():
                path = root / name
                path.write_text(script)
                path.chmod(0o700)
            environment = {"PATH": directory, "MSG_CONTENT": "synthetic fixture"}
            if webhook is not None:
                environment["FEISHU_WEBHOOK_URL"] = webhook
            return subprocess.run(
                ["/bin/bash", "-e", "-c", self.steps["Send to Feishu"]["run"]],
                env=environment, capture_output=True, text=True, timeout=5,
            )

    def test_missing_or_empty_webhook_skips_without_calling_curl(self):
        for webhook in (None, ""):
            with self.subTest(webhook=webhook):
                result = self.run_send(webhook)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("skipping notification", result.stdout)
                self.assertNotIn("CURL_STUB_CALLED", result.stdout)

    def test_configured_webhook_preserves_send_path_using_offline_stubs(self):
        result = self.run_send("https://example.invalid/synthetic-webhook")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CURL_STUB_CALLED", result.stdout)

    def test_merged_pr_message_reproduces_original_trigger_offline(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "output"
            environment = dict(os.environ, EVENT_NAME="pull_request_target", EVENT_ACTION="closed",
                PR_TITLE="Synthetic PR", PR_URL="https://example.invalid/pr/1", PR_USER="fixture",
                PR_MERGED="true", PR_MERGED_BY="fixture", GITHUB_OUTPUT=str(output))
            result = subprocess.run(
                ["/bin/bash", "-e", "-c", self.steps["Build message"]["run"]],
                env=environment, capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("skip=false", output.read_text())


if __name__ == "__main__":
    unittest.main()
