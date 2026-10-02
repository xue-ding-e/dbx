"""Offline regressions for the artifact verifier's real helpers and cleanup."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import textwrap
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

SPEC = importlib.util.spec_from_file_location("artifact_smoke", Path(__file__).with_name("verify-remote-mcp-artifact.py"))
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


class SmokeTests(unittest.TestCase):
    def test_environment_replaces_profiles_and_strips_case_insensitive_overrides(self):
        inherited = {"PATH": "keep", "DBX_WEB_URL": "private", "dbx_secret_key": "private",
                     "DbX_DATA_DIR": "private", "home": "private", "APPDATA": "private",
                     "RUST_LOG": "trace"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = smoke.isolated_environment(root, inherited)
            self.assertEqual(env["PATH"], "keep")
            self.assertNotIn("private", env.values())
            self.assertEqual(env["DBX_DATA_DIR"], str(root / "data"))
            self.assertEqual(env["RUST_LOG"], "warn")
            self.assertEqual(len(bytes.fromhex(Path(env["DBX_SECRET_KEY_FILE"]).read_text())), 32)
            if os.name != "nt":
                self.assertEqual(Path(env["DBX_SECRET_KEY_FILE"]).stat().st_mode & 0o777, 0o600)
            self.assertEqual(inherited["dbx_secret_key"], "private")

    def test_fixtures_have_different_encryption_keys(self):
        keys = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as directory:
                env = smoke.isolated_environment(Path(directory), {})
                keys.append(Path(env["DBX_SECRET_KEY_FILE"]).read_text())
        self.assertNotEqual(*keys)

    def test_signing_fixture_produces_valid_ephemeral_rs256_tokens(self):
        fixture = smoke.SigningFixture()
        token = fixture.token(sub="second-owner")
        header, payload, signature = token.split(".")
        decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        self.assertEqual(json.loads(decode(payload))["sub"], "second-owner")
        self.assertEqual(json.loads(decode(header))["alg"], "RS256")
        fixture.key.public_key().verify(decode(signature), (header + "." + payload).encode(),
                                        padding.PKCS1v15(), hashes.SHA256())
        self.assertNotIn("d", fixture.jwks()["keys"][0])
        self.assertEqual(fixture.tokens, [token])

    def test_wrong_key_token_has_valid_claims_but_invalid_signature(self):
        trusted = smoke.SigningFixture()
        foreign = smoke.SigningFixture()
        token = foreign.token()
        header, payload, signature = token.split(".")
        decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        self.assertEqual(json.loads(decode(header))["kid"], trusted.jwks()["keys"][0]["kid"])
        self.assertEqual(json.loads(decode(payload))["iss"], trusted.issuer)
        self.assertEqual(json.loads(decode(payload))["aud"], trusted.resource)
        self.assertEqual(json.loads(decode(payload))["sub"], "owner")
        with self.assertRaises(InvalidSignature):
            trusted.key.public_key().verify(decode(signature), (header + "." + payload).encode(),
                                            padding.PKCS1v15(), hashes.SHA256())

    def test_json_and_sse_responses_match_request_id(self):
        value = {"jsonrpc": "2.0", "id": 7, "result": {"tools": []}}
        for data in [json.dumps(value).encode(),
                     b'event: message\ndata: {"id":2,"result":{}}\n\ndata: ' + json.dumps(value).encode() + b"\n\n"]:
            self.assertEqual(smoke.decode_rpc(data, 7), value)

    def test_invalid_or_failed_rpc_responses_are_rejected(self):
        for data in [b"invalid", b'{"id":8,"result":{}}', b'{"id":7,"error":{}}',
                     b'data: [1]\n', b'data: {"id":7}\n', b'data: nope\n']:
            with self.subTest(data=data), self.assertRaises(smoke.SmokeFailure):
                smoke.decode_rpc(data, 7)

    def test_log_redaction_detects_tokens_across_read_boundaries(self):
        for secret in [b"test-token-value", b"BEGIN PRIVATE KEY", b"BEGIN RSA PRIVATE KEY"]:
            data = b"a" * (65536 - 3) + secret + b"b"
            with self.assertRaises(smoke.SmokeFailure):
                smoke.require_redacted(io.BytesIO(data), ["test-token-value"])
        smoke.require_redacted(io.BytesIO(b"normal diagnostic message"), [])

    def test_binary_manifest_hashes_exact_bytes_and_checks_pe_architecture(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "binary.exe"
            header = bytearray(64)
            header[:2] = b"MZ"
            struct.pack_into("<I", header, 0x3C, 64)
            data = header + b"PE\0\0" + struct.pack("<H", 0x8664)
            binary.write_bytes(data)
            report = smoke.binary_manifest(binary, True)
            self.assertEqual(report["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(report["bytes"], len(data))
            self.assertEqual(report["architecture"], "AMD64")
            for invalid in [b"", b"not PE", data[:-1], header + b"BAD\0\0\0",
                            header + b"PE\0\0" + struct.pack("<H", 0xAA64)]:
                binary.write_bytes(invalid)
                with self.assertRaises(smoke.SmokeFailure):
                    smoke.binary_manifest(binary, True)

    def test_failed_check_reaps_child_and_drains_large_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "logs-flushed"
            script = "import sys,time,pathlib; sys.stderr.write('x'*1000000); sys.stderr.flush(); pathlib.Path('logs-flushed').touch(); time.sleep(60)"
            command = [sys.executable, "-c", script]
            with self.assertRaisesRegex(smoke.SmokeFailure, "deliberate failure"):
                with smoke.managed_process(command, os.environ, directory) as (process, _, _):
                    deadline = time.monotonic() + 5
                    while not marker.exists():
                        self.assertIsNone(process.poll())
                        self.assertLess(time.monotonic(), deadline, "child log pipe blocked")
                        time.sleep(0.01)
                    raise smoke.SmokeFailure("deliberate failure")
            self.assertIsNotNone(process.poll())

    def test_unresponsive_child_is_killed_and_reaped(self):
        # Exercise the escalation branch without waiting ten seconds.
        with tempfile.TemporaryDirectory() as directory:
            with smoke.managed_process([sys.executable, "-c", "import time; time.sleep(60)"],
                                       os.environ, directory) as (process, _, _):
                real_wait = process.wait
                calls = []
                def wait(timeout):
                    calls.append(timeout)
                    if len(calls) == 1:
                        raise subprocess.TimeoutExpired("synthetic", timeout)
                    return real_wait(timeout=timeout)
                process.wait = wait
            self.assertEqual(calls, [10, 10])
            self.assertIsNotNone(process.poll())

    def test_stdio_failure_reaps_process(self):
        original = smoke.managed_process
        children = []
        from contextlib import contextmanager
        @contextmanager
        def failing_child(command, env, cwd, **kwargs):
            script = "import sys,time; sys.stdin.readline(); print('not-json',flush=True); time.sleep(60)"
            with original([sys.executable, "-c", script], env, cwd, **kwargs) as result:
                children.append(result[0])
                yield result
        with tempfile.TemporaryDirectory() as directory, patch.object(smoke, "managed_process", failing_child):
            with self.assertRaisesRegex(smoke.SmokeFailure, "invalid JSON"):
                smoke.check_stdio(Path("unused"), Path(directory), os.environ)
        self.assertIsNotNone(children[0].poll())

    def test_stdio_skips_notifications_and_closes_cleanly(self):
        original = smoke.managed_process
        from contextlib import contextmanager
        @contextmanager
        def protocol_child(command, env, cwd, **kwargs):
            script = textwrap.dedent('''
                import json,sys
                for line in sys.stdin:
                    request = json.loads(line)
                    if "id" not in request:
                        continue
                    print(json.dumps({"jsonrpc":"2.0","method":"notifications/message"}),flush=True)
                    result = {"tools":[{"name":"dbx_list_connections"}]} if request["method"] == "tools/list" else {}
                    print(json.dumps({"jsonrpc":"2.0","id":request["id"],"result":result}),flush=True)
            ''')
            with original([sys.executable, "-c", script], env, cwd, **kwargs) as result:
                yield result
        with tempfile.TemporaryDirectory() as directory, patch.object(smoke, "managed_process", protocol_child):
            self.assertEqual(smoke.check_stdio(Path("unused"), Path(directory), os.environ),
                             {"stdio_compatible": True})

    def test_checks_remain_enabled_under_python_optimization(self):
        command = [sys.executable, "-O", "-c",
                   f"import runpy; m=runpy.run_path({str(Path(smoke.__file__).resolve())!r}); m['require'](False, 'expected')"]
        result = subprocess.run(command, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"SmokeFailure: expected", result.stderr)

    def test_failed_smoke_removes_temporary_profile_and_key(self):
        captured = []
        def failing_http(binary, root, env, signing):
            captured.append(root)
            self.assertTrue(Path(env["DBX_SECRET_KEY_FILE"]).is_file())
            raise smoke.SmokeFailure("fixture failure")
        with patch.object(smoke, "binary_manifest", return_value={}), \
             patch.object(smoke, "check_http", side_effect=failing_http):
            with self.assertRaisesRegex(smoke.SmokeFailure, "fixture failure"):
                smoke.run(Path("unused"), Path("unused"))
        self.assertEqual(len(captured), 1)
        self.assertFalse(captured[0].exists())

    def test_main_does_not_log_sensitive_exception_content(self):
        with patch.object(sys, "argv", ["smoke", __file__, __file__]), \
             patch.object(smoke, "run", side_effect=ValueError("synthetic-secret")), \
             patch("sys.stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(smoke.main(), 1)
            self.assertEqual(json.loads(stderr.getvalue()), {"status": "failed", "reason": "ValueError"})


if __name__ == "__main__":
    unittest.main()
