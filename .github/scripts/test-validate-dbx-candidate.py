"""Pure synthetic admission and selector tests: every proc/cgroup I/O is mocked."""
import contextlib
import importlib.util
import io
from pathlib import Path
import stat
import types
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("dbxdriver", Path(__file__).with_name("validate-dbx-candidate.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
GIB = 1024**3
ROOT = "/sys/fs/cgroup"


class SyntheticV2:
    def __init__(self):
        self.text = {
            "/proc/meminfo": f"MemTotal: {16 * GIB // 1024} kB\nMemAvailable: {10 * GIB // 1024} kB\n",
            "/proc/self/cgroup": "0::/jobs/test\n",
            "/proc/self/mountinfo": "36 25 0:32 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
        }
        self.controls = {
            ROOT + "/cgroup.controllers": b"cpu memory pids\n",
            ROOT + "/memory.stat": b"anon 1\nfile 2\nkernel_stack 3\npagetables 4\n",
            ROOT + "/jobs/memory.max": str(12 * GIB).encode(),
            ROOT + "/jobs/memory.current": str(GIB).encode(),
            ROOT + "/jobs/test/memory.max": b"max",
            ROOT + "/jobs/test/memory.current": str(GIB).encode(),
        }
        self.directories = {ROOT, ROOT + "/jobs", ROOT + "/jobs/test"}
        self.fds, self.counts, self.opened = {}, {}, []
        self.next_fd = 100
        self.denied = set()
        self.nonregular = set()
        self.namespace = "cgroup:[42]"

    def read_text(self, path, *_args, **_kwargs):
        path = str(path)
        if path not in self.text:
            raise AssertionError("Unmocked text read: " + path)
        self.counts[path] = self.counts.get(path, 0) + 1
        value = self.text[path]
        return value[min(self.counts[path] - 1, len(value) - 1)] if isinstance(value, list) else value

    def readlink(self, path):
        assert path == "/proc/self/ns/cgroup", "Another process's namespace must not be read"
        self.counts[path] = self.counts.get(path, 0) + 1
        value = self.namespace
        return value[min(self.counts[path] - 1, len(value) - 1)] if isinstance(value, list) else value

    def open(self, path, flags, *, dir_fd=None):
        path = str(path) if dir_fd is None else self.fds[dir_fd] + "/" + str(path)
        self.opened.append(path)
        assert flags & driver.os.O_NOFOLLOW, "Control traversal must not follow symlinks"
        if path in self.denied:
            raise PermissionError(13, "synthetic denied", path)
        if path not in self.controls and path not in self.directories:
            raise FileNotFoundError(2, "synthetic absent", path)
        self.next_fd += 1
        self.fds[self.next_fd] = path
        return self.next_fd

    def fstat(self, fd):
        path = self.fds[fd]
        kind = stat.S_IFDIR if path in self.directories or path in self.nonregular else stat.S_IFREG
        return types.SimpleNamespace(st_mode=kind | 0o600, st_dev=1, st_ino=hash(path))

    def observe(self):
        with contextlib.ExitStack() as stack:
            # A plain wrapper binds the Path instance; no real /proc or cgroup
            # call is available as a fallback anywhere in this fixture.
            stack.enter_context(mock.patch.object(Path, "read_text", lambda path, *a, **kw: self.read_text(path, *a, **kw)))
            stack.enter_context(mock.patch.object(Path, "resolve", lambda path, **_kw: path))
            stack.enter_context(mock.patch.object(driver.os, "readlink", self.readlink))
            stack.enter_context(mock.patch.object(driver.os, "open", self.open))
            stack.enter_context(mock.patch.object(driver.os, "fstat", self.fstat))
            stack.enter_context(mock.patch.object(driver.os, "read", lambda fd, size: self.controls[self.fds[fd]][:size]))
            stack.enter_context(mock.patch.object(driver.os, "close", lambda fd: self.fds.pop(fd)))
            stack.enter_context(mock.patch.object(driver.os, "environ", {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux"}))
            stack.enter_context(mock.patch.object(driver.shutil, "disk_usage", lambda _path: types.SimpleNamespace(free=32 * GIB)))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            return driver.admit("/synthetic-workspace")


class AdmissionTests(unittest.TestCase):
    def test_real_root_positive_evidence_and_exact_missing_controls(self):
        fake = SyntheticV2()
        fake.text["/proc/self/cgroup"] = "0::/\n"
        result = fake.observe()
        self.assertEqual(result["effective_available_bytes"], 10 * GIB)
        self.assertEqual(result["effective_capacity_bytes"], 16 * GIB)

    def test_ancestor_limit_beats_larger_child_limit(self):
        fake = SyntheticV2()
        fake.controls[ROOT + "/jobs/test/memory.max"] = str(14 * GIB).encode()
        result = fake.observe()
        self.assertEqual(result["effective_capacity_bytes"], 12 * GIB)
        self.assertEqual(result["effective_available_bytes"], 10 * GIB)

    def test_child_max_does_not_ignore_ancestor(self):
        self.assertEqual(SyntheticV2().observe()["effective_available_bytes"], 10 * GIB)

    def test_hidden_mount_root_is_unknown(self):
        fake = SyntheticV2()
        fake.text["/proc/self/mountinfo"] = "36 25 0:32 /hidden /sys/fs/cgroup rw - cgroup2 cgroup rw\n"
        with self.assertRaisesRegex(RuntimeError, "hidden cgroup ancestors"):
            fake.observe()

    def test_visible_root_scalar_control_is_unknown(self):
        for control in ["memory.max", "memory.current"]:
            fake = SyntheticV2()
            fake.controls[ROOT + "/" + control] = b"max" if control == "memory.max" else b"0"
            with self.assertRaisesRegex(RuntimeError, "incomplete ancestry"):
                fake.observe()

    def test_permission_error_is_not_missing_and_has_no_alternate_read(self):
        fake = SyntheticV2()
        fake.denied.add(ROOT + "/memory.max")
        with self.assertRaises(PermissionError):
            fake.observe()
        self.assertEqual(fake.opened[-1], ROOT + "/memory.max")
        self.assertEqual(fake.opened.count(ROOT + "/memory.max"), 1)

    def test_missing_child_control_is_not_unlimited(self):
        fake = SyntheticV2()
        del fake.controls[ROOT + "/jobs/memory.current"]
        with self.assertRaises(FileNotFoundError):
            fake.observe()

    def test_cgroup_migration_is_unknown(self):
        fake = SyntheticV2()
        fake.text["/proc/self/cgroup"] = ["0::/jobs/test\n", "0::/other\n"]
        with self.assertRaisesRegex(RuntimeError, "process migrated"):
            fake.observe()

    def test_namespace_migration_is_unknown(self):
        fake = SyntheticV2()
        fake.namespace = ["cgroup:[42]", "cgroup:[43]"]
        with self.assertRaisesRegex(RuntimeError, "namespace changed"):
            fake.observe()

    def test_capacity_is_not_available_memory(self):
        fake = SyntheticV2()
        fake.controls[ROOT + "/jobs/memory.current"] = str(3 * GIB).encode()
        with self.assertRaisesRegex(RuntimeError, "less than 10 GiB effective available"):
            fake.observe()

    def test_nonregular_or_invalid_root_stat_is_unknown(self):
        fake = SyntheticV2()
        fake.nonregular.add(ROOT + "/memory.stat")
        with self.assertRaisesRegex(RuntimeError, "nonregular"):
            fake.observe()
        fake = SyntheticV2()
        fake.controls[ROOT + "/memory.stat"] += b"invalid record extra\n"
        with self.assertRaisesRegex(RuntimeError, "invalid root memory.stat"):
            fake.observe()

    def test_nested_mount_and_legacy_hierarchy_are_unknown(self):
        fake = SyntheticV2()
        fake.text["/proc/self/mountinfo"] += "37 36 0:33 / /sys/fs/cgroup/jobs rw - tmpfs tmpfs rw\n"
        with self.assertRaisesRegex(RuntimeError, "nested mount"):
            fake.observe()
        fake = SyntheticV2()
        fake.text["/proc/self/cgroup"] = "5:memory:/jobs/test\n"
        with self.assertRaisesRegex(RuntimeError, "v1/mixed"):
            fake.observe()


class SelectorTests(unittest.TestCase):
    def test_exact_frozen_count_and_no_duplicates(self):
        self.assertEqual(sum(map(len, driver.CASES.values())), 127)
        self.assertEqual(len(driver.FRONTEND), 15)
        for cases in driver.CASES.values():
            self.assertTrue(cases)
            self.assertEqual(len(cases), len(set(cases)))

    def test_list_parser_does_not_accept_zero_tests_as_success(self):
        self.assertEqual(driver.discover_tests("a: test\nb: benchmark\n2 tests, 0 benchmarks"), ["a"])
        for content in ["test result: ok. 0 passed; 0 failed; 0 ignored;", "test result: ok. 1 passed; 0 failed; 1 ignored;"]:
            with self.assertRaises(RuntimeError):
                driver.validate_result(content, 1)
        driver.validate_result("test result: ok. 1 passed; 0 failed; 0 ignored;", 1)

    def test_test_environment_has_no_credentials_or_host_profile(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.dict(driver.os.environ, {"DBX_SECRET_KEY":"not-allowed", "GH_TOKEN":"not-allowed", "HOME":"/real", "SSH_AUTH_SOCK":"not-allowed", "DBUS_SESSION_BUS_ADDRESS":"not-allowed", "HTTPS_PROXY":"not-allowed"}):
                env = driver.isolated_env(Path(temp) / "synthetic")
            self.assertNotEqual(env["HOME"], "/real")
            for key in ["DBX_SECRET_KEY", "GH_TOKEN", "SSH_AUTH_SOCK", "DBUS_SESSION_BUS_ADDRESS", "HTTPS_PROXY"]:
                self.assertNotIn(key, env)

    def test_network_wrapper_never_falls_back_to_host_network(self):
        command = driver.network_fixture(["test-binary", "arg with spaces"])
        self.assertEqual(command[:6], ["unshare", "--user", "--map-current-user", "--keep-caps", "--net", "--"])
        self.assertEqual(command[-2:], ["test-binary", "arg with spaces"])
        self.assertIn('ip link set lo up; exec setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs -- "$@"', command)

class OwnedProcessTests(unittest.TestCase):
    def prepare(self, directory):
        import time
        driver.output = Path(directory)
        driver.deadline = time.monotonic() + 20
        driver.command_records = []
        driver.cancellation = {"spawning": False, "pending": None}

    def test_success_records_group_cleanup_and_leader_reaped(self):
        import tempfile, sys
        with tempfile.TemporaryDirectory() as temp:
            self.prepare(temp)
            code, content = driver.run([sys.executable, "-c", "print('synthetic-only')"], temp, "success", timeout=10, env={})
            self.assertEqual(code, 0)
            self.assertEqual(content.strip(), "synthetic-only")
            self.assertEqual(driver.command_records[0]["cleanup"], "owned group TERM/KILL sent; leader reaped")

    def test_timeout_is_failure_and_reaps_owned_leader(self):
        import tempfile, sys
        with tempfile.TemporaryDirectory() as temp:
            self.prepare(temp)
            with self.assertRaisesRegex(RuntimeError, "time/output budget exceeded"):
                driver.run([sys.executable, "-c", "import time; time.sleep(60)"], temp, "timeout", timeout=6, env={})
            self.assertTrue(driver.command_records[0]["timed_out_or_output_limit"])
            self.assertEqual(driver.command_records[0]["cleanup"], "owned group TERM/KILL sent; leader reaped")

if __name__ == "__main__":
    unittest.main()
