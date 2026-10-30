"""Offline packaging regressions. No real launchctl, credentials or services."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


def deny_external_effects(event, args):
    if event in {"subprocess.Popen", "os.system", "socket.connect", "socket.sendto", "socket.getaddrinfo", "socket.bind"}:
        raise AssertionError(f"offline regression prohibited external effect: {event}")


sys.addaudithook(deny_external_effects)
SPEC = importlib.util.spec_from_file_location("installer", Path(__file__).with_name("install_macos.py"))
assert SPEC is not None and SPEC.loader is not None
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class PackagingTests(unittest.TestCase):
    def setUp(self):
        # Keep every fixture under the caller's owned evidence directory.
        self.tmp = tempfile.TemporaryDirectory(prefix="packaging-", dir=os.environ["PACKAGING_TEST_ROOT"])
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / "Home with spaces"
        self.home.mkdir(mode=0o700)
        self.binary = self.root / "approved binary"
        self.binary.write_bytes(struct.pack("<IIII", 0xFEEDFACF, 0x0100000C, 0, 2) + b"fixture-not-executable-code")
        self.binary.chmod(0o700)
        self.sha = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.calls = []
        self.identity = dict(user="fixture", host="fixture-mac", arch="arm64", uid=os.getuid(), home=str(self.home))
        self.env = patch.dict(os.environ, {"HOME": str(self.home), "MCP_TOKEN": "must-not-inherit", "TUNNEL_TARGET": "must-not-use"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def run_fake(self, argv, **kwargs):
        self.calls.append(argv)
        self.assertIn(argv[0], ["/bin/launchctl", "/usr/sbin/lsof"])
        self.assertNotIn("bootstrap", argv)
        self.assertNotIn("kickstart", argv)
        if argv[0] == "/bin/launchctl":
            return subprocess.CompletedProcess(argv, 113, "", f'Could not find service "{m.LABEL}" in domain for user gui:{os.getuid()}')
        return subprocess.CompletedProcess(argv, 1, "", "")

    def args(self, *more):
        return ["install", "--binary", str(self.binary), "--sha256", self.sha,
                "--version", "test-v1", "--expect-user", "fixture", "--expect-host", "fixture-mac",
                "--expect-arch", "arm64", "--no-autostart", *more]

    def invoke(self, *more, runner=None):
        out = io.StringIO()
        with patch.object(m, "identity", return_value=self.identity), patch.object(m, "port_bind_check"), contextlib.redirect_stdout(out):
            rc = m.main(self.args(*more), runner=runner or self.run_fake)
        return rc, out.getvalue()

    @property
    def data(self):
        return self.home / "Library/Application Support/messenger-mcp-stuv2"

    def test_dry_run_deterministic_no_writes(self):
        before = sorted(str(x.relative_to(self.root)) for x in self.root.rglob("*"))
        a = self.invoke("--dry-run")
        b = self.invoke("--dry-run")
        self.assertEqual(a, b)
        self.assertEqual(a[0], 0)
        self.assertEqual(before, sorted(str(x.relative_to(self.root)) for x in self.root.rglob("*")))
        self.assertNotIn("must-not-inherit", a[1])
        self.assertEqual(json.loads(a[1])["state"], "dry-run")

    def test_install_private_cold_staged_spaces(self):
        rc, output = self.invoke()
        self.assertEqual(rc, 0)
        self.assertFalse((self.home / "Library/LaunchAgents").exists())
        cfg = (self.data / "secrets.env").read_text()
        values = dict(line.split("=", 1) for line in cfg.splitlines())
        self.assertEqual(values["READ_ONLY"], "true")
        self.assertEqual(values["SYNC_ENABLED"], "false")
        self.assertEqual(values["PAIRING_ENABLED"], "false")
        self.assertEqual(values["LISTEN"], "127.0.0.1:7381")
        self.assertGreaterEqual(len(values["MCP_TOKEN"]), 32)
        self.assertNotEqual(values["MCP_TOKEN"], values["INTERNAL_SECRET"])
        for key in ["MATRIX_PASSWORD", "BRIDGE_PROVISIONING_SECRET", "TUNNEL_TARGET"]:
            self.assertNotIn(key, values)
        for file in self.data.rglob("*"):
            mode = file.stat().st_mode & 0o777
            self.assertEqual(mode, 0o700 if file.is_dir() or file.name == "messenger-mcp" else 0o600)
        self.assertEqual(self.data.stat().st_mode & 0o777, 0o700)
        plist_path = self.data / "launchd" / f"{m.LABEL}.plist"
        plist = plistlib.loads(plist_path.read_bytes())
        self.assertEqual(plist["ProgramArguments"], [str(self.data / "bin/messenger-mcp"), "serve", "--data", str(self.data)])
        self.assertFalse(plist["RunAtLoad"])
        self.assertFalse(plist["KeepAlive"])
        self.assertNotIn("EnvironmentVariables", plist)
        for secret in [values["MCP_TOKEN"], values["INTERNAL_SECRET"]]:
            self.assertNotIn(secret, output)
            self.assertNotIn(secret.encode(), plist_path.read_bytes())
        self.assertEqual((self.data / "bin/messenger-mcp").read_bytes(), self.binary.read_bytes())
        receipt = json.loads((self.data / "install-receipt.json").read_text())
        self.assertEqual(receipt["sha256"], self.sha)
        self.assertFalse(receipt["autostart"])
        self.assertEqual(receipt["label"], m.LABEL)

    def test_reinstall_refuses_without_overwrite(self):
        self.assertEqual(self.invoke()[0], 0)
        before = (self.data / "secrets.env").read_bytes()
        with self.assertRaises(m.Refusal):
            self.invoke()
        self.assertEqual((self.data / "secrets.env").read_bytes(), before)

    def test_binary_digest_mismatch_refuses(self):
        self.binary.write_bytes(self.binary.read_bytes() + b"changed")
        with self.assertRaises(m.Refusal):
            self.invoke("--dry-run")
        self.assertFalse(self.data.exists())

    def test_wrong_arch_and_non_macho_refuse(self):
        with self.assertRaises(m.Refusal):
            m.check_binary(self.binary, self.sha, "x86_64")
        self.binary.write_bytes(b"#!/bin/sh\nexit 0\n")
        with self.assertRaises(m.Refusal):
            m.check_binary(self.binary, hashlib.sha256(self.binary.read_bytes()).hexdigest(), "arm64")

    def test_identity_mismatch_refuses(self):
        self.identity["host"] = "different-host"
        with self.assertRaises(m.Refusal):
            self.invoke("--dry-run")
        self.assertFalse(self.calls)

    def test_home_identity_mismatch_refuses(self):
        self.identity["home"] = str(self.root)
        with self.assertRaises(m.Refusal):
            self.invoke()

    def test_existing_plist_refuses_even_staging(self):
        agents = self.home / "Library/LaunchAgents"
        agents.mkdir(parents=True)
        path = agents / f"{m.LABEL}.plist"
        path.write_text("foreign")
        with self.assertRaises(m.Refusal):
            self.invoke()
        self.assertEqual(path.read_text(), "foreign")
        self.assertFalse(self.data.exists())

    def test_registered_label_refuses(self):
        def run(argv, **kw):
            return subprocess.CompletedProcess(argv, 0, "foreign registration", "")
        with self.assertRaises(m.Refusal):
            self.invoke(runner=run)
        self.assertFalse(self.data.exists())

    def test_launchctl_uncertain_refuses(self):
        def run(argv, **kw):
            return subprocess.CompletedProcess(argv, 1, "", "permission denied")
        with self.assertRaises(m.Refusal):
            self.invoke(runner=run)

    def test_any_listener_refuses_without_kill(self):
        def run(argv, **kw):
            if argv[0].endswith("lsof"):
                return subprocess.CompletedProcess(argv, 0, "p999\nu999\nn*:7381\n", "")
            return self.run_fake(argv, **kw)
        with self.assertRaises(m.Refusal):
            self.invoke(runner=run)

    def test_lsof_error_refuses(self):
        def run(argv, **kw):
            if argv[0].endswith("lsof"):
                return subprocess.CompletedProcess(argv, 1, "", "not allowed")
            return self.run_fake(argv, **kw)
        with self.assertRaises(m.Refusal):
            self.invoke(runner=run)

    def test_symlink_ancestor_refuses(self):
        (self.home / "Library").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(m.Refusal):
            self.invoke()

    def test_world_writable_ancestor_refuses(self):
        (self.home / "Library").mkdir(mode=0o777)
        (self.home / "Library").chmod(0o777)
        with self.assertRaises(m.Refusal):
            self.invoke()

    def test_symlink_binary_refuses(self):
        link = self.root / "binary-link"
        link.symlink_to(self.binary)
        with self.assertRaises(m.Refusal):
            m.check_binary(link, self.sha, "arm64")

    def test_publish_explicit_never_starts(self):
        self.assertEqual(self.invoke("--publish-launchagent")[0], 0)
        p = self.home / "Library/LaunchAgents" / f"{m.LABEL}.plist"
        self.assertFalse(plistlib.loads(p.read_bytes())["RunAtLoad"])
        self.assertTrue(all("print" in x or x[0].endswith("lsof") for x in self.calls))

    def test_autostart_requires_publish_and_explicit_choice(self):
        with self.assertRaises(m.Refusal):
            self.invoke("--autostart-on-login")
        args = [x for x in self.args("--publish-launchagent", "--autostart-on-login") if x != "--no-autostart"]
        with patch.object(m, "identity", return_value=self.identity), patch.object(m, "port_bind_check"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(m.main(args, runner=self.run_fake), 0)
        p = self.home / "Library/LaunchAgents" / f"{m.LABEL}.plist"
        self.assertTrue(plistlib.loads(p.read_bytes())["RunAtLoad"])
        self.assertTrue(plistlib.loads(p.read_bytes())["KeepAlive"])

    def test_custom_stage_directory(self):
        stage = self.home / "review stage"
        self.assertEqual(self.invoke("--stage-dir", str(stage))[0], 0)
        self.assertTrue((stage / f"{m.LABEL}.plist").exists())

    def test_partial_failure_rolls_back_only_owned_files(self):
        original = m.private_write
        def fail(path, data, mode=0o600):
            if path.name == "install-receipt.json":
                raise OSError("fixture interruption")
            return original(path, data, mode)
        with patch.object(m, "private_write", side_effect=fail), self.assertRaises(OSError):
            self.invoke("--publish-launchagent")
        self.assertFalse(self.data.exists())
        self.assertTrue(self.binary.exists())

    def test_status_staged_no_secret_read(self):
        self.invoke()
        # Assert status does not require opening secrets or a ledger.
        (self.data / "secrets.env").unlink()
        out = io.StringIO()
        with patch.object(m, "identity", return_value=self.identity), contextlib.redirect_stdout(out):
            self.assertEqual(m.main(["status", "--data-dir", str(self.data)], runner=self.run_fake), 0)
        result = json.loads(out.getvalue())
        self.assertEqual(result["service"], "not-registered")
        self.assertEqual(result["listener"], "absent")
        self.assertEqual(result["source"], "unpaired-capture-disabled configuration, live state not queried")

    def status_call(self, runner):
        with patch.object(m, "identity", return_value=self.identity), contextlib.redirect_stdout(io.StringIO()) as out:
            rc = m.main(["status", "--data-dir", str(self.data)], runner=runner)
        return rc, json.loads(out.getvalue())

    def running_fixture(self, argv, **kwargs):
        if argv[0].endswith("launchctl"):
            binary = self.data / "bin/messenger-mcp"
            source = self.data / "launchd" / f"{m.LABEL}.plist"
            text = f"path = {source}\nprogram = {binary}\narguments = {{\n{binary}\nserve\n--data\n{self.data}\n}}\npid = 43210\n"
            return subprocess.CompletedProcess(argv, 0, text, "")
        if "txt" in argv:
            return subprocess.CompletedProcess(argv, 0, f"p43210\nn{self.data / 'bin/messenger-mcp'}\n", "")
        return subprocess.CompletedProcess(argv, 0, "p43210\nu501\nn127.0.0.1:7381\n", "")

    def test_status_exact_owned_running_fixture(self):
        self.invoke()
        rc, result = self.status_call(self.running_fixture)
        self.assertEqual(rc, 0)
        self.assertEqual(result["service"], "registered-owned")
        self.assertEqual(result["listener"], "owned")

    def test_status_rejects_other_label_binary(self):
        self.invoke()
        def run(argv, **kwargs):
            if argv[0].endswith("launchctl"):
                return subprocess.CompletedProcess(argv, 0, "program = /foreign\npid = 43210\n", "")
            return self.running_fixture(argv, **kwargs)
        with self.assertRaises(m.Refusal):
            self.status_call(run)

    def test_status_rejects_altered_arguments_and_plist_origin(self):
        self.invoke()
        for old, new in [("\n--data\n", "\n--other\n"), ("path = ", "path = /foreign")]:
            def run(argv, **kwargs):
                result = self.running_fixture(argv, **kwargs)
                if argv[0].endswith("launchctl"):
                    result.stdout = result.stdout.replace(old, new)
                return result
            with self.assertRaises(m.Refusal):
                self.status_call(run)

    def test_status_rejects_foreign_listener_pid(self):
        self.invoke()
        def run(argv, **kwargs):
            if argv[0].endswith("lsof") and "txt" not in argv:
                return subprocess.CompletedProcess(argv, 0, "p12345\nu501\nn127.0.0.1:7381\n", "")
            return self.running_fixture(argv, **kwargs)
        with self.assertRaises(m.Refusal):
            self.status_call(run)

    def test_status_rejects_foreign_executable_image(self):
        self.invoke()
        def run(argv, **kwargs):
            if "txt" in argv:
                return subprocess.CompletedProcess(argv, 0, "p43210\nn/foreign\n", "")
            return self.running_fixture(argv, **kwargs)
        with self.assertRaises(m.Refusal):
            self.status_call(run)

    def test_status_rejects_unregistered_listener(self):
        self.invoke()
        def run(argv, **kwargs):
            if argv[0].endswith("launchctl"):
                return self.run_fake(argv, **kwargs)
            return self.running_fixture(argv, **kwargs)
        with self.assertRaises(m.Refusal):
            self.status_call(run)

    def test_status_rejects_permissive_receipt_and_plist(self):
        self.invoke()
        receipt = self.data / "install-receipt.json"
        receipt.chmod(0o644)
        with self.assertRaises(m.Refusal):
            self.status_call(self.run_fake)
        receipt.chmod(0o600)
        p = self.data / "launchd" / f"{m.LABEL}.plist"
        p.chmod(0o644)
        with self.assertRaises(m.Refusal):
            self.status_call(self.run_fake)

    def test_status_rejects_permissive_data_directory(self):
        self.invoke()
        self.data.chmod(0o755)
        with self.assertRaises(m.Refusal):
            self.status_call(self.run_fake)

    def test_binary_nonexecutable_writable_and_hardlink_refuse(self):
        for mode in [0o600, 0o777]:
            self.binary.chmod(mode)
            with self.assertRaises(m.Refusal):
                self.invoke()
        self.binary.chmod(0o700)
        os.link(self.binary, self.root / "hardlink")
        with self.assertRaises(m.Refusal):
            self.invoke()

    def test_stage_conflict_and_outside_home_refuse(self):
        stage = self.home / "existing"
        stage.mkdir()
        with self.assertRaises(m.Refusal):
            self.invoke("--stage-dir", str(stage))
        with self.assertRaises(m.Refusal):
            self.invoke("--data-dir", str(self.root / "outside"))
        self.assertFalse(self.data.exists())

    def test_exclusive_root_refuses_race_without_deleting_foreign(self):
        original = m.Creation.mkdir
        def race(creation, path, exclusive=False):
            if path == self.data and exclusive:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.mkdir()
                (path / "inherited-ledger").write_text("foreign")
            return original(creation, path, exclusive)
        with patch.object(m.Creation, "mkdir", race), self.assertRaises(FileExistsError):
            self.invoke()
        self.assertEqual((self.data / "inherited-ledger").read_text(), "foreign")
        self.assertFalse((self.data / "secrets.env").exists())

    def test_no_private_file_overwrite(self):
        target = self.root / "existing-private"
        target.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            m.private_write(target, b"replace")
        self.assertEqual(target.read_bytes(), b"keep")

    def test_root_identity_refused(self):
        with patch.object(m.sys, "platform", "darwin"), patch.object(m.os, "getuid", return_value=0), self.assertRaises(m.Refusal):
            m.identity()

    def test_inspection_timeout_refuses(self):
        def run(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, 10)
        with self.assertRaises(m.Refusal):
            self.invoke(runner=run)

    def test_native_x86_binary_supported(self):
        self.binary.write_bytes(struct.pack("<IIII", 0xFEEDFACF, 0x01000007, 0, 2) + b"fixture")
        digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.assertEqual(m.check_binary(self.binary, digest, "x86_64"), self.binary.read_bytes())

    def test_status_detects_binary_drift(self):
        self.invoke()
        (self.data / "bin/messenger-mcp").write_bytes(b"drift")
        with patch.object(m, "identity", return_value=self.identity), self.assertRaises(m.Refusal):
            m.main(["status", "--data-dir", str(self.data)], runner=self.run_fake)


if __name__ == "__main__":
    unittest.main(verbosity=2)
