#!/usr/bin/env python3
"""Offline, create-only macOS packaging. This module never starts a service.

Only subprocesses are exact-label `launchctl print` and listener inspection with
lsof. Installation does not execute even the supplied approved binary. Tests
inject those read-only subprocesses and identity discovery.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import pwd
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys

LABEL = "com.stuv2.messenger-mcp"
LISTEN = "127.0.0.1:7381"
SCHEMA = 1


class Refusal(Exception):
    """An ambiguous or unsafe prerequisite, before deployment."""


def identity():
    if sys.platform != "darwin":
        raise Refusal("macOS is required")
    uid = os.getuid()
    if uid == 0:
        raise Refusal("run as the target login user, never root or sudo")
    record = pwd.getpwuid(uid)
    return dict(uid=uid, user=record.pw_name, home=record.pw_dir,
                host=socket.gethostname(), arch=platform.machine())


def clean_path(raw):
    p = Path(os.path.abspath(os.path.expanduser(str(raw))))
    if any(ord(c) < 32 or ord(c) == 127 for c in str(p)):
        raise Refusal("paths must not contain control separators")
    return p


def safe_ancestors(path, uid):
    """Reject symlinks, foreign owners and writable existing ancestors."""
    for node in reversed([path, *path.parents]):
        if not os.path.lexists(node):
            continue
        s = node.lstat()
        if not stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode):
            raise Refusal(f"not a real directory: {node}")
        if s.st_uid not in (0, uid) or s.st_mode & 0o022:
            raise Refusal(f"unsafe directory ownership or write permissions: {node}")


def user_home(who):
    home = clean_path(os.environ.get("HOME", ""))
    if home != clean_path(who["home"]):
        raise Refusal("HOME does not match the login user's home")
    safe_ancestors(home, who["uid"])
    if home.lstat().st_uid != who["uid"]:
        raise Refusal("home must belong to the login user")
    return home


def private_regular(path, mode=None):
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_nlink != 1:
        raise Refusal(f"not a singly linked user-owned regular file: {path}")
    if mode is not None and stat.S_IMODE(s.st_mode) != mode:
        raise Refusal(f"unexpected private file mode: {path}")
    return s


def check_binary(path, expected_sha, arch):
    safe_ancestors(path.parent, os.getuid())
    private_regular(path)
    flags = os.O_RDONLY | os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags), "rb") as stream:
        s = os.fstat(stream.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_nlink != 1:
            raise Refusal("opened binary is not a singly linked user-owned regular file")
        if s.st_mode & 0o022 or not s.st_mode & stat.S_IXUSR:
            raise Refusal("binary must be executable and not group/world writable")
        if s.st_size > 256 * 1024 * 1024:
            raise Refusal("binary exceeds packaging size ceiling")
        data = stream.read(256 * 1024 * 1024 + 1)
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha:
        raise Refusal("approved binary SHA-256 mismatch")
    # Native thin 64-bit Mach-O executable only. Never invoke --version.
    if len(data) < 16:
        raise Refusal("expected a native Mach-O executable")
    magic, cpu, _, filetype = struct.unpack("<IIII", data[:16])
    cpus = {"arm64": 0x0100000C, "x86_64": 0x01000007}
    if magic != 0xFEEDFACF or cpu != cpus.get(arch) or filetype != 2:
        raise Refusal("expected a native thin 64-bit Mach-O executable for the approved architecture")
    return data


def inspect(argv, runner):
    # Do not inherit source, proxy, Python, shell or credential environment.
    try:
        return runner(argv, capture_output=True, text=True, timeout=10,
                      env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
                      check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refusal("ownership inspection unavailable or timed out") from None


def registered(uid, runner):
    result = inspect(["/bin/launchctl", "print", f"gui/{uid}/{LABEL}"], runner)
    if result.returncode == 0:
        return result.stdout
    # A generic failure is NOT proof that the label is absent.
    error = result.stderr + result.stdout
    if result.returncode == 113 and "Could not find service" in error and f'"{LABEL}"' in error:
        return None
    raise Refusal("could not establish exact launchd label ownership")


def listeners(runner):
    result = inspect(["/usr/sbin/lsof", "-nP", "-iTCP:7381", "-sTCP:LISTEN", "-Fpun"], runner)
    if result.returncode == 1 and not result.stdout.strip() and not result.stderr.strip():
        return []
    if result.returncode != 0 or result.stderr.strip():
        raise Refusal("could not establish listener ownership")
    pids = re.findall(r"^p([0-9]+)$", result.stdout, re.M)
    if not pids:
        raise Refusal("unrecognized listener ownership output")
    return sorted(set(int(x) for x in pids))


def port_bind_check():
    # Bind only, never listen, connect, accept, send or make a provider request.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 7381))
    except OSError:
        raise Refusal("loopback port 7381 is unavailable") from None


def absent(path):
    if os.path.lexists(path):
        raise Refusal(f"existing target, refusing to reuse or overwrite: {path}")


def private_write(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    opened = None
    try:
        opened = os.fstat(fd)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    except BaseException:
        # Do not unlink a replacement created by another actor during failure.
        try:
            current = path.lstat()
            if opened is not None and (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino):
                path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(fd)
    return opened.st_ino


class Creation:
    """Rollback only exact paths/inodes created by this invocation, never rmtree."""
    def __init__(self):
        self.files = []
        self.dirs = []

    def mkdir(self, path, exclusive=False):
        if not exclusive and path.exists():
            safe_ancestors(path, os.getuid())
            return
        self.mkdir(path.parent)
        path.mkdir(mode=0o700)  # Exclusive for each new ownership root.
        self.dirs.append((path, path.lstat().st_ino))

    def write(self, path, data, mode=0o600):
        self.mkdir(path.parent)
        inode = private_write(path, data, mode)
        self.files.append((path, inode))

    def rollback(self):
        failures = []
        for path, inode in reversed(self.files):
            try:
                if path.lstat().st_ino != inode:
                    raise OSError("changed identity")
                path.unlink()
            except OSError:
                failures.append(str(path))
        for path, inode in reversed(self.dirs):
            try:
                if path.lstat().st_ino != inode:
                    raise OSError("changed identity")
                path.rmdir()
            except OSError:
                failures.append(str(path))
        if failures:
            # Paths only. Never disclose file contents or subprocess output.
            print("Rollback retained paths requiring manual review: " + ", ".join(failures), file=sys.stderr)


def install(args, who, home, runner):
    if (args.expect_user, args.expect_host, args.expect_arch) != (who["user"], who["host"], who["arch"]):
        raise Refusal("expected user, hostname or architecture does not match this machine")
    if not re.fullmatch(r"[0-9a-f]{64}", args.sha256):
        raise Refusal("--sha256 must be the approved lowercase 64-character SHA-256")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", args.version):
        raise Refusal("--version must be a bounded release identifier, not executable arguments")
    if args.autostart_on_login and (args.no_autostart or not args.publish_launchagent):
        raise Refusal("autostart requires explicit --publish-launchagent and cannot accompany --no-autostart")
    data = clean_path(args.data_dir or home / "Library/Application Support/messenger-mcp-stuv2")
    if not data.is_relative_to(home) or data == home:
        raise Refusal("data directory must be a new directory inside the target user's home")
    stage = clean_path(args.stage_dir) if args.stage_dir else data / "launchd"
    if args.stage_dir and (not stage.is_relative_to(home) or stage == home or stage == data):
        raise Refusal("stage directory must be a separate new directory inside the user's home")
    agent = home / "Library/LaunchAgents" / f"{LABEL}.plist"
    staged = stage / f"{LABEL}.plist"
    binary = clean_path(args.binary)
    safe_ancestors(data.parent, who["uid"])
    safe_ancestors(stage.parent, who["uid"])
    safe_ancestors(agent.parent, who["uid"])
    absent(data)
    if args.stage_dir:
        absent(stage)
    absent(agent)  # Even staging must not hide an already-owned/conflicting label.
    payload = check_binary(binary, args.sha256, args.expect_arch)
    if registered(who["uid"], runner) is not None:
        raise Refusal("exact launchd label is already registered; no automatic replacement")
    if listeners(runner):
        raise Refusal("port 7381 has an existing listener; no process will be stopped")
    port_bind_check()
    installed_binary = data / "bin/messenger-mcp"
    plist = {"Label": LABEL, "ProgramArguments": [str(installed_binary), "serve", "--data", str(data)],
             "WorkingDirectory": str(data), "RunAtLoad": args.autostart_on_login,
             "KeepAlive": args.autostart_on_login, "ThrottleInterval": 10,
             "StandardOutPath": str(data / "logs/stdout.log"),
             "StandardErrorPath": str(data / "logs/stderr.log"), "Umask": 0o077}
    plist_bytes = plistlib.dumps(plist, sort_keys=True)
    plan = dict(state="dry-run" if args.dry_run else "staged", label=LABEL,
                user=who["user"], host=who["host"], arch=who["arch"], version=args.version,
                sha256=args.sha256, data_dir=str(data), staged_plist=str(staged),
                published_plist=str(agent) if args.publish_launchagent else None,
                autostart=args.autostart_on_login, listen=LISTEN,
                source="unpaired-capture-disabled", starts_service=False)
    if args.dry_run:
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0
    created = Creation()
    old_umask = os.umask(0o077)
    try:
        # Recheck write targets after preflight. Every leaf is exclusive-created.
        absent(data)
        if args.stage_dir:
            absent(stage)
        absent(agent)
        created.mkdir(data, exclusive=True)
        if args.stage_dir:
            created.mkdir(stage, exclusive=True)
        for child in ["bin", "logs", "uploads", "downloads", "launchd"]:
            created.mkdir(data / child)
        created.write(installed_binary, payload, 0o700)
        cfg = (f"MCP_TOKEN={secrets.token_hex(32)}\nINTERNAL_SECRET={secrets.token_hex(32)}\n"
               "READ_ONLY=true\nSYNC_ENABLED=false\nPAIRING_ENABLED=false\nLISTEN=127.0.0.1:7381\n")
        created.write(data / "secrets.env", cfg.encode())
        for name in ["stdout.log", "stderr.log"]:
            created.write(data / "logs" / name, b"")
        created.write(staged, plist_bytes)
        if args.publish_launchagent:
            created.write(agent, plist_bytes)
        receipt = dict(plan, schema=SCHEMA, uid=who["uid"],
                       plist_sha256=hashlib.sha256(plist_bytes).hexdigest())
        created.write(data / "install-receipt.json", (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode())
    except BaseException:
        created.rollback()
        raise
    finally:
        os.umask(old_umask)
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0


def status(args, who, home, runner):
    data = clean_path(args.data_dir or home / "Library/Application Support/messenger-mcp-stuv2")
    if not data.is_relative_to(home) or data == home:
        raise Refusal("status requires a private data directory inside the user's home")
    safe_ancestors(data, who["uid"])
    if stat.S_IMODE(data.lstat().st_mode) != 0o700:
        raise Refusal("data directory must be private mode 0700")
    receipt_path = data / "install-receipt.json"
    private_regular(receipt_path, 0o600)
    receipt = json.loads(receipt_path.read_text())
    if (receipt.get("schema"), receipt.get("label"), receipt.get("uid"), receipt.get("data_dir")) != (SCHEMA, LABEL, who["uid"], str(data)):
        raise Refusal("receipt is not bound to this user, label and data directory")
    binary = data / "bin/messenger-mcp"
    check_binary(binary, receipt["sha256"], who["arch"])
    staged = Path(receipt["staged_plist"])
    targets = [staged]
    if receipt["published_plist"]:
        agent = home / "Library/LaunchAgents" / f"{LABEL}.plist"
        if receipt["published_plist"] != str(agent):
            raise Refusal("receipt has an unexpected published plist path")
        targets.append(agent)
    for target in targets:
        if not target.is_relative_to(home):
            raise Refusal("plist is outside the target home")
        safe_ancestors(target.parent, who["uid"])
        private_regular(target, 0o600)
        if hashlib.sha256(target.read_bytes()).hexdigest() != receipt["plist_sha256"]:
            raise Refusal("plist differs from the install receipt")
    service = registered(who["uid"], runner)
    pids = listeners(runner)
    if service is None and pids:
        raise Refusal("listener exists without the owned registered service")
    if service is not None:
        # Exact launchd Program and pid, plus the listener's executable text image.
        if not re.search(r"^\s*program = " + re.escape(str(binary)) + r"\s*$", service, re.M):
            raise Refusal("registered label does not identify the installed binary")
        source = re.search(r"^\s*path = (.+?)\s*$", service, re.M)
        if source is None or source.group(1) not in [str(t) for t in targets]:
            raise Refusal("registered label is not loaded from a receipt-bound plist")
        arguments = re.search(r"^\s*arguments = \{\s*\n(.*?)^\s*\}", service, re.M | re.S)
        actual_args = [line.strip() for line in arguments.group(1).splitlines() if line.strip()] if arguments else []
        if actual_args != [str(binary), "serve", "--data", str(data)]:
            raise Refusal("registered service arguments do not match the private cold package")
        match = re.search(r"^\s*pid = ([0-9]+)\s*$", service, re.M)
        if pids:
            if match is None or pids != [int(match.group(1))]:
                raise Refusal("listener PID does not match the exact launchd service")
            image = inspect(["/usr/sbin/lsof", "-a", "-p", str(pids[0]), "-d", "txt", "-Fn"], runner)
            if image.returncode != 0 or image.stderr.strip() or f"n{binary}" not in image.stdout.splitlines():
                raise Refusal("listener executable cannot be bound to the installed binary")
    print(json.dumps(dict(label=LABEL, service="registered-owned" if service is not None else "not-registered",
                          listener="owned" if pids else "absent", binary_sha256=receipt["sha256"],
                          source="unpaired-capture-disabled configuration, live state not queried"), indent=2, sort_keys=True))
    return 0


def main(argv=None, runner=subprocess.run):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("install", help="create fresh private cold-readonly package, never start it")
    p.add_argument("--binary", required=True, help="parent-built approved native Mach-O binary")
    p.add_argument("--sha256", required=True, help="digest from the approved binary receipt")
    p.add_argument("--version", required=True, help="parent-attested release identifier, bound through the digest")
    p.add_argument("--expect-user", required=True)
    p.add_argument("--expect-host", required=True, help="exact socket.gethostname()")
    p.add_argument("--expect-arch", required=True, choices=["arm64", "x86_64"])
    p.add_argument("--data-dir")
    p.add_argument("--stage-dir", help="optional new private staging directory inside home")
    p.add_argument("--dry-run", action="store_true", help="same read-only preflight, deterministic plan, no writes or randomness")
    p.add_argument("--no-autostart", action="store_true", help="explicitly retain default dormant launchd configuration")
    p.add_argument("--publish-launchagent", action="store_true", help="also create exact user LaunchAgent file, never bootstrap")
    p.add_argument("--autostart-on-login", action="store_true", help="explicitly enable RunAtLoad/KeepAlive for published agent; never starts now")
    s = sub.add_parser("status", help="read-only exact-label/listener and binary/plist integrity, no secret or source reads")
    s.add_argument("--data-dir")
    args = parser.parse_args(argv)
    who = identity()
    home = user_home(who)
    if args.command == "install":
        return install(args, who, home, runner)
    return status(args, who, home, runner)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Refusal as error:
        # Only first-party validation text, never subprocess output or secrets.
        print(f"messenger-mcp packaging refused: {error}. No service was started.", file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError):
        # Do not echo untrusted file contents or subprocess text in a traceback.
        print("messenger-mcp packaging failed. Check private paths and the install receipt. No service was started.", file=sys.stderr)
        sys.exit(1)
