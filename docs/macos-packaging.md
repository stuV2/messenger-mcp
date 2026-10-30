# macOS packaging and operations

## Scope and prerequisites

This runbook packages a fresh cold-readonly service. It never connects Facebook, starts Matrix/bridge services or validates Marketplace triage. Only the deployment owner may activate the reviewed service after the final review and approved-binary receipt. Do not run the activation commands during an author/test pass.

Use the target login user, never root or `sudo`. Python must already exist. On the initial Apple-silicon target the interpreter is `/opt/homebrew/bin/python3.12`; another native macOS host may use another installed Python 3 path through `MESSENGER_PACKAGING_PYTHON`. Go is not a packaging prerequisite. The parent builds and reviews the executable separately without replacing system Go.

Before installation, bind the approved release identifier, SHA-256, source revision, target user, exact `socket.gethostname()` and architecture in the deployment receipt. `--version` is the parent's release attestation. The packager verifies the approved digest and native Mach-O architecture but intentionally never invokes an untrusted binary to ask its version. It is not a code-signature or dependency review.

Preflight checks the user/home binding, symlink-free safe parent directories, target conflicts, executable ownership/mode/digest/architecture, exact label absence and all TCP listeners on port 7381, including wildcard and IPv6 listeners. A bind probe also checks `127.0.0.1:7381` availability without listening. If launchctl/lsof inspection fails ambiguously, packaging refuses. It does not inspect or alter other service labels, read credentials, or use ports 7382/7383. A preflight cannot reserve the port until later activation; recheck ownership then.

## Dry-run

Use reviewed non-secret values. The binary must be a user-owned, singly linked native thin 64-bit Mach-O executable, not a wrapper script or universal binary. Parent directories must not be symlinks or group/world writable. Expected architecture is `arm64` or `x86_64`.

```sh
MESSENGER_PACKAGING_PYTHON=/opt/homebrew/bin/python3.12 \
  ./scripts/install-macos.sh install \
  --binary '/absolute/path/to/approved/messenger-mcp' \
  --sha256 APPROVED_LOWERCASE_SHA256 --version APPROVED_RELEASE_ID \
  --expect-user APPROVED_USER --expect-host APPROVED_EXACT_HOSTNAME --expect-arch arm64 \
  --no-autostart --dry-run
```

The JSON plan has no timestamps, random values or secrets. Repeating it with unchanged inputs produces identical output. It performs no writes and no network requests. It does run read-only exact-label `launchctl print` and `lsof` checks on a real host. Author tests replace those with fake runners; author validation must not invoke real launchctl.

## Stage or publish without starting

Remove `--dry-run` from the approved command to create the private package. With no publishing flag it writes the plist only under the private data directory. Optional `--stage-dir '/absolute/new/private/stage'` selects a separate, new staging directory within the target home. `--data-dir` may select a new private directory within that same home. No existing data directory, stage directory or exact LaunchAgent file is reused, even if empty. This is intentionally create-only, not an in-place upgrade.

The default package is dormant. Both `RunAtLoad` and `KeepAlive` are false. To publish an exact dormant LaunchAgent during this same installation, add `--publish-launchagent --no-autostart`. The installer writes no other label and calls no bootstrap, kickstart, bootout or kill command.

For a separately approved always-on installation, replace `--no-autostart` with `--publish-launchagent --autostart-on-login`. This deliberately writes `RunAtLoad=true` and `KeepAlive=true`. It still does not start anything during installation, but macOS may load the published agent on the next login. Do not request this flag before activation approval. A merely staged package is not promotable by rerunning the installer; preserve/archive that exact staging package first or choose a fresh data directory for the final installation. Do not casually copy or edit its plist because that breaks the receipt binding.

Generated layout, within the private data directory:

```text
bin/messenger-mcp                    0700, exact approved binary copy
secrets.env                          0600, private runtime configuration
install-receipt.json                 0600, non-secret install bindings
launchd/com.stuv2.messenger-mcp.plist 0600, default staged plist
logs/stdout.log                      0600
logs/stderr.log                      0600
uploads/                            0700, empty
downloads/                          0700, empty
```

The data directory and created subdirectories are 0700. New shared parent directories are also created with 0700, but existing safe shared directories are not chmodded. Published LaunchAgent mode is 0600. Both log files are precreated privately and launchd uses umask 077. No ledger, existing queue, provider credentials or account sessions are imported.

`secrets.env` contains independent random 32-byte MCP and internal tokens encoded as hex. Only `MCP_TOKEN` is needed for cold MCP access. The runtime reads configuration directly from this file. Its remaining exact keys are:

```text
READ_ONLY=true
SYNC_ENABLED=false
PAIRING_ENABLED=false
LISTEN=127.0.0.1:7381
```

There is no `MATRIX_PASSWORD` or `BRIDGE_PROVISIONING_SECRET`. Tokens never appear in installer output, command arguments, launchd environment or plist. Do not `cat` the secrets file, pass tokens as shell arguments, enable shell tracing, put them in URLs or commit them. Configure a future approved client with a private file/secret reader that constructs the Bearer header inside the process. Do not copy a token into chat. Same-user code can still read this file; permissions do not defend against compromise of the login account.

## Activation, deployment owner only

The final published installation must have passed independent review and binary transport acceptance. Set these path variables locally, they contain no secrets:

```sh
DATA="$HOME/Library/Application Support/messenger-mcp-stuv2"
PLIST="$HOME/Library/LaunchAgents/com.stuv2.messenger-mcp.plist"
DOMAIN="gui/$(id -u)"
SERVICE="$DOMAIN/com.stuv2.messenger-mcp"
```

If a custom data directory was approved, use that exact directory instead. First run the read-only status command below and confirm the executable/plist digests, absent label and absent listener. Any conflict stops activation, do not resolve it by killing another process. The launchd bootstrap target must be this user domain and the exact newly published plist.

```sh
# STATE CHANGES. Deployment owner executes these only after approval.
/bin/launchctl bootstrap "$DOMAIN" "$PLIST"
# Dormant plist only: explicitly start its one instance.
# Do not use -k, which would kill an existing instance.
/bin/launchctl kickstart "$SERVICE"
```

With `--autostart-on-login`, bootstrap already starts the agent; omit kickstart and verify instead. With `--no-autostart`, a kickstarted instance is not configured to restart after exit/login. Persistent deployment needs the deliberate autostart option at package creation, followed by restart/persistence acceptance by the owner.

After activation, status must bind the exact launchd program and PID to the listener and the installed executable text image. Separately exercise real HTTP/MCP authentication, limits, status/tool-list behavior and disabled mutation/pair/sync behavior. Prove that the binary makes no source requests before claiming a capture-disabled deployment. `/healthz` alone proves only process liveness. Do not connect an account or read messages for this acceptance.

## Read-only status

```sh
/opt/homebrew/bin/python3.12 -I -B scripts/install_macos.py status --data-dir "$DATA"
```

Status reads the install receipt, binary and plist, not tokens, message databases or provider state. It validates private paths/file modes and compares executable/plist digests with the receipt. For a loaded label it requires the exact binary program path; if a listener exists its PID must match launchd and its executable image must match the installed binary. Unknown ownership fails closed. A registered service without a listener is reported distinctly, it is not declared healthy.

The status output's capture-disabled wording describes the installed package intent, not verified runtime flags or Facebook readiness. Changing runtime configuration is outside this runbook and is not detected by this token-free status path. Use the owner's transport acceptance to verify effective policy. Status is not a hostile same-user process attestation.

For a manual investigation, inspect only the exact service and port, without stopping anything:

```sh
/bin/launchctl print "$SERVICE"
/usr/sbin/lsof -nP -iTCP:7381 -sTCP:LISTEN
```

Do not post raw logs or service output without review, even though this package keeps secrets out of the plist and argv.

## Uninstall and rollback without broad deletion

Automatic failure rollback removes only exact files/inodes created by that installer invocation, then removes its newly created empty directories. It never recursively deletes a data tree or stops services. On interruption or identity drift, it retains ambiguous paths for manual review. A power failure can leave a partial package, which the next run refuses rather than overwriting.

For an installed service, first run status and verify the exact label/binary/plist binding against the approved receipt. If identity has drifted, stop and investigate instead of booting out a potentially foreign service. Then the deployment owner can stop only the owned label:

```sh
# STATE CHANGE. Exact owned label only, after successful identity verification.
/bin/launchctl bootout "$SERVICE"
```

If it was never bootstrapped, do not bootout anything. A missing service is not a reason to use wildcard labels, `pkill`, `killall` or broad process matches. Verify `launchctl print "$SERVICE"` now reports that exact service missing and lsof reports no port-7381 listener. If another listener remains, investigate it without killing it.

Preserve the exact published plist and data directory in a private, operator-selected archive within the same home. Use a NEW archive directory and refuse existing destinations. Move only `$PLIST` after its digest/ownership verification. Retain `$DATA` intact as evidence and for recovery; if you need its original pathname for a fresh installation, move only that exact verified directory to a new private archive pathname after the service is stopped. Do not remove a whole LaunchAgents directory, old upstream services, unrelated logs, bridge/Synapse data or other users' files. No recursive deletion command is needed for rollback.

There is no automatic upgrade or old-queue migration. After the preceding stop/verification steps, an operator can preserve a published package with these exact-path moves. Pick a unique archive name and stop if any command fails. For a stage-only package, omit the plist move because no published plist belongs to it.

```sh
# STATE CHANGES. Only after exact ownership/digest checks and confirmed stop.
ARCHIVE="$HOME/messenger-mcp-rollback-APPROVED_UNIQUE_ID"
# The && chain stops before moves if the new archive cannot be created.
mkdir -m 700 "$ARCHIVE" && \
  mv "$PLIST" "$ARCHIVE/com.stuv2.messenger-mcp.plist" && \
  mv "$DATA" "$ARCHIVE/data"
```

To change versions, stop and archive this exact service, package a newly approved binary into a fresh directory, and repeat review/activation. To restore a previous package, independently verify its receipt and private modes, ensure its exact target path and the label/port are free, then restore only the verified exact archived paths and repeat acceptance. Restoring or enabling any paired/sync-enabled archive requires new source approval, it is not authorized by this cold-service rollback procedure.

## Test boundary

Run `scripts/test_install_macos.py` with Python's standard library and `PACKAGING_TEST_ROOT` set to an existing private task-owned scratch directory. Tests create isolated HOME fixtures, never read real credentials and inject fake launchctl/lsof responses. An audit hook rejects real subprocesses and socket bind/connect/send/name-resolution effects inside the test interpreter. It is an in-process guard, not an OS sandbox. Fixture binaries are inert header-shaped bytes, not production binaries.

Packaging regression receipts do not certify the Go binary, macOS launchd compatibility, restart persistence, live Facebook login or Marketplace support. Those remain separate deployment/source gates. The old optional upstream pins in `deploy/versions.env` are retained as provenance only and are never sourced by the installer.
