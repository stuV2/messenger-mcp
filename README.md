# messenger-mcp, stuV2 fork

A hardened experimental MCP adapter derived from [0xjesus/messenger-mcp](https://github.com/0xjesus/messenger-mcp). Fork: [stuV2/messenger-mcp](https://github.com/stuV2/messenger-mcp). The Go module path still uses the upstream identity to avoid an unrelated module migration.

The supported initial deployment is a **real authenticated local MCP HTTP service, unpaired and capture-disabled**. It is not a verified Facebook or Marketplace reader. Building, packaging or starting this cold service does not establish live account compatibility, inbox completeness, listing identity or privacy-compatible message triage.

## Safe initial configuration

| Setting | Packaged value |
|---|---|
| MCP endpoint | `http://127.0.0.1:7381/mcp` |
| Caller authentication | Distinct random `MCP_TOKEN`, loaded from a private file |
| `READ_ONLY` | `true` |
| `SYNC_ENABLED` | `false` |
| `PAIRING_ENABLED` | `false` |
| Source account | None, unpaired |
| Data directory | `~/Library/Application Support/messenger-mcp-stuv2` |
| Only owned launchd label | `com.stuv2.messenger-mcp` |

The cold service requires no Matrix password or bridge secret. It must not connect a provider, sync, backfill, pair an account, run an outbox worker or replay an inherited send queue. Packaging uses a fresh directory and refuses existing data rather than importing an old ledger. Read-only is not the same as capture-disabled; these are independent controls and must remain set as shown.

The intended default MCP tool set is limited to status and metadata discovery, without message previews or mutation tools. Body retrieval, attachment acquisition, sending and read receipts are not permission granted by installing the service. Final binary behavior must pass the transport acceptance tests before deployment. A process health response alone is not that proof.

## macOS packaging

Requires an existing Python 3 installation, native macOS user session and a separately reviewed, parent-built native Mach-O binary. The installer does not build, download or install anything. No `pip`, Go toolchain, Synapse, mautrix bridge, SSH, tunnel, `caffeinate` or source login is involved.

Use [the macOS runbook](docs/macos-packaging.md) for exact preflight, dry-run, staging, activation, status and rollback instructions. The installer never bootstraps or starts a service, including when asked to publish its single LaunchAgent file. Autostart is off unless explicitly requested. Do not pipe an Internet installer into a shell.

For a deterministic, read-only preflight, replace the non-secret approval placeholders below with values from the build/review receipt. Confirm the exact target hostname independently before approving it.

```sh
MESSENGER_PACKAGING_PYTHON=/opt/homebrew/bin/python3.12 \
  ./scripts/install-macos.sh install \
  --binary '/absolute/path/to/reviewed/messenger-mcp' \
  --sha256 APPROVED_LOWERCASE_SHA256 --version APPROVED_RELEASE_ID \
  --expect-user YOUR_LOGIN_USER --expect-host APPROVED_EXACT_HOSTNAME --expect-arch arm64 \
  --no-autostart --dry-run
```

Dry-run performs only local identity, file, launchd-label and listener checks. It does not write files, generate randomness, execute the supplied binary or make network requests. A temporary bind probe does not listen or connect. Existing conflicting files, any listener on port 7381 or an already registered exact label cause refusal. It never stops an unrelated process or overwrites existing configuration.

## Privacy limits and source approval

The original architecture uses Synapse and mautrix-meta to mirror Messenger into a local ledger. That is not metadata-first source acquisition. Filtering a mirrored archive later does not undo broad body capture. A future bridge can persist account cookies, native sessions and access tokens. Matrix and this application's ledger/media can retain plaintext copies; OS file permissions are not encryption or downstream erasure.

Pairing and source access need a separate account-owner decision and privacy/source review. Keep existing privacy holds in place. Do not enable sync or pairing just to see whether login works. No source-login command is included in the safe installation path. An MCP token authorizes access to this daemon, not permission to connect an account or read private messages.

The old bridge installer/configurator is retired. Historical optional upstream pins remain in `deploy/versions.env` for future review only. They are not installed, approved as current dependencies, or proof of live compatibility. Old upstream design documents under `docs/superpowers/` describe historical plans, not this fork's deployment policy.

## Verification

Packaging regressions use the Python standard library, isolated homes and temporary fixtures, fake launchctl/lsof responses, and an in-process guard against real subprocesses or socket effects:

```sh
# Use an operator-selected private scratch directory, not a credential directory.
PACKAGING_TEST_ROOT='/absolute/path/to/private/test-scratch' \
  /opt/homebrew/bin/python3.12 -I -B scripts/test_install_macos.py
```

Create that scratch directory first with mode 0700. These are packaging tests, not Go transport acceptance or live Facebook verification. The supplied fixture binaries are inert Mach-O-shaped bytes and are never executed. The real approved binary, exact native listener, authenticated MCP behavior and restart persistence need separate deployment acceptance by the deployment owner.

## License and provenance

MIT, see `LICENSE`. Upstream baseline: `9413e44e80bb98cf8d80324140e7083a4e07497d`. The optional, separately distributed mautrix-meta bridge is AGPL-3.0; this packaging does not install or link it. Review its obligations before any future distribution.
