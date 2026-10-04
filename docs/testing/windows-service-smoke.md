# Native Windows CLI and MCP verification

The `Windows CLI and MCP smoke` workflow builds both service binaries from its
own checkout on `windows-2022`. It tests default CLI/MCP features plus
`dbx-mcp/os-keyring` in the development profile. The log records the checked-out
commit, feature selection, exact binary SHA-256 digests and AMD64 PE checks.
This is service-binary coverage, not a desktop installer, signature, updater,
release-optimization or database-driver compatibility certification.

The workflow has read-only repository permission. It neither consumes a
historical workflow artifact nor publishes packages, releases, container images
or mirror updates. No repository-specific branch, account, run ID or source SHA
is embedded. For pull requests the recorded checkout may be GitHub's test merge
commit; push runs verify the actual pushed head.

## Protocol smoke script

With trusted binaries built from a reviewed source revision:

```powershell
python -m pip install -r scripts/remote-mcp-requirements.txt
cargo build --locked -p dbx-cli -p dbx-mcp --features dbx-mcp/os-keyring
python scripts/verify-remote-mcp-artifact.py target/debug/dbx-mcp.exe target/debug/dbx.exe --require-windows-amd64
```

The same script accepts local Linux/macOS binaries without
`--require-windows-amd64`. It never downloads or chooses an executable itself.
The OAuth checks depend on authenticated remote MCP support and the CLI check
requires saved-connection listing.

Each invocation creates a disposable profile, home/config/data directories, a
random data-key file, an in-memory RSA signing key and local JWKS/config files.
Inherited `DBX_*` settings are removed case-insensitively. The HTTP server listens
on loopback; the client ignores system HTTP proxies. Issuer/resource names use
reserved `.test` domains, with no remote issuer discovery. The explicit data-key
file prevents application OS-keyring access, including in keyring-enabled builds.
The script lists an empty profile and never connects to a database.

Checks include:

- CLI empty-profile output, stdio initialization, tool listing and EOF shutdown
- HTTP metadata, authenticated initialization, tool listing and empty-profile call
- Missing, malformed, wrong-signature, expired, wrong-issuer and wrong-audience token rejection
- Disallowed subject/scope, cross-owner session access, foreign Origin and body limits
- Session DELETE and invalidation, bounded process cleanup, and synthetic token redaction

On Windows, the HTTP process is terminated only after session deletion; this does
not claim a graceful Windows console-control shutdown. On POSIX, SIGINT must exit
cleanly. Failure paths reap children before deleting fixture directories. Child
logs are private temporary files and are never printed or uploaded. Successful
JSON output contains checks and binary hashes, not tokens or profile contents.
Checks remain enabled under `python -O`.

## Native keyring fixture

```powershell
cargo test --locked --manifest-path tools/keyring-fixture/Cargo.toml
cargo run --locked --manifest-path tools/keyring-fixture/Cargo.toml
```

This separate, unpublished test crate exercises the same `keyring` 3.6.3 native
Windows backend. It addresses only service `org.dbx.ci.synthetic-keyring` and a
unique process/time-specific synthetic user. It never enumerates credentials or
uses DBX's real service/user names. An existing entry is left untouched and fails
the check. Once the fresh-name check succeeds, every subsequent return attempts
cleanup, including a potentially partial write. Success requires exact roundtrip,
explicit deletion and verified absence. No credential value or backend error is
printed.

An unavailable Windows backend fails the run. Non-Windows execution reports
`unsupported` with exit code 2; cross-platform CI runs the injected-backend unit
tests there, not a misleading native success. An abruptly killed runner or process
cannot guarantee destructor execution, so prefer disposable CI user accounts.
The fixture verifies backend availability, not migration of a real desktop key
or application credential permissions.

## Offline verifier regressions

```sh
python scripts/verify-remote-mcp-artifact.test.py -v
python -O scripts/verify-remote-mcp-artifact.test.py
cargo test --locked --manifest-path tools/keyring-fixture/Cargo.toml
```

These tests drive parsing, environment isolation, signature validity, binary
manifests, log redaction and real subprocess cleanup. Credential failure cases
use an injected backend and do not access a local keyring.
