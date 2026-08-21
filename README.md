<p align="center">
  <img src="assets/banner.svg" alt="rutile: least-privilege secrets for AI agents" width="880">
</p>

<p align="center">
  <img alt="version" src="https://img.shields.io/badge/version-1.4.0-E8B84B?style=flat-square&labelColor=1A1713">
  <img alt="go" src="https://img.shields.io/badge/go-1.25-E8B84B?style=flat-square&labelColor=1A1713&logo=go&logoColor=EDE8DF">
  <img alt="platform" src="https://img.shields.io/badge/platform-macOS%20·%20Linux-9B937F?style=flat-square&labelColor=1A1713">
  <img alt="mcp" src="https://img.shields.io/badge/MCP-native-E8B84B?style=flat-square&labelColor=1A1713">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-9B937F?style=flat-square&labelColor=1A1713">
</p>

<p align="center">
  <b>English</b> · <a href="README.ru.md">Русский</a> · <a href="https://lercas.github.io/rutile-site/">Website</a> · <a href="AGENTS.md">AGENTS.md</a> · <a href="SECURITY.md">SECURITY.md</a> · <a href="CHANGELOG.md">CHANGELOG</a>
</p>

Rutile is a local secrets broker for people and AI agents. It stores encrypted
values, gives each agent a separate identity, and applies a default-deny access
policy. Temporary grants, access requests, delegation, and an audit log make
agent access explicit and reviewable.

## Quick start

```bash
go install github.com/Lercas/rutile/cmd/rutile@latest

rutile init
rutile add dev/myproject/api-key
rutile show dev/myproject/api-key
```

The daemon starts on first use. It asks for the passphrase when the store is
locked and removes the decrypted key from memory after 30 idle minutes.

Existing data can be imported from passage, pass, or an environment file:

```bash
rutile import passage
rutile import pass
rutile import env .env --prefix dev/myproject
```

## Connect an agent

```bash
rutile agent add claude --type claude-code
rutile allow claude "dev/**" --for 1h
```

The first command prints the token once. Store it in the agent environment as
`RUTILE_TOKEN`; do not put it in source files or logs. Access that is not
explicitly allowed remains denied.

| MCP tool | Purpose |
|---|---|
| `get_secret` | Read an allowed value and optionally record a reason |
| `list_secrets` | List only paths visible to the agent |
| `request_access` | Submit an access request for human review |
| `delegate_access` | Create a scoped, short-lived token for a helper |
| `store_status` | Check the lock state and visible path count |

[AGENTS.md](AGENTS.md) documents the complete MCP contract and error handling.
The repository also includes a Claude Code plugin in `.claude-plugin/`.

## Access control and delegation

Grants support glob patterns, expiry with `--for`, and one-time use with
`--one-time`. Review denied requests with `rutile requests`, then use
`rutile approve <id>` or `rutile reject <id>`.

Every access decision is written to a hash-chained audit log. Run
`rutile audit verify` to detect edits or removed records. The chain is
tamper-evident, but a
user who can rewrite the whole log can also recalculate it. Export checkpoints
to an external append-only system when that threat matters.

Delegated tokens are limited to the intersection of their patterns and the
parent's current policy. Their maximum lifetime is 24 hours and delegation
depth is one. Revoking or restricting the parent immediately affects its
children.

```bash
rutile delegations
rutile delegations revoke <id>
```

## Run commands with secrets

Use environment injection when a command needs a secret but the caller does
not need the value:

```bash
rutile run -e STRIPE_KEY=dev/stripe/sk_test -- ./deploy.sh
rutile run --allow-argv-secrets -- deploy --token {{rutile:deploy/token}}
```

Environment injection keeps the value out of the command text and shell
history. It is not a data-loss prevention boundary: the child process can still
print or log its environment. Argument substitution is disabled by default
because arguments may appear in process listings and telemetry.

Secret values are limited to **512 KiB**. Use rutile for credentials and small
configuration values, not datasets or arbitrary blobs.

## Architecture

<p align="center">
  <img src="assets/architecture.svg" alt="Rutile clients connect to the daemon through a Unix socket" width="880">
</p>

The single binary provides a CLI, a daemon, and an MCP server. MCP is available
over stdio and streamable HTTP. Local components use newline-delimited JSON over
a Unix socket. Values and the private identity are encrypted with age. Tokens
are stored only as SHA-256 hashes. The store is a Git repository and can be
synchronized with `rutile git push`.

Supported clients include Claude Code, Claude Desktop, Cursor, Windsurf, Zed,
Cline, Roo Code, Continue, OpenAI Agents SDK, LangChain, LangGraph, CrewAI,
AutoGen, and custom MCP clients.

## Dedicated host

```bash
rutile mcp --http 0.0.0.0:7997 --tls-cert cert.pem --tls-key key.pem
```

Non-loopback HTTP requires TLS. Use `--insecure` only inside a protected SSH or
WireGuard tunnel. Per-IP rate limiting is enabled by default.

Use `--tls-client-ca` for mTLS. Adding `--spiffe-trust-domain <domain>`
permits token-free authentication for a matching URI SAN:
`spiffe://<domain>/agent/<name>`. Without that option, mTLS verifies the
client certificate but still requires a bearer token.

For a shared host, run the daemon under a dedicated account:

```bash
rutile daemon --socket-mode 0660 --admin-uid <uid>
```

System mode checks human operations against kernel peer credentials. The mTLS
gateway must run as the daemon owner. Service templates are in
[`contrib/`](contrib). Install `rutile-daemon@.service` as
`rutile-daemon@<admin-uid>.service`, and run `rutile-mcp.service` under the
same dedicated user.

Key rotation preserves recovery copies as `identities.age.bak` and
`identities.age.bak-*`. Test the new key before deleting any recovery copy.

## Security boundaries

In the default mode, policy controls well-behaved agents and records their
actions. Any process running under your user account can access the daemon with
your privileges and bypass agent policy. System mode moves that boundary to a
dedicated operating-system account.

Expiry limits future access but cannot retract a value already returned.
Secret paths, agent names, and policy rules remain plaintext on disk. Go does
not guarantee that secret bytes are immediately cleared from memory. See
[SECURITY.md](SECURITY.md) for the full threat model.

## Development

```bash
make test          # unit and integration tests with the race detector
make test-linux    # run the test suite in Docker
make smoke         # end-to-end checks, including mTLS and rate limiting
make release-check # run all release checks
```

The website source and its build instructions are maintained in
[`Lercas/rutile-site`](https://github.com/Lercas/rutile-site).

A `v*` tag starts the release workflow. It builds platform and source archives,
CycloneDX SBOMs, checksums, and GitHub provenance attestations. Workflow
configuration alone does not prove that a public or signed release exists.
Check the release page and attestations directly.

## License

MIT

<p align="center">
  <img src="assets/logo.svg" width="36" alt=""><br>
  <sub><code>© rutile contributors · MIT</code></sub>
</p>
