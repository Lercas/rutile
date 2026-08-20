<p align="center">
  <img src="assets/banner.svg" alt="rutile — least-privilege secrets for AI agents" width="880">
</p>

<p align="center">
  <img alt="version" src="https://img.shields.io/badge/version-1.4.0-E8B84B?style=flat-square&labelColor=1A1713">
  <img alt="go" src="https://img.shields.io/badge/go-1.25-E8B84B?style=flat-square&labelColor=1A1713&logo=go&logoColor=EDE8DF">
  <img alt="platform" src="https://img.shields.io/badge/platform-macOS%20·%20Linux-9B937F?style=flat-square&labelColor=1A1713">
  <img alt="mcp" src="https://img.shields.io/badge/MCP-native-E8B84B?style=flat-square&labelColor=1A1713">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-9B937F?style=flat-square&labelColor=1A1713">
</p>

<p align="center">
  <b>English</b> · <a href="README.ru.md">Русский</a> · <a href="AGENTS.md">AGENTS.md</a> · <a href="SECURITY.md">SECURITY.md</a> · <a href="CHANGELOG.md">CHANGELOG</a>
</p>

A local secrets broker for humans **and multi-agent AI systems** — the
spiritual successor to `pass`/`passage`, rebuilt for a world where your
terminal has agents in it. Every secret an agent *sees* can be exfiltrated
through prompt injection; every static key in an MCP config is a leak
waiting to happen. rutile gives each agent its own identity, a default-deny
policy, bounded grants, an audit trail — and ways to use secrets without
ever putting them into an LLM context.


## Quick start

```bash
go install github.com/Lercas/rutile/cmd/rutile@latest

rutile init                        # once: pick a passphrase
rutile add dev/myproject/api-key   # store a secret
rutile show dev/myproject/api-key  # read it back
```

The daemon auto-starts on first use, prompts for your passphrase only when
locked, and wipes the key from memory after 30 idle minutes. Migrating is
one command: `rutile import passage`, `rutile import pass`, or
`rutile import env .env --prefix dev/myproject`.

## Connect an agent

```bash
rutile agent add claude --type claude-code   # prints the token once + a ready `claude mcp add` line
rutile allow claude "dev/**" --for 1h        # everything else stays denied
```

| MCP tool | What the agent gets |
|---|---|
| `get_secret` | a value; the optional `reason` lands in your audit log |
| `list_secrets` | only the paths its policy allows |
| `request_access` | files a request for you — no retry-looping a denial |
| `delegate_access` | a scoped, short-lived sub-token for a helper agent |
| `store_status` | locked? how many secrets visible? |

The full contract — errors, workflows, rules of conduct — lives in
[AGENTS.md](AGENTS.md). The repo doubles as a **Claude Code plugin**
(`.claude-plugin/` + skill + `/rutile:secrets-setup`), so Claude learns the
context-minimizing workflow automatically.

## The three ideas

**Default-deny policy, human in the loop.** Grants are globs with `--for`
TTLs and `--one-time` burns. A denied agent files a request; you run
`rutile requests` → `rutile approve <id>`. Every access — including every
denial — lands in a hash-chained audit log where a single flipped byte is
detected by `rutile audit verify`.

**Context-minimizing execution.** When a secret is only an *input* to a
command, rutile can inject it without returning the value itself:

```bash
rutile run -e STRIPE_KEY=dev/stripe/sk_test -- ./deploy.sh
rutile run --allow-argv-secrets -- deploy --token {{rutile:deploy/token}}
```

The value is absent from the command text and shell history. This is not an
exfiltration boundary: the child process can still print or log its environment.
Environment injection is preferred; argv substitution is disabled unless the
caller explicitly accepts process-list and telemetry exposure with
`--allow-argv-secrets`.

Secret values are limited to **512 KiB**. Use rutile for credentials and small
configuration values, not datasets or general-purpose blobs.

**Delegation that shrinks.** An orchestrator mints sub-tokens for helpers:
a child's access is *its patterns ∩ the parent's live policy*, TTL-capped at
24h, depth 1. Restrict or revoke the parent — every child dies instantly.

```bash
rutile delegations              # who minted what, until when
rutile delegations revoke <id>
```

## Architecture

<p align="center">
  <img src="assets/architecture.svg" alt="Clients (CLI, MCP stdio, MCP HTTP) talk to the rutile daemon over a 0600 unix socket; the daemon holds policy, delegation, audit and the decrypted age key in memory; disk files are encrypted or secret-free" width="880">
</p>

One binary, three roles: the CLI, the daemon (auto-spawned; launchd/systemd
units in [`contrib/`](contrib)), and the MCP server (stdio + streamable
HTTP). The wire protocol is newline-delimited JSON over a unix socket.
Everything at rest is age-encrypted or secret-free (tokens exist only as
sha256), and the store is a git repo — `rutile git push` syncs it anywhere.

## Running on a dedicated host

```bash
rutile mcp --http 0.0.0.0:7997 --tls-cert cert.pem --tls-key key.pem
```

- non-loopback without TLS is **refused** (explicit `--insecure` only inside
  an SSH tunnel / WireGuard);
- per-IP rate limiting on by default; `--tls-client-ca` enables **mTLS**,
  and `--spiffe-trust-domain <domain>` allows a matching SPIFFE URI SAN
  `spiffe://<domain>/agent/<name>` to authenticate the agent with **no bearer
  token at all** (SPIRE-compatible). Without the trust-domain flag, mTLS still
  verifies the client certificate but Bearer authentication remains required;
- token hygiene per agent: `--type`, `--expires 30d`, `--local-only`
  (rejected on the HTTP transport even if leaked);
- **system mode** makes the boundary real: `rutile daemon --socket-mode 0660
  --admin-uid <uid>` under a dedicated user — human-privileged calls are
  verified against kernel peer credentials. The mTLS gateway must run as the
  daemon owner; certificate assertions from other socket peers are rejected.

Ready-to-adapt system units live in [`contrib/`](contrib): install
`rutile-daemon@.service` as `rutile-daemon@<admin-uid>.service`, then run the
HTTPS gateway from `rutile-mcp.service` under the same dedicated `rutile` uid.

Key rotation keeps the first distinct recovery key as `identities.age.bak` and
uses timestamped `identities.age.bak-*` files for later distinct rotations. The
CLI prints the exact recovery path; test the new key before deleting any copy.

## Works where your agents work

| | |
|---|---|
| **MCP stdio** | Claude Code, Claude Desktop, Cursor, Windsurf, Zed, Cline / Roo Code, Continue |
| **MCP HTTP** | OpenAI Agents SDK, LangChain / LangGraph, CrewAI, AutoGen, custom orchestrators — Bearer or mTLS/SPIFFE |
| **Runs on** | macOS, Linux, Docker, systemd / launchd, GitHub Actions |
| **No MCP at all** | any process via `rutile run` — the broker need not return the value directly |

## Honest security model

Policy is guardrails for honest agents plus an audit trail — in default
mode any process under *your* uid can bypass it (the ssh-agent trust
model); system mode turns that into a kernel-enforced boundary. TTLs bound
exposure windows but cannot un-leak a served value. Metadata (paths, agent
names, rules) is plaintext on disk, like pass/gopass. The full threat model
— what we defend against, what we deliberately don't — is in
[SECURITY.md](SECURITY.md).

## Development

```bash
make test          # unit + integration (race-clean, incl. rotation stress)
make test-linux    # the same suite in Docker
make smoke         # 25-step end-to-end scenario, mTLS and rate limits included
make release-check # everything that must be green before a release
make site          # build the landing page (site/, Astro)
```

A `v*` tag triggers the GitHub release workflow. It builds four platform
archives plus a source archive, emits a CycloneDX SBOM for every binary archive
and `checksums.txt`, then asks GitHub to attest provenance for those artifacts.
This configuration is not evidence that a public or signed release has been
published; verify the release page and attestations directly.

## Roadmap

TLS-intercepting credential-injecting proxy (the agent doesn't see the
secret even as a placeholder) · hardware-backed keys (Secure Enclave) ·
sealed-metadata mode · homebrew tap.

---

<p align="center">
  <img src="assets/logo.svg" width="36" alt=""><br>
  <sub><code>© rutile contributors · MIT</code></sub>
</p>
