# Changelog

## Unreleased

### Security
- Fail closed when an audit entry or one-time consumption cannot be persisted;
  concurrent one-time reads now disclose the value exactly once.
- Accept SPIFFE certificate assertions over IPC only from the daemon owner or
  root, closing a system-mode group-socket impersonation path.
- Make argv secret substitution opt-in with `--allow-argv-secrets`; document
  that child output and telemetry remain outside rutile's control.
- Replace security-state files with durable unique-temp + fsync + rename writes,
  reject symlink/non-regular state files, and confine store I/O with `os.Root`.
- Bound HTTP headers and bodies, Unix RPC fields, secret plaintext (512 KiB),
  passphrases, encrypted/state files, agent metadata, paths, reasons,
  policy/delegation patterns and request/delegation counts.
- Require a configured SPIFFE trust domain for certificate-only authentication;
  bind the URI identity to the asserted agent name and trusted local gateway.
- Fail closed on partial `RUTILE_AGENT`/`RUTILE_TOKEN` environments and prefer
  permanent policy grants over one-time rules regardless of creation order.

### Reliability
- Rotate keys through a crash-safe dual-recipient transition, then remove the
  old recipient in a second pass; preserve distinct recovery identities in
  non-overwriting, versioned `.bak-*` files and report the exact path.
- Preserve pending access requests when approval TTL validation or policy
  persistence fails.
- Rotate audit logs by durably copying the archive before atomically replacing
  the active chain, so checkpoint failure leaves the original log appendable.
- Add dedicated systemd system-mode and mTLS gateway units, release automation,
  archive SBOMs, source bundles, build-provenance attestations, and regression
  coverage for peer credentials, delegation, requests and concurrent writes.
- Update the static site to Astro 7 and resolve the dependency audit findings.

## 1.4.0 — 2026-08-20

Hardening: everything from the network-security roadmap.

### Added
- **Per-IP rate limiting** on the HTTP transport (`--rate-limit`, default
  120 req/min, burst half; 429 beyond).
- **mTLS** (`--tls-client-ca`): verified client certificates required; a
  SPIFFE URI SAN `spiffe://<domain>/agent/<name>` authenticates the agent
  with no bearer token (SPIRE-compatible), still subject to policy,
  local-only and expiry checks.
- **System mode**: `rutile daemon --socket-mode 0660 --admin-uid N` — the
  daemon can run under a dedicated uid; human-privileged operations are
  gated by kernel peer credentials (SO_PEERCRED / LOCAL_PEERCRED), making
  the privilege boundary real instead of guardrails.

## 1.3.0 — 2026-08-19

Network deployment and token hygiene.

### Added
- **Native TLS for the HTTP transport**: `rutile mcp --http ... --tls-cert
  --tls-key`; a non-loopback bind without TLS is now refused unless
  `--insecure` is passed explicitly. Dedicated-host deployment documented.
- **Token metadata**: `rutile agent add --type <kind> --expires 30d
  --local-only`. Expiry hard-kills the token; local-only tokens are rejected
  on the HTTP transport (and at the HTTP door) even if leaked; delegated
  sub-tokens inherit the parent's constraints. Shown in `agent list`.
- Agent compatibility matrix and internal-encryption boundaries documented
  (README, SECURITY.md).

## 1.2.0 — 2026-08-19

### Changed
- **Project renamed: protolith → rutile.** Rutile is the mineral with the
  highest refractive index — short, readable, and collision-free on GitHub.
- **BREAKING**: binary `rutile`, home dir `~/.rutile`, env vars `RUTILE_DIR`
  / `RUTILE_SOCKET` / `RUTILE_AGENT` / `RUTILE_TOKEN`, token prefixes
  `rtl_` / `rtl_d_`, placeholders `{{rutile:path}}`, plugin commands
  `/rutile:*`. Migration from a protolith install: `mv ~/.protolith
  ~/.rutile`, re-issue agent tokens (`rutile agent add …`), update MCP
  configs and env vars. Old `ptl_` tokens are not recognized.

## 1.1.0 — 2026-08-19

Product-completeness release: migration, diagnostics, docs, Claude Code
plugin, deep testing and a security pass.

### Added
- **Import**: `rutile import passage` (age), `import pass` (gpg),
  `import env` (dotenv) — one-command migration from every incumbent.
- **`rutile doctor`** — installation health check (permissions, daemon,
  audit chain, git, leftovers).
- **Claude Code plugin**: `.claude-plugin/` + `.mcp.json` + `skills/rutile`
  skill + `/rutile:secrets-setup` and `/rutile:secrets-status`
  commands — installing the plugin wires the MCP server and teaches the
  agent the zero-expose workflow automatically.
- Docs: English `README.md` (with language switch to `README.ru.md`),
  `AGENTS.md` (full agent contract), `SECURITY.md` (threat model),
  MIT `LICENSE`, CI workflow, goreleaser config, launchd/systemd units
  in `contrib/`.

### Fixed
- **Race**: key rotation now takes an exclusive lock against secret
  reads/writes — a concurrent `get` can no longer pair the old key with a
  freshly re-encrypted file (found by the new stress test).
- Terminal escape injection: agent-supplied reasons/notes are sanitized
  before display.

### Testing
- `go test -race` across the suite; concurrency stress test; daemon
  restart persistence test; kill -9 crash-recovery, full MCP stdio session
  and dotenv import in the smoke suite; `FuzzValidatePath` (15M+ execs).

## 1.0.0 — 2026-08-19

Первый стабильный релиз. Позиционирование: локальный secrets-брокер для
мультиагентных AI-систем.

### Добавлено
- **Делегирование суб-агентам**: агент выпускает scoped суб-токен
  (`delegate_access` в MCP, метод `delegate` в протоколе); доступ ребёнка =
  его паттерны ∩ живая политика родителя; TTL до 24ч; глубина 1;
  `rutile delegations [revoke]`.
- **Zero-expose запуск**: `rutile run -e VAR=path -- cmd`,
  плейсхолдеры `{{rutile:path}}` в аргументах; значения минуют контекст
  LLM и shell history.
- **Ротация ключа**: `rutile rotate` — новый identity, перешифровка
  всего store, crash-safe порядок с `identities.age.bak`;
  `rutile backup <dir>`.
- **Ротация аудита**: `rutile audit rotate` — архив + новая цепочка,
  связанная checkpoint-записью с финальным хэшем старой.
- Версия через ldflags; `make test-linux` (Docker), `make release-check`.

### Базовая функциональность (0.x)
- age-шифрованное pass-style хранилище, git-версионирование, авто-коммиты.
- Демон-брокер (ssh-agent-модель): авто-спавн, авто-unlock, idle auto-lock.
- Агенты: токены (хранится sha256), политики-глобы с `--for`/`--one-time`,
  read-only доступ, MCP stdio + streamable HTTP (Bearer), reason в аудите.
- Human-in-the-loop: `request_access` → `rutile requests/approve/reject`.
- Tamper-evident аудит (hash-цепочка), `audit verify`.
