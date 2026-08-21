# Security Model

## Threat model

**What rutile defends against:**

| Threat | Defense |
|---|---|
| Secrets at rest read by anyone | age (X25519) encryption; the private key is itself scrypt-passphrase-encrypted |
| Other OS users on the machine | 0700 home dir, 0600 files and unix socket |
| An honest agent reading more than intended (bugs, prompt injection steering) | default-deny per-agent policy, TTL / one-time grants, read-only agents |
| Accidental direct disclosure by the broker | `rutile run -e` injects values without returning them; child output remains outside rutile's control |
| Sub-agent privilege creep | delegation is intersection-scoped, TTL-capped (24h), depth-1, dies with the parent |
| Accidental or unsophisticated history tampering | hash-chained audit log (`audit verify` pinpoints the broken seq); checkpoint-linked across rotations |
| Stolen agent token file | tokens are stored only as sha256; a leaked *token* is revocable (`agent revoke`), bounded by policy, can carry a hard expiry (`--expires`) and can be `--local-only` (rejected on the HTTP transport) |
| Network transport | non-loopback HTTP is refused without TLS (`--tls-cert/--tls-key`); `--insecure` requires an explicit flag; per-IP rate limiting on by default |
| Stolen bearer token on the network | optional mTLS (`--tls-client-ca`): no valid client certificate → no TLS session at all; `--spiffe-trust-domain` binds certificate-only identities to one explicit SPIFFE domain |
| Local process impersonating the human (system mode) | peer-credential check (SO_PEERCRED / LOCAL_PEERCRED): human ops only for `--admin-uid` and root |
| Long-lived key exposure | `rutile rotate` re-encrypts the store under a fresh identity, crash-safe (old key kept as `.bak` until verified) |

**What rutile does NOT defend against (by design — be honest with
yourself about these):**

- **Malicious code running under your own uid (default mode).** The unix
  socket trusts the uid: any process under the daemon owner's uid can act
  as the "human" caller. This is the ssh-agent/gpg-agent trust model.
  **System mode** (`--socket-mode 0660 --admin-uid N`, daemon under a
  dedicated uid) turns this into a real boundary: human-privileged calls
  are verified against kernel peer credentials, key files live under a uid
  agents don't have. Remaining gap: hardware-backed keys.
- **Un-leaking a served value.** `--one-time`/`--for` bound the window of
  access; a value already returned to a caller is out of our hands.
- **Child-process output and observation.** `rutile run` does not print a
  secret itself, but the launched program can print/log its environment.
  Argv injection is opt-in because argv may be visible through process listings
  and telemetry. rutile is not a sandbox or an output-DLP layer.
- **Memory forensics.** Go's GC does not guarantee zeroing; passphrases and
  plaintexts may persist in process memory until collected.
- **Plaintext metadata.** Secret *values* and the private key are always
  encrypted at rest (age / scrypt); tokens exist only as sha256. But
  *metadata* — secret path names, agent names, policy rules, audit entries —
  is plaintext on disk, same as pass/gopass (their filenames leak the same).
  Protected from other users by 0700/0600 modes. A "sealed metadata" mode is
  on the roadmap.
- **A compromised daemon binary.** Verify what you install.

## Design properties

- Agents authenticate with bearer tokens; only `sha256(token)` is persisted
  (`agents/*.yaml`, `delegations.yaml`), compared in constant time.
- Secret reads and listings are returned only after their audit entry is
  durably appended. Audit failure therefore blocks disclosure. Denied auth and
  policy decisions are also audited when the audit storage is available.
- In system mode, certificate identities arriving over the unix socket are
  accepted only from the daemon owner's uid (or root). Run the mTLS gateway as
  that dedicated uid; group socket members cannot forge SPIFFE assertions.
- Secret paths are validated against a strict charset (`[a-zA-Z0-9._@-]`
  segments) to exclude traversal; store writes are atomic
  (temp file + rename).
- Secret plaintext is capped at 512 KiB across CLI, daemon and imports. State,
  ciphertext, HTTP and Unix-RPC inputs are also bounded before allocation or
  expensive parsing.
- The daemon binds the socket with 0600 and refuses to start if another
  daemon owns it; stale sockets from crashes are detected by a dial probe.
- `edit` keeps its plaintext working copy inside the 0700 store home and
  best-effort shreds it afterwards; it never touches the shared temp dir.
- The store git repo never contains: plaintext secrets, tokens, the audit
  log, pending requests, or live delegations.

The hash chain is locally tamper-evident, not cryptographically anchored. A
writer who can replace the whole log can recompute it; export the final hash to
an independent append-only system if that attacker is in scope.

Rotation recovery files are never overwritten with different key material:
later rotations allocate `identities.age.bak-*`. These files remain encrypted
by their historical passphrases, but they are sensitive recovery material and
must follow an explicit retention and deletion policy.

## Audit status (v1.1.0)

- Full test suite passes under `go test -race`, including a stress test of
  concurrent reads/writes during key rotation.
- `FuzzValidatePath`: 15M+ executions asserting no accepted path can escape
  the store root.
- Agent-supplied strings (reasons/notes) are stripped of control characters
  before terminal display — ANSI escape injection into the operator's
  terminal is neutralized.
- gosec runs in CI. The excluded generic rules are explicitly bounded here:
  G204/G702 cover intentional argv-based execution without a shell (`rutile
  run`, `$EDITOR`, `git`, `gpg`); G304 covers paths selected by the same local
  user; G703's backup target is confined with `os.Root` and created with
  `O_EXCL`; G104 is limited to best-effort cleanup closes. These paths do not
  accept lower-privilege agent input for human operations.

## Reporting a vulnerability

Open a private report (GitHub security advisory once public, or contact the
maintainer directly). Please include reproduction steps. Do not open public
issues for unpatched vulnerabilities.
