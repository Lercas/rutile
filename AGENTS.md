# rutile — Agent Guide

This file is the contract for AI agents (and their developers) using
rutile as an MCP server. If you are an agent reading this: follow the
workflows below exactly — they are designed so you never need to guess.

## Connecting

**stdio (Claude Code and most MCP clients):**

```json
{
  "mcpServers": {
    "rutile": {
      "command": "rutile",
      "args": ["mcp"],
      "env": {
        "RUTILE_AGENT": "<your-agent-name>",
        "RUTILE_TOKEN": "rtl_..."
      }
    }
  }
}
```

**HTTP (frameworks without stdio, remote agents over an SSH tunnel):**

```
POST http://127.0.0.1:7997        (server: rutile mcp --http 127.0.0.1:7997)
Authorization: Bearer rtl_<token>
```

The token identifies you. It is shown to the human exactly once at
`rutile agent add <name>`. Never print it into logs, files, or chat.

## Tools

### get_secret

```
input:  { "path": "dev/myproject/api-key", "reason": "deploying to staging" }
output: { "value": "..." }
```

- `reason` is optional but **strongly encouraged** — it is written to the
  human's audit log and builds trust in you.
- Errors you will see:
  - `policy_denied` — you may not read this path. **Do not retry.** Either
    call `request_access`, or relay the error's instruction to the user
    (it contains the exact `rutile allow ...` command).
  - `locked` — the store is locked. Ask the user to run `rutile unlock`
    in a terminal, then retry once.
  - `not_found` — no secret at that path. Check `list_secrets` first.
  - `invalid_token` — your token is revoked or expired. Stop and tell the user.

### list_secrets

```
input:  { "prefix": "dev" }        (prefix optional)
output: { "paths": ["dev/a", "dev/b/c"] }
```

Returns **only** paths your policy allows. An empty list means you have no
grants yet — not that the store is empty.

### request_access

```
input:  { "path": "prod/db-password", "reason": "needed for the migration task" }
output: { "id": "a1b2c3d4", "status": "pending", "message": "..." }
```

Files a request for the human to review. Returns immediately — **do not
poll**. Tell the user: *"I requested access to `prod/db-password`
(id a1b2c3d4). Review with `rutile requests`, then I'll retry."* A
duplicate request for the same path returns the same id.

### delegate_access

```
input:  { "label": "worker-1", "patterns": ["dev/build/**"], "ttl": "30m" }
output: { "id": "…", "token": "rtl_d_…", "expires_at": "…" }
```

Mints a sub-token for a helper agent. Rules:

- the child can read only *its patterns ∩ your current policy*;
- it cannot delegate further, cannot file requests;
- max ttl 24h (default 1h); it dies with your token.

Hand the token to the sub-agent via its `RUTILE_TOKEN` environment —
**never through shared conversation context**. Prefer the narrowest
patterns and shortest ttl that let the sub-agent finish its task.

### store_status

```
output: { "unlocked": true, "visible_secrets": 5 }
```

Cheap. Call it before bothering the user about unlocking.

## Using secrets without direct broker disclosure (preferred)

If you only need a secret inside a command — not its value — run the
command through `rutile run` in your shell instead of calling `get_secret`.
Rutile itself then returns no secret value:

```bash
rutile run -e API_KEY=dev/svc/key -- sh -c 'curl -H "X-Key: $API_KEY" https://api.example.com'
rutile run --allow-argv-secrets -- deploy --token {{rutile:deploy/token}}
```

With `RUTILE_AGENT`/`RUTILE_TOKEN` in your environment this resolves through
your policy, exactly like `get_secret` — including audit. Prefer `-e` env
injection: rutile does not return the value itself, but the child process can
still print or log its environment. Argv placeholders require the explicit
`--allow-argv-secrets` risk acknowledgement because argv may be visible in
process listings and telemetry.

## Rules of conduct

1. Ask for the narrowest path, not `**`.
2. Always pass `reason` — the human reads it in their audit log.
3. On `policy_denied`: one `request_access`, then wait for the human. Never
   retry-loop a denial.
4. Never echo secret values into files, logs, commit messages, or chat
   unless the user explicitly asks for the value itself.
5. Prefer `rutile run` over `get_secret` whenever the secret is only
   an input to a command.
6. Sub-agents get delegated tokens, never your own token.

## Error-handling cheat sheet

| Error code | Meaning | What you do |
|---|---|---|
| `policy_denied` | no rule allows this path | `request_access` once, inform user |
| `locked` | store locked | ask user: `rutile unlock`, retry once |
| `not_found` | no such secret | `list_secrets`, re-check the path |
| `invalid_token` | token revoked, expired (`--expires`), or local-only used over HTTP | stop; user must re-issue |
| `forbidden` | write attempt / depth-2 delegation | don't — these are human-only |
