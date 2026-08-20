# Contributing to rutile

Thanks for your interest! A few ground rules keep this security tool healthy:

## Development

```bash
make test          # unit + integration (must stay race-clean)
make smoke         # full e2e scenario — required before any PR
make release-check # lint + test + smoke + Linux-in-Docker
```

Go 1.25+. Conventional commits in English (`feat:`, `fix:`, `docs:`…).

## What we look for

- **Every behavior change ships with a test.** Security invariants (policy
  enforcement, delegation scoping, audit chaining, token checks) get
  regression tests in `internal/daemon`.
- New attack-surface (network, parsing, exec) needs a matching note in
  `SECURITY.md` — we document what we defend against *and what we don't*.
- Agent-facing changes update `AGENTS.md` (it is the contract agents read).

## Security issues

Please do **not** open public issues for vulnerabilities — see
[SECURITY.md](SECURITY.md) for private reporting.
