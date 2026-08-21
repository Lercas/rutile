---
description: Set up rutile for this machine and connect Claude Code as an agent
allowed-tools: Bash(rutile:*), Bash(claude mcp:*)
---

Guide the user through rutile setup:

1. Check the installation with `rutile doctor` (if the binary is missing,
   suggest `go install ./cmd/rutile` from the rutile repo).
2. If the store is not initialized, have the USER run `rutile init`
   themselves (it prompts for a passphrase — do not automate it; suggest
   typing `! rutile init` so it runs in this session interactively).
3. Register this Claude Code instance: `rutile agent add claude` — relay
   the printed `claude mcp add ...` command to the user (do not echo the
   token anywhere else).
4. Ask which path scope Claude should get and run
   `rutile allow claude "<scope>"`.
5. If the user has an existing pass/passage store or .env files, offer
   `rutile import passage|pass|env`.
