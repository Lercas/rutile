---
description: Show rutile store status, pending agent requests and recent audit entries
allowed-tools: Bash(rutile:*)
---

Run `rutile status`, `rutile requests` and `rutile audit -n 10`,
then summarize for the user: lock state, secret count, pending agent access
requests (with the approve/reject commands ready to copy), and anything
unusual in the recent audit entries (denials, unknown agents).
