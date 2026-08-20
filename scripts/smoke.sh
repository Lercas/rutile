#!/usr/bin/env bash
# End-to-end smoke test: runs the full human + agent flow in a sandbox dir.
set -euo pipefail

cd "$(dirname "$0")/.."
WORK_DIR="$(mktemp -d)"
BIN="$WORK_DIR/rutile"
go build -o "$BIN" ./cmd/rutile

export RUTILE_DIR="$WORK_DIR/home"
mkdir -p "$RUTILE_DIR"
trap 'kill "${DAEMON_PID:-}" 2>/dev/null || true; pkill -f "$BIN daemon" 2>/dev/null || true; rm -rf "$WORK_DIR"' EXIT

PASS="smoke-passphrase-123"

step() { echo; echo "== $*"; }

step "init"
echo "$PASS" | "$BIN" init

step "daemon start (manual foreground-in-background for the test)"
"$BIN" daemon --idle-timeout 5m &>"$RUTILE_DIR/daemon-test.log" &
DAEMON_PID=$!
sleep 0.5

step "unlock + add + show"
# non-tty: unlock via socket directly using a tiny stdin trick is not available,
# so drive unlock through the CLI by piping into `rutile add` is impossible
# non-interactively; instead call unlock via a here-doc python? No: use the
# hidden path — unlock is human-only JSON over the socket:
python3 - "$RUTILE_DIR/daemon.sock" "$PASS" <<'EOF'
import json, socket, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall((json.dumps({"id":"1","method":"unlock","params":{"passphrase":sys.argv[2]}})+"\n").encode())
resp = json.loads(s.makefile().readline())
assert resp.get("error") is None, resp
print("unlocked")
EOF

echo -n "super-secret-value" | "$BIN" add dev/demo/api-key
[ "$("$BIN" show dev/demo/api-key)" = "super-secret-value" ] && echo "show OK"

step "ls"
"$BIN" ls | grep -q "dev/demo/api-key" && echo "ls OK"

step "agent add + allow"
AGENT_OUT="$("$BIN" agent add smokebot)"
TOKEN="$(echo "$AGENT_OUT" | grep -o 'rtl_[0-9a-f]*' | head -1)"
[ -n "$TOKEN" ] && echo "token captured"
"$BIN" allow smokebot "dev/**"
"$BIN" allow smokebot "prod/one-shot" --one-time
echo -n "one-shot-value" | "$BIN" add prod/one-shot

step "agent get via socket (policy allow)"
python3 - "$RUTILE_DIR/daemon.sock" "$TOKEN" <<'EOF'
import json, socket, sys
def call(method, params, auth=None):
    s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
    req = {"id":"x","method":method,"params":params}
    if auth: req["auth"] = auth
    s.sendall((json.dumps(req)+"\n").encode())
    return json.loads(s.makefile().readline())
auth = {"agent":"smokebot","token":sys.argv[2]}
r = call("get", {"path":"dev/demo/api-key"}, auth)
assert r.get("error") is None and r["result"]["value"] == "super-secret-value", r
print("agent read OK")
r = call("get", {"path":"secret/forbidden"}, auth)
assert r["error"]["code"] == "policy_denied", r
print("policy deny OK")
r = call("get", {"path":"prod/one-shot"}, auth)
assert r.get("error") is None, r
r2 = call("get", {"path":"prod/one-shot"}, auth)
assert r2["error"]["code"] == "policy_denied", r2
print("one-time consumed OK")
r = call("get", {"path":"dev/demo/api-key"}, {"agent":"smokebot","token":"rtl_wrong"})
assert r["error"]["code"] == "invalid_token", r
print("bad token rejected OK")
r = call("put", {"path":"dev/evil","value":"x"}, auth)
assert r["error"]["code"] == "forbidden", r
print("agent write forbidden OK")
EOF

step "access request flow (agent asks, human approves)"
REQ_ID=$(python3 - "$RUTILE_DIR/daemon.sock" "$TOKEN" <<'EOF'
import json, socket, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
req = {"id":"r","method":"access_request","auth":{"agent":"smokebot","token":sys.argv[2]},
       "params":{"path":"secret/forbidden","reason":"smoke test needs it"}}
s.sendall((json.dumps(req)+"\n").encode())
r = json.loads(s.makefile().readline())
assert r.get("error") is None and r["result"]["status"] == "pending", r
print(r["result"]["id"])
EOF
)
"$BIN" requests | grep -q "smoke test needs it" && echo "requests listed OK"
"$BIN" status | grep -q "запросов от агентов" && echo "status shows pending OK"
echo -n "forbidden-value" | "$BIN" add secret/forbidden
"$BIN" approve "$REQ_ID" --one-time
python3 - "$RUTILE_DIR/daemon.sock" "$TOKEN" <<'EOF'
import json, socket, sys
def call(method, params, auth):
    s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
    s.sendall((json.dumps({"id":"x","method":method,"params":params,"auth":auth})+"\n").encode())
    return json.loads(s.makefile().readline())
auth = {"agent":"smokebot","token":sys.argv[2]}
r = call("get", {"path":"secret/forbidden","reason":"approved read"}, auth)
assert r.get("error") is None and r["result"]["value"] == "forbidden-value", r
print("approved read OK")
EOF

step "MCP over HTTP (a2a): Bearer auth"
"$BIN" mcp --http 127.0.0.1:7997 &>"$RUTILE_DIR/mcp-http.log" &
HTTP_PID=$!
sleep 0.5
python3 - "$TOKEN" <<'EOF'
import json, sys, urllib.request, urllib.error
body = json.dumps({"jsonrpc":"2.0","id":1,"method":"initialize",
    "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}).encode()
def post(token):
    req = urllib.request.Request("http://127.0.0.1:7997", data=body, method="POST",
        headers={"Content-Type":"application/json","Accept":"application/json, text/event-stream",
                 "Authorization":"Bearer "+token})
    try:
        return urllib.request.urlopen(req).status
    except urllib.error.HTTPError as e:
        return e.code
assert post(sys.argv[1]) == 200, "valid token rejected"
print("http valid token OK")
assert post("rtl_wrong") == 400, "invalid token accepted"
print("http invalid token rejected OK")
EOF
kill "$HTTP_PID" 2>/dev/null
wait "$HTTP_PID" 2>/dev/null || true

step "rutile run: env + placeholder injection"
OUT=$("$BIN" run -e MY_KEY=dev/demo/api-key -- sh -c 'printf "%s" "$MY_KEY"')
[ "$OUT" = "super-secret-value" ] && echo "run env OK"
OUT=$("$BIN" run --allow-argv-secrets -- printf '%s' '{{rutile:dev/demo/api-key}}')
[ "$OUT" = "super-secret-value" ] && echo "run placeholder OK"

step "delegation: parent mints scoped sub-token"
python3 - "$RUTILE_DIR/daemon.sock" "$TOKEN" <<'EOF'
import json, socket, sys
def call(method, params, auth):
    s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
    s.sendall((json.dumps({"id":"x","method":method,"params":params,"auth":auth})+"\n").encode())
    return json.loads(s.makefile().readline())
parent = {"agent":"smokebot","token":sys.argv[2]}
r = call("delegate", {"label":"worker","patterns":["dev/demo/**"],"ttl":"10m"}, parent)
assert r.get("error") is None, r
child = {"agent":"smokebot","token":r["result"]["token"]}
g = call("get", {"path":"dev/demo/api-key"}, child)
assert g.get("error") is None and g["result"]["value"] == "super-secret-value", g
print("child read in scope OK")
g = call("get", {"path":"secret/forbidden"}, child)
assert g["error"]["code"] == "policy_denied", g
print("child out-of-scope denied OK")
g = call("delegate", {"label":"w2","patterns":["dev/**"]}, child)
assert g["error"]["code"] == "forbidden", g
print("child cannot re-delegate OK")
EOF
"$BIN" delegations | grep -q "smokebot>worker" && echo "delegations listed OK"

step "rotate: new key, secrets survive"
python3 - "$RUTILE_DIR/daemon.sock" <<'EOF'
import json, socket, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall((json.dumps({"id":"1","method":"rotate","params":{"new_passphrase":"rotated-pass-456"}})+"\n").encode())
r = json.loads(s.makefile().readline())
assert r.get("error") is None and r["result"]["reencrypted"] >= 3, r
print("rotate OK, reencrypted:", r["result"]["reencrypted"])
EOF
[ "$("$BIN" show dev/demo/api-key)" = "super-secret-value" ] && echo "post-rotate read OK"
[ -f "$RUTILE_DIR/identities.age.bak" ] && echo "old key backed up OK"

step "MCP stdio: full session (initialize, tools/list, get_secret)"
(
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}'
printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_secret","arguments":{"path":"dev/demo/api-key","reason":"smoke stdio"}}}'
printf '%s\n' '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"store_status","arguments":{}}}'
sleep 1
) | RUTILE_AGENT=smokebot RUTILE_TOKEN=$TOKEN "$BIN" mcp 2>/dev/null | python3 -c '
import json,sys
tools=set(); got=False; status=False
for line in sys.stdin:
    m=json.loads(line)
    if m.get("id")==2: tools={t["name"] for t in m["result"]["tools"]}
    if m.get("id")==3: got="super-secret-value" in json.dumps(m["result"])
    if m.get("id")==4:
        payload=json.dumps(m["result"])
        status="\"unlocked\": true" in payload and "\"visible_secrets\": 1" in payload
need={"get_secret","list_secrets","request_access","delegate_access","store_status"}
assert need <= tools, f"missing tools: {need-tools}"
assert got, "stdio get_secret failed"
assert status, "stdio store_status failed or returned wrong visibility"
print("mcp stdio session OK")
'

step "import env"
printf 'FOO_KEY=foo-val\n# comment\nexport BAR_KEY="bar val"\n' > "$RUTILE_DIR/test.env"
"$BIN" import env "$RUTILE_DIR/test.env" --prefix imported/demo | grep -q "imported: 2" && echo "import env OK"
[ "$("$BIN" show imported/demo/BAR_KEY)" = "bar val" ] && echo "imported value OK"

step "crash recovery: kill -9 daemon, auto-respawn"
DPID=$(pgrep -f "$BIN daemon" | head -1)
kill -9 "$DPID"
sleep 0.3
"$BIN" status >/dev/null && echo "respawn after kill -9 OK"
python3 - "$RUTILE_DIR/daemon.sock" <<'EOF'
import json, socket, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall((json.dumps({"id":"1","method":"unlock","params":{"passphrase":"rotated-pass-456"}})+"\n").encode())
r = json.loads(s.makefile().readline())
assert r.get("error") is None, r
print("re-unlock after crash OK")
EOF

step "system mode: agent store_status is not a human call"
CURRENT_DPID=$(pgrep -f "$BIN daemon" | head -1)
kill "$CURRENT_DPID"
for _ in $(seq 1 40); do [ ! -S "$RUTILE_DIR/daemon.sock" ] && break; sleep 0.05; done
ADMIN_UID=$(( $(id -u) + 1 ))
"$BIN" daemon --admin-uid "$ADMIN_UID" &>"$RUTILE_DIR/daemon-system-test.log" &
SYSTEM_DPID=$!
for _ in $(seq 1 40); do [ -S "$RUTILE_DIR/daemon.sock" ] && break; sleep 0.05; done
if "$BIN" status >/dev/null 2>&1; then
  echo "system-mode daemon accepted human call from wrong uid" >&2
  exit 1
fi
(
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"system-smoke","version":"1"}}}'
printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"store_status","arguments":{}}}'
sleep 1
) | RUTILE_AGENT=smokebot RUTILE_TOKEN=$TOKEN "$BIN" mcp 2>/dev/null | python3 -c '
import json,sys
ok=False
for line in sys.stdin:
    m=json.loads(line)
    if m.get("id")==2:
        payload=json.dumps(m.get("result", {}))
        ok="\"visible_secrets\": 1" in payload
assert ok, "store_status failed under system-mode admin boundary"
print("system-mode agent status OK")
'
kill "$SYSTEM_DPID"; wait "$SYSTEM_DPID" 2>/dev/null || true
"$BIN" daemon --idle-timeout 5m &>"$RUTILE_DIR/daemon-test.log" &
DAEMON_PID=$!
for _ in $(seq 1 40); do [ -S "$RUTILE_DIR/daemon.sock" ] && break; sleep 0.05; done
python3 - "$RUTILE_DIR/daemon.sock" <<'EOF'
import json, socket, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall((json.dumps({"id":"1","method":"unlock","params":{"passphrase":"rotated-pass-456"}})+"\n").encode())
r = json.loads(s.makefile().readline())
assert r.get("error") is None, r
EOF

step "MCP over HTTPS: TLS + non-loopback guard"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$RUTILE_DIR/tls.key" -out "$RUTILE_DIR/tls.crt" \
  -days 1 -subj "/CN=localhost" &>/dev/null
"$BIN" mcp --http 127.0.0.1:7998 --tls-cert "$RUTILE_DIR/tls.crt" --tls-key "$RUTILE_DIR/tls.key" \
  &>"$RUTILE_DIR/mcp-tls.log" &
TLS_PID=$!
sleep 0.5
python3 - "$TOKEN" <<'EOF'
import json, ssl, sys, urllib.request, urllib.error
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
body = json.dumps({"jsonrpc":"2.0","id":1,"method":"initialize",
    "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}).encode()
req = urllib.request.Request("https://127.0.0.1:7998", data=body, method="POST",
    headers={"Content-Type":"application/json","Accept":"application/json, text/event-stream",
             "Authorization":"Bearer "+sys.argv[1]})
assert urllib.request.urlopen(req, context=ctx).status == 200
print("https initialize OK")
EOF
kill "$TLS_PID" 2>/dev/null; wait "$TLS_PID" 2>/dev/null || true
GUARD_OUT=$("$BIN" mcp --http 0.0.0.0:7999 2>&1 || true)
echo "$GUARD_OUT" | grep -q "без TLS" && echo "non-loopback without TLS refused OK"

step "mTLS + SPIFFE identity (no bearer token)"
TLSD="$RUTILE_DIR/mtls"; mkdir -p "$TLSD"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$TLSD/ca.key" -out "$TLSD/ca.crt" -days 1 -subj "/CN=rutile-test-ca" &>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$TLSD/client.key" -out "$TLSD/client.csr" -subj "/CN=smokebot" &>/dev/null
openssl x509 -req -in "$TLSD/client.csr" -CA "$TLSD/ca.crt" -CAkey "$TLSD/ca.key" \
  -CAcreateserial -days 1 -out "$TLSD/client.crt" \
  -extfile <(printf "subjectAltName=URI:spiffe://rutile.test/agent/smokebot") &>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$TLSD/other.key" -out "$TLSD/other.csr" -subj "/CN=smokebot" &>/dev/null
openssl x509 -req -in "$TLSD/other.csr" -CA "$TLSD/ca.crt" -CAkey "$TLSD/ca.key" \
  -CAcreateserial -days 1 -out "$TLSD/other.crt" \
  -extfile <(printf "subjectAltName=URI:spiffe://other.test/agent/smokebot") &>/dev/null
"$BIN" mcp --http 127.0.0.1:8001 \
  --tls-cert "$RUTILE_DIR/tls.crt" --tls-key "$RUTILE_DIR/tls.key" \
  --tls-client-ca "$TLSD/ca.crt" --spiffe-trust-domain rutile.test &>"$RUTILE_DIR/mcp-mtls.log" &
MTLS_PID=$!
sleep 0.5
python3 - "$TLSD" <<'EOF'
import json, ssl, sys, urllib.error, urllib.request
d = sys.argv[1]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
ctx.load_cert_chain(d + "/client.crt", d + "/client.key")
body = json.dumps({"jsonrpc":"2.0","id":1,"method":"initialize",
    "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}).encode()
req = urllib.request.Request("https://127.0.0.1:8001", data=body, method="POST",
    headers={"Content-Type":"application/json","Accept":"application/json, text/event-stream"})
assert urllib.request.urlopen(req, context=ctx).status == 200
print("mtls spiffe identity OK (no bearer)")
# Same CA and agent name, but a different SPIFFE trust domain: TLS succeeds,
# certificate-only agent authentication must not.
other = ssl.create_default_context(); other.check_hostname = False; other.verify_mode = ssl.CERT_NONE
other.load_cert_chain(d + "/other.crt", d + "/other.key")
try:
    urllib.request.urlopen(req, context=other)
    raise AssertionError("cross-domain SPIFFE identity accepted")
except urllib.error.HTTPError as e:
    assert e.code in (400, 401, 403), e.code
print("cross-domain spiffe identity rejected OK")
# no client cert at all -> TLS handshake refused
ctx2 = ssl.create_default_context(); ctx2.check_hostname = False; ctx2.verify_mode = ssl.CERT_NONE
try:
    urllib.request.urlopen(urllib.request.Request("https://127.0.0.1:8001", data=body, method="POST",
        headers={"Content-Type":"application/json","Accept":"application/json, text/event-stream"}), context=ctx2)
    raise SystemExit("request without client cert accepted")
except Exception as e:
    print("no client cert rejected OK")
EOF
kill "$MTLS_PID" 2>/dev/null; wait "$MTLS_PID" 2>/dev/null || true

step "rate limit: 429 after burst"
"$BIN" mcp --http 127.0.0.1:8002 --rate-limit 6 &>"$RUTILE_DIR/mcp-rl.log" &
RL_PID=$!
sleep 0.5
python3 - "$TOKEN" <<'EOF'
import json, sys, urllib.request, urllib.error
body = json.dumps({"jsonrpc":"2.0","id":1,"method":"initialize",
    "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}).encode()
codes = []
for i in range(12):
    req = urllib.request.Request("http://127.0.0.1:8002", data=body, method="POST",
        headers={"Content-Type":"application/json","Accept":"application/json, text/event-stream",
                 "Authorization":"Bearer "+sys.argv[1]})
    try:
        codes.append(urllib.request.urlopen(req).status)
    except urllib.error.HTTPError as e:
        codes.append(e.code)
assert 429 in codes, codes
print("rate limit 429 OK")
EOF
kill "$RL_PID" 2>/dev/null; wait "$RL_PID" 2>/dev/null || true

step "audit rotate: checkpoint chain"
"$BIN" audit rotate | grep -q "checkpoint" && echo "audit rotate OK"
"$BIN" audit verify

step "audit verify + git log"
"$BIN" audit verify
"$BIN" audit -n 5
"$BIN" git log --oneline -3

step "backup refuses overwrite"
"$BIN" backup "$RUTILE_DIR/backup"
[ -s "$RUTILE_DIR/backup/identities.age" ] && [ -s "$RUTILE_DIR/backup/recipients.txt" ] && echo "backup files OK"
if "$BIN" backup "$RUTILE_DIR/backup" >/dev/null 2>&1; then
  echo "backup unexpectedly overwrote existing files" >&2
  exit 1
fi
echo "backup overwrite refused OK"

step "lock"
"$BIN" lock
"$BIN" status | grep -q "заблокировано" && echo "lock OK"

echo
echo "SMOKE TEST PASSED"
