package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lercas/rutile/internal/ageio"
	"github.com/Lercas/rutile/internal/audit"
	"github.com/Lercas/rutile/internal/paths"
	"github.com/Lercas/rutile/internal/protocol"
	"github.com/Lercas/rutile/internal/store"
)

const testPass = "test-passphrase-123"

// startDaemon initializes a store in a temp RUTILE_DIR and runs the
// daemon on its socket.
func startDaemon(t *testing.T) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "home")
	t.Setenv("RUTILE_DIR", dir)
	// darwin caps unix socket paths at ~104 bytes; test temp dirs blow past it
	sockDir, err := os.MkdirTemp("", "ptl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	t.Setenv("RUTILE_SOCKET", filepath.Join(sockDir, "d.sock"))
	if err := os.MkdirAll(paths.StoreDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	id, genErr := ageio.GenerateIdentity()
	if genErr != nil {
		t.Fatal(genErr)
	}
	if err := ageio.SaveIdentityEncrypted(paths.IdentityFile(), id, testPass); err != nil {
		t.Fatal(err)
	}
	if err := ageio.SaveRecipients(paths.RecipientsFile(), id.Recipient()); err != nil {
		t.Fatal(err)
	}
	d, err := New(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	lastDaemon = d
	ctx, cancel := context.WithCancel(context.Background())
	lastCancel = cancel
	t.Cleanup(cancel)
	go d.Run(ctx)
	waitSocketUp(t)
}

func waitSocketUp(t *testing.T) {
	t.Helper()
	for i := 0; i < 80; i++ {
		if conn, err := net.Dial("unix", paths.SocketPath()); err == nil {
			conn.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("daemon socket never came up")
}

func waitSocketGone(t *testing.T) {
	t.Helper()
	for i := 0; i < 80; i++ {
		if conn, err := net.Dial("unix", paths.SocketPath()); err != nil {
			return
		} else {
			conn.Close()
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("old daemon socket never went away")
}

func call(t *testing.T, method string, auth *protocol.AgentAuth, params, out any) *protocol.RPCError {
	t.Helper()
	conn, err := net.Dial("unix", paths.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, _ := json.Marshal(params)
	if params == nil {
		raw = []byte(`{}`)
	}
	req := protocol.Request{ID: "t", Method: method, Auth: auth, Params: raw}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(conn)
	if !sc.Scan() {
		t.Fatal("no response")
	}
	var resp protocol.Response
	if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != nil {
		return resp.Error
	}
	if out != nil {
		if err := json.Unmarshal(resp.Result, out); err != nil {
			t.Fatal(err)
		}
	}
	return nil
}

func mustOK(t *testing.T, e *protocol.RPCError) {
	t.Helper()
	if e != nil {
		t.Fatalf("unexpected error: %v", e)
	}
}

func TestRequestEnvelopeBounds(t *testing.T) {
	if err := validateRequestEnvelope(protocol.Request{ID: "ok", Method: "get"}); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
	for _, req := range []protocol.Request{
		{ID: "", Method: "get"},
		{ID: strings.Repeat("i", maxRequestID+1), Method: "get"},
		{ID: "ok", Method: ""},
		{ID: "ok", Method: strings.Repeat("m", maxMethodLen+1)},
	} {
		if err := validateRequestEnvelope(req); err == nil || err.Code != protocol.CodeBadRequest {
			t.Fatalf("invalid envelope accepted: %+v", req)
		}
	}
}

func TestSecretValueSizeBound(t *testing.T) {
	startDaemon(t)
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil))
	if e := call(t, "put", nil, protocol.PutParams{
		Path: "dev/too-large", Value: strings.Repeat("x", store.MaxSecretValueLen+1),
	}, nil); e == nil || e.Code != protocol.CodeBadRequest {
		t.Fatalf("oversized secret accepted: %v", e)
	}
	mustOK(t, call(t, "put", nil, protocol.PutParams{Path: "dev/control", Value: "small"}, nil))
	var got protocol.GetResult
	mustOK(t, call(t, "get", nil, protocol.GetParams{Path: "dev/control"}, &got))
	if got.Value != "small" {
		t.Fatalf("control value=%q", got.Value)
	}
}

func TestUnlockRejectsOversizedPassphraseBeforeKDF(t *testing.T) {
	startDaemon(t)
	e := call(t, "unlock", nil, protocol.UnlockParams{Passphrase: strings.Repeat("x", ageio.MaxPassphraseLen+1)}, nil)
	if e == nil || e.Code != protocol.CodeBadRequest {
		t.Fatalf("oversized passphrase reached unlock path: %v", e)
	}
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil))
}

func registerAgent(t *testing.T, name string) *protocol.AgentAuth {
	t.Helper()
	var res protocol.AgentAddResult
	mustOK(t, call(t, "agent_add", nil, protocol.AgentAddParams{Name: name}, &res))
	return &protocol.AgentAuth{Agent: name, Token: res.Token}
}

func TestFullFlow(t *testing.T) {
	startDaemon(t)

	// locked: get denied with locked code
	e := call(t, "get", nil, protocol.GetParams{Path: "dev/a"}, nil)
	if e == nil || e.Code != protocol.CodeLocked {
		t.Fatalf("want locked, got %v", e)
	}

	if e := call(t, "unlock", nil, protocol.UnlockParams{Passphrase: "wrong"}, nil); e == nil {
		t.Fatal("wrong passphrase accepted")
	}
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil))
	mustOK(t, call(t, "put", nil, protocol.PutParams{Path: "dev/a", Value: "v1"}, nil))

	var got protocol.GetResult
	mustOK(t, call(t, "get", nil, protocol.GetParams{Path: "dev/a"}, &got))
	if got.Value != "v1" {
		t.Fatalf("value = %q", got.Value)
	}

	auth := registerAgent(t, "bot")
	// no rule yet
	if e := call(t, "get", auth, protocol.GetParams{Path: "dev/a"}, nil); e == nil || e.Code != protocol.CodeDenied {
		t.Fatalf("want policy_denied, got %v", e)
	}
	mustOK(t, call(t, "rule_add", nil, protocol.RuleAddParams{Agent: "bot", Pattern: "dev/**"}, nil))
	mustOK(t, call(t, "get", auth, protocol.GetParams{Path: "dev/a", Reason: "test read"}, &got))

	// agent writes forbidden
	if e := call(t, "put", auth, protocol.PutParams{Path: "dev/x", Value: "v"}, nil); e == nil || e.Code != protocol.CodeForbidden {
		t.Fatalf("want forbidden, got %v", e)
	}
	// bad token
	bad := &protocol.AgentAuth{Agent: "bot", Token: "rtl_nope"}
	if e := call(t, "get", bad, protocol.GetParams{Path: "dev/a"}, nil); e == nil || e.Code != protocol.CodeInvalidToken {
		t.Fatalf("want invalid_token, got %v", e)
	}
}

func TestOversizedRequestMetadataRejectedWithoutPoisoningAudit(t *testing.T) {
	startDaemon(t)
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil))
	mustOK(t, call(t, "put", nil, protocol.PutParams{Path: "dev/bounded", Value: "ok"}, nil))
	auth := registerAgent(t, "boundedbot")
	mustOK(t, call(t, "rule_add", nil, protocol.RuleAddParams{Agent: "boundedbot", Pattern: "dev/**"}, nil))

	oversized := strings.Repeat("x", 2049)
	if e := call(t, "get", auth, protocol.GetParams{Path: "dev/bounded", Reason: oversized}, nil); e == nil || e.Code != protocol.CodeBadRequest {
		t.Fatalf("oversized reason accepted: %v", e)
	}
	oversizedPath := strings.Repeat("a", 1025)
	if e := call(t, "get", auth, protocol.GetParams{Path: oversizedPath}, nil); e == nil || e.Code != protocol.CodeBadRequest {
		t.Fatalf("oversized path accepted: %v", e)
	}
	if e := call(t, "list", auth, protocol.ListParams{Prefix: oversizedPath}, nil); e == nil || e.Code != protocol.CodeBadRequest {
		t.Fatalf("oversized prefix accepted: %v", e)
	}

	malformed := &protocol.AgentAuth{Agent: strings.Repeat("z", 4096), Token: "rtl_invalid"}
	if e := call(t, "list", malformed, protocol.ListParams{}, nil); e == nil || e.Code != protocol.CodeInvalidToken {
		t.Fatalf("malformed auth accepted: %v", e)
	}
	auditBytes, err := os.ReadFile(paths.AuditFile())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(auditBytes), malformed.Agent) {
		t.Fatal("malformed auth metadata was copied into the audit log")
	}
	foundBoundedActor := false
	scanner := bufio.NewScanner(strings.NewReader(string(auditBytes)))
	for scanner.Scan() {
		var entry audit.Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatal(err)
		}
		if entry.Actor == "<invalid>" && entry.Reason == "malformed_auth_metadata" {
			foundBoundedActor = true
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if !foundBoundedActor {
		t.Fatal("bounded malformed-auth audit entry was not recorded")
	}
	if _, err := audit.Verify(paths.AuditFile()); err != nil {
		t.Fatalf("audit chain was poisoned by rejected metadata: %v", err)
	}

	var got protocol.GetResult
	mustOK(t, call(t, "get", auth, protocol.GetParams{Path: "dev/bounded", Reason: "control"}, &got))
	if got.Value != "ok" {
		t.Fatalf("legitimate control read returned %q", got.Value)
	}
}

func TestOneTimeNotBurnedWhileLocked(t *testing.T) {
	startDaemon(t)
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil))
	mustOK(t, call(t, "put", nil, protocol.PutParams{Path: "prod/key", Value: "shhh"}, nil))
	auth := registerAgent(t, "bot")
	mustOK(t, call(t, "rule_add", nil, protocol.RuleAddParams{Agent: "bot", Pattern: "prod/key", OneTime: true}, nil))
	mustOK(t, call(t, "lock", nil, nil, nil))

	// locked read must NOT consume the one-time grant
	if e := call(t, "get", auth, protocol.GetParams{Path: "prod/key"}, nil); e == nil || e.Code != protocol.CodeLocked {
		t.Fatalf("want locked, got %v", e)
	}
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil))

	var got protocol.GetResult
	mustOK(t, call(t, "get", auth, protocol.GetParams{Path: "prod/key"}, &got))
	if got.Value != "shhh" {
		t.Fatalf("value = %q", got.Value)
	}
	// now it is consumed
	if e := call(t, "get", auth, protocol.GetParams{Path: "prod/key"}, nil); e == nil || e.Code != protocol.CodeDenied {
		t.Fatalf("want policy_denied after consume, got %v", e)
	}
}

func TestOneTimeConcurrentReadServedOnce(t *testing.T) {
	startDaemon(t)
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil))
	mustOK(t, call(t, "put", nil, protocol.PutParams{Path: "prod/once", Value: "only-once"}, nil))
	auth := registerAgent(t, "racebot")
	mustOK(t, call(t, "rule_add", nil, protocol.RuleAddParams{Agent: "racebot", Pattern: "prod/once", OneTime: true}, nil))

	params, _ := json.Marshal(protocol.GetParams{Path: "prod/once"})
	const readers = 24
	var wg sync.WaitGroup
	results := make(chan bool, readers)
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, rpcErr := lastDaemon.handleGet(params, caller{agent: auth.Agent})
			results <- rpcErr == nil
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for ok := range results {
		if ok {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("one-time grant served %d concurrent reads, want exactly 1", successes)
	}
}

func TestGetFailsClosedWhenAuditUnavailable(t *testing.T) {
	startDaemon(t)
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil))
	mustOK(t, call(t, "put", nil, protocol.PutParams{Path: "dev/audit", Value: "secret"}, nil))
	if err := os.Rename(paths.AuditFile(), paths.AuditFile()+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(paths.AuditFile(), 0o700); err != nil {
		t.Fatal(err)
	}
	var got protocol.GetResult
	e := call(t, "get", nil, protocol.GetParams{Path: "dev/audit"}, &got)
	if e == nil || e.Code != protocol.CodeInternal {
		t.Fatalf("want internal audit failure, got %v", e)
	}
	if got.Value != "" {
		t.Fatal("secret returned despite audit failure")
	}
}

func TestOneTimeReadFailsClosedWhenConsumptionCannotPersist(t *testing.T) {
	startDaemon(t)
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil))
	mustOK(t, call(t, "put", nil, protocol.PutParams{Path: "prod/durable", Value: "secret"}, nil))
	auth := registerAgent(t, "durablebot")
	mustOK(t, call(t, "rule_add", nil, protocol.RuleAddParams{Agent: "durablebot", Pattern: "prod/durable", OneTime: true}, nil))
	if err := os.Remove(paths.PolicyFile()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(paths.PolicyFile(), 0o700); err != nil {
		t.Fatal(err)
	}
	var got protocol.GetResult
	e := call(t, "get", auth, protocol.GetParams{Path: "prod/durable"}, &got)
	if e == nil || e.Code != protocol.CodeInternal {
		t.Fatalf("want internal persistence failure, got %v", e)
	}
	if got.Value != "" {
		t.Fatal("secret returned despite failed one-time persistence")
	}
}

func TestAccessRequestFlow(t *testing.T) {
	startDaemon(t)
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil))
	mustOK(t, call(t, "put", nil, protocol.PutParams{Path: "prod/db", Value: "pw"}, nil))
	auth := registerAgent(t, "bot")

	var ar protocol.AccessRequestResult
	mustOK(t, call(t, "access_request", auth, protocol.AccessRequestParams{Path: "prod/db", Reason: "deploy"}, &ar))
	if ar.Status != "pending" || ar.ID == "" {
		t.Fatalf("bad request result: %+v", ar)
	}
	// duplicate returns the same id
	var ar2 protocol.AccessRequestResult
	mustOK(t, call(t, "access_request", auth, protocol.AccessRequestParams{Path: "prod/db"}, &ar2))
	if ar2.ID != ar.ID {
		t.Fatalf("duplicate got new id: %s vs %s", ar2.ID, ar.ID)
	}

	var list protocol.RequestListResult
	mustOK(t, call(t, "request_list", nil, nil, &list))
	if len(list.Requests) != 1 || list.Requests[0].Reason != "deploy" {
		t.Fatalf("request_list: %+v", list)
	}
	if e := call(t, "request_resolve", nil, protocol.RequestResolveParams{ID: ar.ID, Approve: true, For: "not-a-duration"}, nil); e == nil || e.Code != protocol.CodeBadRequest {
		t.Fatalf("want bad_request for invalid approval ttl, got %v", e)
	}
	mustOK(t, call(t, "request_list", nil, nil, &list))
	if len(list.Requests) != 1 || list.Requests[0].ID != ar.ID {
		t.Fatalf("invalid approval lost pending request: %+v", list)
	}
	// agents cannot list or resolve
	if e := call(t, "request_list", auth, nil, nil); e == nil || e.Code != protocol.CodeForbidden {
		t.Fatalf("want forbidden, got %v", e)
	}

	var res protocol.RequestResolveResult
	mustOK(t, call(t, "request_resolve", nil, protocol.RequestResolveParams{ID: ar.ID, Approve: true, OneTime: true}, &res))
	if !res.Approved || res.Rule == nil || !res.Rule.OneTime {
		t.Fatalf("resolve: %+v", res)
	}

	var got protocol.GetResult
	mustOK(t, call(t, "get", auth, protocol.GetParams{Path: "prod/db"}, &got))
	if got.Value != "pw" {
		t.Fatalf("value = %q", got.Value)
	}
	// queue drained
	mustOK(t, call(t, "request_list", nil, nil, &list))
	if len(list.Requests) != 0 {
		t.Fatalf("queue not drained: %+v", list)
	}
	// resolving again -> not_found
	if e := call(t, "request_resolve", nil, protocol.RequestResolveParams{ID: ar.ID}, nil); e == nil || e.Code != protocol.CodeNotFound {
		t.Fatalf("want not_found, got %v", e)
	}
}
