package daemon

import (
	"errors"
	"os"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/Lercas/rutile/internal/ageio"
	"github.com/Lercas/rutile/internal/audit"
	"github.com/Lercas/rutile/internal/paths"
	"github.com/Lercas/rutile/internal/protocol"
)

func TestDelegationFlow(t *testing.T) {
	startDaemon(t)
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil))
	mustOK(t, call(t, "put", nil, protocol.PutParams{Path: "dev/build/key", Value: "bk"}, nil))
	mustOK(t, call(t, "put", nil, protocol.PutParams{Path: "dev/deploy/key", Value: "dk"}, nil))
	parent := registerAgent(t, "orchestrator")
	mustOK(t, call(t, "rule_add", nil, protocol.RuleAddParams{Agent: "orchestrator", Pattern: "dev/**"}, nil))

	// humans cannot delegate
	if e := call(t, "delegate", nil, protocol.DelegateParams{Label: "w", Patterns: []string{"dev/**"}}, nil); e == nil {
		t.Fatal("human delegate accepted")
	}

	var del protocol.DelegateResult
	mustOK(t, call(t, "delegate", parent, protocol.DelegateParams{
		Label: "worker-1", Patterns: []string{"dev/build/**"}, TTL: "30m",
	}, &del))
	if del.Token == "" || del.ID == "" {
		t.Fatalf("bad delegate result: %+v", del)
	}
	child := &protocol.AgentAuth{Agent: "orchestrator", Token: del.Token}

	// child reads inside its patterns ∩ parent policy
	var got protocol.GetResult
	mustOK(t, call(t, "get", child, protocol.GetParams{Path: "dev/build/key"}, &got))
	if got.Value != "bk" {
		t.Fatalf("value = %q", got.Value)
	}
	// outside child patterns (but inside parent policy) -> denied
	if e := call(t, "get", child, protocol.GetParams{Path: "dev/deploy/key"}, nil); e == nil || e.Code != protocol.CodeDenied {
		t.Fatalf("want delegation_scope denial, got %v", e)
	}
	// child list is filtered to the intersection
	var lst protocol.ListResult
	mustOK(t, call(t, "list", child, protocol.ListParams{}, &lst))
	if len(lst.Paths) != 1 || lst.Paths[0] != "dev/build/key" {
		t.Fatalf("child list: %v", lst.Paths)
	}
	// depth limit: child cannot delegate further
	if e := call(t, "delegate", child, protocol.DelegateParams{Label: "w2", Patterns: []string{"dev/**"}}, nil); e == nil || e.Code != protocol.CodeForbidden {
		t.Fatalf("want forbidden, got %v", e)
	}
	// child cannot file access requests
	if e := call(t, "access_request", child, protocol.AccessRequestParams{Path: "prod/x"}, nil); e == nil || e.Code != protocol.CodeForbidden {
		t.Fatalf("want forbidden, got %v", e)
	}

	// parent loses policy -> child instantly loses too (intersection)
	mustOK(t, call(t, "rule_del", nil, protocol.RuleDelParams{Agent: "orchestrator"}, nil))
	if e := call(t, "get", child, protocol.GetParams{Path: "dev/build/key"}, nil); e == nil || e.Code != protocol.CodeDenied {
		t.Fatalf("want denied after parent rule removal, got %v", e)
	}
	mustOK(t, call(t, "rule_add", nil, protocol.RuleAddParams{Agent: "orchestrator", Pattern: "dev/**"}, nil))

	// parent can revoke its own child
	mustOK(t, call(t, "delegation_revoke", parent, protocol.DelegationRevokeParams{ID: del.ID}, nil))
	if e := call(t, "get", child, protocol.GetParams{Path: "dev/build/key"}, nil); e == nil || e.Code != protocol.CodeInvalidToken {
		t.Fatalf("want invalid_token after revoke, got %v", e)
	}

	// revoking the parent kills all remaining children
	var del2 protocol.DelegateResult
	mustOK(t, call(t, "delegate", parent, protocol.DelegateParams{Label: "worker-2", Patterns: []string{"dev/**"}}, &del2))
	mustOK(t, call(t, "agent_revoke", nil, protocol.AgentRevokeParams{Name: "orchestrator"}, nil))
	child2 := &protocol.AgentAuth{Agent: "orchestrator", Token: del2.Token}
	if e := call(t, "get", child2, protocol.GetParams{Path: "dev/build/key"}, nil); e == nil || e.Code != protocol.CodeInvalidToken {
		t.Fatalf("want invalid_token after parent revoke, got %v", e)
	}
}

func TestRotate(t *testing.T) {
	startDaemon(t)
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil))
	mustOK(t, call(t, "put", nil, protocol.PutParams{Path: "a/one", Value: "v1"}, nil))
	mustOK(t, call(t, "put", nil, protocol.PutParams{Path: "b/two", Value: "v2"}, nil))

	var res protocol.RotateResult
	mustOK(t, call(t, "rotate", nil, protocol.RotateParams{NewPassphrase: "brand-new-pass"}, &res))
	if res.Reencrypted != 2 {
		t.Fatalf("reencrypted = %d", res.Reencrypted)
	}
	if res.Backup != paths.IdentityFile()+".bak" {
		t.Fatalf("identity backup=%q", res.Backup)
	}
	// still readable while unlocked (daemon swapped the key in memory)
	var got protocol.GetResult
	mustOK(t, call(t, "get", nil, protocol.GetParams{Path: "a/one"}, &got))
	if got.Value != "v1" {
		t.Fatalf("value = %q", got.Value)
	}
	// old passphrase no longer opens the identity file...
	if _, err := ageio.LoadIdentityEncrypted(paths.IdentityFile(), testPass); err == nil {
		t.Fatal("old passphrase still opens the new identity")
	}
	// ...the new one does, and lock/unlock cycle works
	mustOK(t, call(t, "lock", nil, nil, nil))
	if e := call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil); e == nil {
		t.Fatal("old passphrase unlocked after rotate")
	}
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: "brand-new-pass"}, nil))
	mustOK(t, call(t, "get", nil, protocol.GetParams{Path: "b/two"}, &got))
	if got.Value != "v2" {
		t.Fatalf("value after re-unlock = %q", got.Value)
	}
	oldID, err := ageio.LoadIdentityEncrypted(paths.IdentityFile()+".bak", testPass)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := lastDaemon.store.Read("a/one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ageio.Decrypt(oldID, ct); err == nil {
		t.Fatal("completed rotation left current ciphertext decryptable by old identity")
	}
	recs, err := ageio.LoadRecipients(paths.RecipientsFile())
	if err != nil || len(recs) != 1 {
		t.Fatalf("final recipients = %d, err=%v", len(recs), err)
	}
}

func TestIdentityBackupsNeverOverwriteDifferentRecoveryKey(t *testing.T) {
	startDaemon(t)
	first, err := writeIdentityBackup([]byte("first-identity"))
	if err != nil {
		t.Fatal(err)
	}
	same, err := writeIdentityBackup([]byte("first-identity"))
	if err != nil || same != first {
		t.Fatalf("identical backup not reused: first=%q same=%q err=%v", first, same, err)
	}
	second, err := writeIdentityBackup([]byte("second-identity"))
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("different recovery identity overwrote the first backup")
	}
	got, err := os.ReadFile(first)
	if err != nil || string(got) != "first-identity" {
		t.Fatalf("first recovery identity changed: %q err=%v", got, err)
	}
}

func TestRotateFailureAfterIdentitySwitchRemainsReadableAndRetryable(t *testing.T) {
	startDaemon(t)
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil))
	mustOK(t, call(t, "put", nil, protocol.PutParams{Path: "a/one", Value: "v1"}, nil))
	mustOK(t, call(t, "put", nil, protocol.PutParams{Path: "b/two", Value: "v2"}, nil))

	originalWrite := lastDaemon.store.Write
	writes := 0
	lastDaemon.rotateWrite = func(path string, ciphertext []byte) error {
		writes++
		if writes == 3 { // two transition writes, then fail first final write
			return errors.New("injected final-pass failure")
		}
		return originalWrite(path, ciphertext)
	}
	e := call(t, "rotate", nil, protocol.RotateParams{NewPassphrase: "partially-rotated-pass"}, nil)
	if e == nil || e.Code != protocol.CodeInternal {
		t.Fatalf("want injected rotate failure, got %v", e)
	}
	newID, err := ageio.LoadIdentityEncrypted(paths.IdentityFile(), "partially-rotated-pass")
	if err != nil {
		t.Fatalf("new identity not authoritative after phase switch: %v", err)
	}
	for _, path := range []string{"a/one", "b/two"} {
		ct, err := lastDaemon.store.Read(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ageio.Decrypt(newID, ct); err != nil {
			t.Fatalf("%s unreadable after interrupted final pass: %v", path, err)
		}
	}
	recs, err := ageio.LoadRecipients(paths.RecipientsFile())
	if err != nil || len(recs) != 2 {
		t.Fatalf("transition recipients not retained: count=%d err=%v", len(recs), err)
	}

	lastDaemon.rotateWrite = originalWrite
	var res protocol.RotateResult
	mustOK(t, call(t, "rotate", nil, protocol.RotateParams{NewPassphrase: "final-rotation-pass"}, &res))
	if res.Reencrypted != 2 {
		t.Fatalf("retry reencrypted=%d", res.Reencrypted)
	}
	recs, err = ageio.LoadRecipients(paths.RecipientsFile())
	if err != nil || len(recs) != 1 {
		t.Fatalf("retry did not finalize recipients: count=%d err=%v", len(recs), err)
	}
}

func TestRotateIdentityPersistenceAmbiguityReconcilesToNewKey(t *testing.T) {
	startDaemon(t)
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil))
	mustOK(t, call(t, "put", nil, protocol.PutParams{Path: "a/one", Value: "v1"}, nil))

	originalIdentityWrite := lastDaemon.rotateIdentityWrite
	lastDaemon.rotateIdentityWrite = func(path string, id *age.X25519Identity, passphrase string) error {
		if err := originalIdentityWrite(path, id, passphrase); err != nil {
			return err
		}
		return errors.New("injected error after identity rename")
	}
	e := call(t, "rotate", nil, protocol.RotateParams{NewPassphrase: "ambiguous-new-pass"}, nil)
	if e == nil || e.Code != protocol.CodeInternal {
		t.Fatalf("want injected identity persistence error, got %v", e)
	}
	newID, err := ageio.LoadIdentityEncrypted(paths.IdentityFile(), "ambiguous-new-pass")
	if err != nil {
		t.Fatalf("new identity not authoritative on disk: %v", err)
	}
	// A write after the ambiguous return must remain decryptable by the new
	// on-disk identity after restart.
	mustOK(t, call(t, "put", nil, protocol.PutParams{Path: "b/after", Value: "v2"}, nil))
	for _, path := range []string{"a/one", "b/after"} {
		ct, err := lastDaemon.store.Read(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ageio.Decrypt(newID, ct); err != nil {
			t.Fatalf("%s not decryptable by authoritative new identity: %v", path, err)
		}
	}
	lastDaemon.rotateIdentityWrite = originalIdentityWrite
	var res protocol.RotateResult
	mustOK(t, call(t, "rotate", nil, protocol.RotateParams{NewPassphrase: "reconciled-final-pass"}, &res))
	if res.Reencrypted != 2 {
		t.Fatalf("retry reencrypted=%d", res.Reencrypted)
	}
}

func TestAuditRotate(t *testing.T) {
	startDaemon(t)
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil))
	mustOK(t, call(t, "put", nil, protocol.PutParams{Path: "x/y", Value: "v"}, nil))

	var res protocol.AuditRotateResult
	mustOK(t, call(t, "audit_rotate", nil, nil, &res))
	if res.Archive == "" || res.Entries < 2 {
		t.Fatalf("rotate result: %+v", res)
	}
	// new chain keeps accepting entries and verifies, and so does the archive
	mustOK(t, call(t, "lock", nil, nil, nil))
	if n, err := audit.Verify(paths.AuditFile()); err != nil || n < 2 {
		t.Fatalf("new chain broken: n=%d err=%v", n, err)
	}
	if n, err := audit.Verify(res.Archive); err != nil || n != res.Entries {
		t.Fatalf("archive broken: n=%d err=%v", n, err)
	}
}

func TestTokenHardening(t *testing.T) {
	startDaemon(t)
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil))
	mustOK(t, call(t, "put", nil, protocol.PutParams{Path: "n/s", Value: "v"}, nil))
	if e := call(t, "agent_add", nil, protocol.AgentAddParams{Name: "badexpiry", Expires: "-1h"}, nil); e == nil || e.Code != protocol.CodeBadRequest {
		t.Fatalf("negative agent expiry accepted: %v", e)
	}

	// local-only agent with metadata
	var res protocol.AgentAddResult
	mustOK(t, call(t, "agent_add", nil, protocol.AgentAddParams{
		Name: "localbot", Type: "ci", Expires: "1d", LocalOnly: true,
	}, &res))
	mustOK(t, call(t, "rule_add", nil, protocol.RuleAddParams{Agent: "localbot", Pattern: "n/**"}, nil))

	local := &protocol.AgentAuth{Agent: "localbot", Token: res.Token}
	if e := call(t, "rule_add", nil, protocol.RuleAddParams{Agent: "localbot", Pattern: "n/**", For: "-1h"}, nil); e == nil || e.Code != protocol.CodeBadRequest {
		t.Fatalf("negative rule ttl accepted: %v", e)
	}
	if e := call(t, "delegate", local, protocol.DelegateParams{Label: "badttl", Patterns: []string{"n/**"}, TTL: "-1h"}, nil); e == nil || e.Code != protocol.CodeBadRequest {
		t.Fatalf("negative delegation ttl accepted: %v", e)
	}
	viaHTTP := &protocol.AgentAuth{Agent: "localbot", Token: res.Token, Transport: "http"}

	var got protocol.GetResult
	mustOK(t, call(t, "get", local, protocol.GetParams{Path: "n/s"}, &got))
	if e := call(t, "get", viaHTTP, protocol.GetParams{Path: "n/s"}, nil); e == nil || e.Code != protocol.CodeInvalidToken {
		t.Fatalf("local-only token accepted over http: %v", e)
	}

	// metadata survives into agent_list
	var lst protocol.AgentListResult
	mustOK(t, call(t, "agent_list", nil, nil, &lst))
	found := false
	for _, a := range lst.Agents {
		if a.Name == "localbot" {
			found = true
			if a.Type != "ci" || !a.LocalOnly || a.ExpiresAt == nil {
				t.Fatalf("metadata lost in listing: %+v", a)
			}
		}
	}
	if !found {
		t.Fatal("localbot not listed")
	}

	// a local-only parent's delegated child is also dead over http
	var del protocol.DelegateResult
	mustOK(t, call(t, "delegate", local, protocol.DelegateParams{Label: "kid", Patterns: []string{"n/**"}}, &del))
	childHTTP := &protocol.AgentAuth{Agent: "localbot", Token: del.Token, Transport: "http"}
	if e := call(t, "get", childHTTP, protocol.GetParams{Path: "n/s"}, nil); e == nil || e.Code != protocol.CodeInvalidToken {
		t.Fatalf("child of local-only parent accepted over http: %v", e)
	}
	childLocal := &protocol.AgentAuth{Agent: "localbot", Token: del.Token}
	mustOK(t, call(t, "get", childLocal, protocol.GetParams{Path: "n/s"}, &got))

	// expired agent token is rejected
	var res2 protocol.AgentAddResult
	mustOK(t, call(t, "agent_add", nil, protocol.AgentAddParams{Name: "ephemeral", Expires: "1ms"}, &res2))
	mustOK(t, call(t, "rule_add", nil, protocol.RuleAddParams{Agent: "ephemeral", Pattern: "n/**"}, nil))
	time.Sleep(10 * time.Millisecond)
	exp := &protocol.AgentAuth{Agent: "ephemeral", Token: res2.Token}
	if e := call(t, "get", exp, protocol.GetParams{Path: "n/s"}, nil); e == nil || e.Code != protocol.CodeInvalidToken {
		t.Fatalf("expired token accepted: %v", e)
	}
}

func TestCertIdentityAuth(t *testing.T) {
	startDaemon(t)
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil))
	mustOK(t, call(t, "put", nil, protocol.PutParams{Path: "m/s", Value: "v"}, nil))
	mustOK(t, call(t, "agent_add", nil, protocol.AgentAddParams{Name: "certbot"}, nil))
	mustOK(t, call(t, "rule_add", nil, protocol.RuleAddParams{Agent: "certbot", Pattern: "m/**"}, nil))

	// cert-asserted identity: no bearer token at all
	cert := &protocol.AgentAuth{Agent: "certbot", Cert: "spiffe://rutile/agent/certbot", Transport: "http"}
	if _, e := lastDaemon.resolveCaller(cert, uint32(os.Getuid()+1), true); e == nil || e.Code != protocol.CodeInvalidToken {
		t.Fatalf("untrusted socket peer forged cert identity: %v", e)
	}
	var got protocol.GetResult
	mustOK(t, call(t, "get", cert, protocol.GetParams{Path: "m/s"}, &got))
	if got.Value != "v" {
		t.Fatalf("value = %q", got.Value)
	}
	mismatch := &protocol.AgentAuth{Agent: "certbot", Cert: "spiffe://rutile/agent/other", Transport: "http"}
	if e := call(t, "get", mismatch, protocol.GetParams{Path: "m/s"}, nil); e == nil || e.Code != protocol.CodeInvalidToken {
		t.Fatalf("certificate/agent mismatch accepted: %v", e)
	}
	// unknown agent name in cert -> invalid_token
	bad := &protocol.AgentAuth{Agent: "ghost", Cert: "spiffe://rutile/agent/ghost", Transport: "http"}
	if e := call(t, "get", bad, protocol.GetParams{Path: "m/s"}, nil); e == nil || e.Code != protocol.CodeInvalidToken {
		t.Fatalf("unknown cert identity accepted: %v", e)
	}
	// cert identity still respects local-only over http
	mustOK(t, call(t, "agent_add", nil, protocol.AgentAddParams{Name: "certlocal", LocalOnly: true}, nil))
	lo := &protocol.AgentAuth{Agent: "certlocal", Cert: "spiffe://rutile/agent/certlocal", Transport: "http"}
	if e := call(t, "get", lo, protocol.GetParams{Path: "m/s"}, nil); e == nil || e.Code != protocol.CodeInvalidToken {
		t.Fatalf("local-only cert identity accepted over http: %v", e)
	}
	// policy still applies to cert identities
	if e := call(t, "get", cert, protocol.GetParams{Path: "q/other"}, nil); e == nil || e.Code != protocol.CodeDenied {
		t.Fatalf("cert identity bypassed policy: %v", e)
	}
}
