package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAppendVerifyReopen(t *testing.T) {
	f := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(f)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := l.Append(Entry{ActorType: "human", Actor: "cli", Action: "get", Path: "dev/a", Result: "granted"}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := Verify(f)
	if err != nil || n != 5 {
		t.Fatalf("verify: n=%d err=%v", n, err)
	}
	// reopen continues the chain
	l2, err := Open(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.Append(Entry{ActorType: "agent", Actor: "claude", Action: "get", Result: "denied"}); err != nil {
		t.Fatal(err)
	}
	if n, err := Verify(f); err != nil || n != 6 {
		t.Fatalf("verify after reopen: n=%d err=%v", n, err)
	}
	tail, err := Tail(f, 2)
	if err != nil || len(tail) != 2 || tail[1].Actor != "claude" {
		t.Fatalf("tail: %v %+v", err, tail)
	}
}

func TestRotateCheckpointFailureLeavesActiveChainIntact(t *testing.T) {
	f := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(f)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := l.Append(Entry{ActorType: "human", Actor: "cli", Action: "get", Result: "granted"}); err != nil {
			t.Fatal(err)
		}
	}
	original, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	l.writeCheckpoint = func(string, []byte, os.FileMode) error {
		return errors.New("injected checkpoint failure")
	}
	archive, n, err := l.Rotate()
	if err == nil || n != 2 || archive == "" {
		t.Fatalf("rotate result: archive=%q n=%d err=%v", archive, n, err)
	}
	current, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, original) {
		t.Fatal("failed rotation changed the active audit chain")
	}
	if n, err := Verify(f); err != nil || n != 2 {
		t.Fatalf("active chain after failure: n=%d err=%v", n, err)
	}
	if n, err := Verify(archive); err != nil || n != 2 {
		t.Fatalf("archive after failure: n=%d err=%v", n, err)
	}
	if err := l.Append(Entry{ActorType: "human", Actor: "cli", Action: "lock", Result: "granted"}); err == nil {
		t.Fatal("log accepted an append after ambiguous checkpoint persistence")
	}
	reopened, err := Open(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Append(Entry{ActorType: "human", Actor: "cli", Action: "lock", Result: "granted"}); err != nil {
		t.Fatal(err)
	}
	if n, err := Verify(f); err != nil || n != 3 {
		t.Fatalf("reopened active chain not appendable: n=%d err=%v", n, err)
	}
}

func TestAmbiguousAppendFailureRequiresVerifiedReopen(t *testing.T) {
	f := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(f)
	if err != nil {
		t.Fatal(err)
	}
	l.appendRecord = func(path string, data []byte, mode os.FileMode) error {
		if err := durableAppend(path, data, mode); err != nil {
			return err
		}
		return errors.New("injected error after durable write")
	}
	entry := Entry{ActorType: "agent", Actor: "bot", Action: "get", Result: "denied"}
	if err := l.Append(entry); err == nil {
		t.Fatal("injected append failure was accepted")
	}
	before, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	l.appendRecord = durableAppend
	if err := l.Append(entry); err == nil {
		t.Fatal("poisoned in-memory chain accepted a second append")
	}
	after, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("fail-stop log changed before a verified reopen")
	}
	reopened, err := Open(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Append(Entry{ActorType: "human", Actor: "cli", Action: "unlock", Result: "granted"}); err != nil {
		t.Fatal(err)
	}
	if n, err := Verify(f); err != nil || n != 2 {
		t.Fatalf("verified reopen did not resume the chain: n=%d err=%v", n, err)
	}
}

func TestRotatePathWithoutLogSuffix(t *testing.T) {
	f := filepath.Join(t.TempDir(), "audit")
	l, err := Open(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Append(Entry{ActorType: "human", Actor: "cli", Action: "lock", Result: "granted"}); err != nil {
		t.Fatal(err)
	}
	archive, n, err := l.Rotate()
	if err != nil || n != 1 || archive == "" {
		t.Fatalf("rotate path without suffix: archive=%q n=%d err=%v", archive, n, err)
	}
	if n, err := Verify(archive); err != nil || n != 1 {
		t.Fatalf("archive invalid: n=%d err=%v", n, err)
	}
}

func TestTamperDetected(t *testing.T) {
	f := filepath.Join(t.TempDir(), "audit.log")
	l, _ := Open(f)
	for i := 0; i < 3; i++ {
		if err := l.Append(Entry{ActorType: "human", Actor: "cli", Action: "get", Path: "p", Result: "granted"}); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(f)
	// flip a byte inside the second line's payload
	tampered := bytes.Replace(data, []byte(`"result":"granted"`), []byte(`"result":"denied!"`), 2)
	tampered = bytes.Replace(tampered, []byte(`"result":"denied!"`), []byte(`"result":"granted"`), 1)
	if bytes.Equal(tampered, data) {
		t.Fatal("test setup failed to tamper")
	}
	if err := os.WriteFile(f, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(f); err == nil {
		t.Fatal("tampering not detected")
	}
}

func TestDeletionDetected(t *testing.T) {
	f := filepath.Join(t.TempDir(), "audit.log")
	l, _ := Open(f)
	for i := 0; i < 3; i++ {
		_ = l.Append(Entry{ActorType: "human", Actor: "cli", Action: "get", Result: "granted"})
	}
	data, _ := os.ReadFile(f)
	lines := bytes.SplitN(data, []byte("\n"), 3)
	// drop the middle line
	_ = os.WriteFile(f, append(append([]byte{}, lines[0]...), append([]byte("\n"), lines[2]...)...), 0o600)
	if _, err := Verify(f); err == nil {
		t.Fatal("deleted line not detected")
	}
}

func TestOpenRejectsTamperedChain(t *testing.T) {
	f := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Append(Entry{ActorType: "agent", Actor: "bot", Action: "get", Result: "granted"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	b = bytes.Replace(b, []byte(`"actor":"bot"`), []byte(`"actor":"evil"`), 1)
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(f); err == nil {
		t.Fatal("tampered chain reopened")
	}
}
