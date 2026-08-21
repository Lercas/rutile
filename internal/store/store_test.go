package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidatePath(t *testing.T) {
	bad := []string{"", "/abs", "trail/", "../up", "a/../b", "a//b", "a/./b", "sp ace", "семь", "a\x00b"}
	for _, p := range bad {
		if ValidatePath(p) == nil {
			t.Errorf("expected %q to be rejected", p)
		}
	}
	good := []string{"a", "dev/nasoc/api-key", "x_1/y.2/z@3", "UPPER/case-OK"}
	for _, p := range good {
		if err := ValidatePath(p); err != nil {
			t.Errorf("expected %q to be accepted: %v", p, err)
		}
	}
}

func TestTraversalCannotEscape(t *testing.T) {
	dir := t.TempDir()
	s := New(filepath.Join(dir, "store"))
	if err := s.Write("../escape", []byte("x")); err == nil {
		t.Fatal("traversal write accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "escape.age")); err == nil {
		t.Fatal("file escaped the store root")
	}
}

func TestCRUDAndList(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "store"))
	for _, p := range []string{"dev/a", "dev/sub/b", "prod/c"} {
		if err := s.Write(p, []byte("ct-"+p)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Read("dev/sub/b")
	if err != nil || string(got) != "ct-dev/sub/b" {
		t.Fatalf("read: %v %q", err, got)
	}
	if _, err := s.Read("nope"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	all, err := s.List("")
	if err != nil || len(all) != 3 {
		t.Fatalf("list all: %v %v", err, all)
	}
	dev, _ := s.List("dev")
	if len(dev) != 2 {
		t.Fatalf("list dev: %v", dev)
	}
	if err := s.Remove("dev/sub/b"); err != nil {
		t.Fatal(err)
	}
	if s.Exists("dev/sub/b") {
		t.Fatal("still exists after remove")
	}
	// empty parent dir pruned
	if _, err := os.Stat(filepath.Join(s.dir, "dev/sub")); !os.IsNotExist(err) {
		t.Fatal("empty parent dir not pruned")
	}
}

func TestSymlinkCannotEscapeStoreRoot(t *testing.T) {
	base := t.TempDir()
	storeDir := filepath.Join(base, "store")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(outside, "victim.age")
	if err := os.WriteFile(victim, []byte("outside-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(storeDir, "escape")); err != nil {
		t.Fatal(err)
	}
	s := New(storeDir)
	if err := s.Write("escape/victim", []byte("overwritten")); err == nil {
		t.Fatal("store write followed a symlink outside the root")
	}
	got, err := os.ReadFile(victim)
	if err != nil || string(got) != "outside-data" {
		t.Fatalf("outside file changed: %q err=%v", got, err)
	}
	if _, err := s.Read("escape/victim"); err == nil {
		t.Fatal("store read followed a symlink outside the root")
	}
	if _, err := s.List(""); err == nil {
		t.Fatal("store listing silently accepted a symlink")
	}
	if err := os.Remove(filepath.Join(storeDir, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := s.Write("safe/nested", []byte("ciphertext")); err != nil {
		t.Fatalf("legitimate nested write rejected: %v", err)
	}
	if got, err := s.Read("safe/nested"); err != nil || string(got) != "ciphertext" {
		t.Fatalf("legitimate nested read=%q err=%v", got, err)
	}
}

func TestOversizedCiphertextRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	s := New(dir)
	if err := s.Write("valid", []byte("small")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "oversized.age"), make([]byte, MaxCiphertextLen+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read("oversized"); err == nil {
		t.Fatal("oversized ciphertext accepted")
	}
	if got, err := s.Read("valid"); err != nil || string(got) != "small" {
		t.Fatalf("valid ciphertext=%q err=%v", got, err)
	}
}
