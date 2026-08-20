package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateSecurePath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secure")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "identity")
	if err := os.WriteFile(file, []byte("encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateSecurePath(dir, 0o700, true); err != nil {
		t.Fatalf("valid directory rejected: %v", err)
	}
	if err := validateSecurePath(file, 0o600, false); err != nil {
		t.Fatalf("valid file rejected: %v", err)
	}
	if err := validateSecurePath(filepath.Join(dir, "missing"), 0o600, false); err == nil {
		t.Fatal("missing file accepted")
	}
	if err := os.Chmod(file, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := validateSecurePath(file, 0o600, false); err == nil {
		t.Fatal("wrong exact mode accepted")
	}
	if err := validateSecurePath(dir, 0o700, false); err == nil {
		t.Fatal("directory accepted as regular file")
	}
	link := filepath.Join(dir, "identity-link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if err := validateSecurePath(link, 0o600, false); err == nil {
		t.Fatal("symlink accepted as secure file")
	}
}
