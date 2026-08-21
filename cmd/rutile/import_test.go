package main

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"github.com/Lercas/rutile/internal/store"
)

func TestImportValueBoundsAndNormalization(t *testing.T) {
	got, err := normalizeImportedSecret([]byte("secret\n"))
	if err != nil || got != "secret" {
		t.Fatalf("normal import value=%q err=%v", got, err)
	}
	if _, err := normalizeImportedSecret([]byte(strings.Repeat("x", store.MaxSecretValueLen+1))); err == nil {
		t.Fatal("oversized imported secret accepted")
	}
	if got, err := readLimited(bytes.NewBufferString("abcd"), 4); err != nil || string(got) != "abcd" {
		t.Fatalf("input at limit=%q err=%v", got, err)
	}
	if _, err := readLimited(bytes.NewBufferString("abcde"), 4); err == nil {
		t.Fatal("oversized reader accepted")
	}
	if out, err := commandOutputLimited(exec.Command("sh", "-c", "printf abcd"), 4); err != nil || string(out) != "abcd" {
		t.Fatalf("bounded command output=%q err=%v", out, err)
	}
	if _, err := commandOutputLimited(exec.Command("sh", "-c", "printf abcde"), 4); err == nil {
		t.Fatal("oversized command output accepted")
	}
}
