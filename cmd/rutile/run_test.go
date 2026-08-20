package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/rutile/internal/ageio"
	"github.com/Lercas/rutile/internal/store"
)

func TestResolvePlaceholders(t *testing.T) {
	secrets := map[string]string{"dev/a": "AAA", "dev/b.c-d_e": "BBB"}
	get := func(p string) (string, error) {
		if v, ok := secrets[p]; ok {
			return v, nil
		}
		return "", errors.New("not found")
	}
	out, err := resolvePlaceholders([]string{
		"plain",
		"--token={{rutile:dev/a}}",
		"{{rutile:dev/a}}:{{rutile:dev/b.c-d_e}}",
	}, get)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"plain", "--token=AAA", "AAA:BBB"}
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("arg %d = %q, want %q", i, out[i], want[i])
		}
	}
	if _, err := resolvePlaceholders([]string{"{{rutile:missing/x}}"}, get); err == nil {
		t.Fatal("missing secret must fail the whole run")
	}
	// non-placeholder braces stay untouched
	out, err = resolvePlaceholders([]string{"{{other:thing}}"}, get)
	if err != nil || out[0] != "{{other:thing}}" {
		t.Fatalf("got %q err=%v", out[0], err)
	}
}

func TestBackupPreflightPreventsPartialCopy(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.WriteFile(filepath.Join(dir, "recipients.txt"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	files := []backupFile{
		{name: "identities.age", data: []byte("identity")},
		{name: "recipients.txt", data: []byte("recipient")},
	}
	if err := writeBackupFiles(root, files); err == nil {
		t.Fatal("backup overwrote a pre-existing destination")
	}
	if _, err := os.Stat(filepath.Join(dir, "identities.age")); !os.IsNotExist(err) {
		t.Fatalf("preflight left a partial identity backup: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "recipients.txt")); err != nil {
		t.Fatal(err)
	}
	if err := writeBackupFiles(root, files); err != nil {
		t.Fatalf("valid backup rejected: %v", err)
	}
	for _, file := range files {
		got, err := os.ReadFile(filepath.Join(dir, file.name))
		if err != nil || string(got) != string(file.data) {
			t.Fatalf("backup %s=%q err=%v", file.name, got, err)
		}
	}
}

func TestSecretInputAndGeneratedLengthBounds(t *testing.T) {
	got, err := readSecretInput(strings.NewReader("small-secret\n"))
	if err != nil || got != "small-secret" {
		t.Fatalf("valid secret input: got=%q err=%v", got, err)
	}
	if _, err := readSecretInput(strings.NewReader(strings.Repeat("x", store.MaxSecretValueLen+1))); err == nil {
		t.Fatal("oversized stdin secret accepted")
	}
	for _, length := range []int{-1, 0, store.MaxSecretValueLen + 1} {
		if err := validateGeneratedSecretLength(length); err == nil {
			t.Fatalf("invalid generated length %d accepted", length)
		}
	}
	if err := validateGeneratedSecretLength(24); err != nil {
		t.Fatalf("normal generated length rejected: %v", err)
	}
}

func TestInitPassphraseBoundAndKeyMaterialCommitOrder(t *testing.T) {
	if got, err := readInitPassphrase(strings.NewReader("valid-passphrase\n")); err != nil || got != "valid-passphrase" {
		t.Fatalf("valid piped passphrase: got=%q err=%v", got, err)
	}
	if _, err := readInitPassphrase(strings.NewReader(strings.Repeat("x", ageio.MaxPassphraseLen+1))); err == nil {
		t.Fatal("oversized piped passphrase accepted")
	}
	var order []string
	wantErr := errors.New("recipients failed")
	err := writeInitialKeyMaterial(
		func() error { order = append(order, "recipients"); return wantErr },
		func() error { order = append(order, "identity"); return nil },
	)
	if !errors.Is(err, wantErr) || strings.Join(order, ",") != "recipients" {
		t.Fatalf("identity written after recipients failure: order=%v err=%v", order, err)
	}
	order = nil
	if err := writeInitialKeyMaterial(
		func() error { order = append(order, "recipients"); return nil },
		func() error { order = append(order, "identity"); return nil },
	); err != nil || strings.Join(order, ",") != "recipients,identity" {
		t.Fatalf("valid key material order=%v err=%v", order, err)
	}
}

func TestArgvSecretRequiresExplicitOptIn(t *testing.T) {
	args := []string{"deploy", "--token={{rutile:prod/token}}"}
	if err := validateArgvSecretOptIn(args, false); err == nil {
		t.Fatal("argv secret accepted without opt-in")
	}
	if err := validateArgvSecretOptIn(args, true); err != nil {
		t.Fatalf("explicit argv opt-in rejected: %v", err)
	}
	if err := validateArgvSecretOptIn([]string{"deploy", "--safe"}, false); err != nil {
		t.Fatalf("ordinary argv rejected: %v", err)
	}
}

func TestOptionalAgentAuthFailsClosedOnPartialCredentials(t *testing.T) {
	if auth, err := optionalAgentAuth("", ""); err != nil || auth != nil {
		t.Fatalf("human mode rejected: auth=%v err=%v", auth, err)
	}
	for _, pair := range [][2]string{{"bot", ""}, {"", "rtl_token"}} {
		if auth, err := optionalAgentAuth(pair[0], pair[1]); err == nil || auth != nil {
			t.Fatalf("partial credentials downgraded: pair=%v auth=%v err=%v", pair, auth, err)
		}
	}
	auth, err := optionalAgentAuth("bot", "rtl_token")
	if err != nil || auth == nil || auth.Agent != "bot" || auth.Token != "rtl_token" {
		t.Fatalf("complete credentials rejected: auth=%+v err=%v", auth, err)
	}
}

func TestEnvironmentVariableNameValidation(t *testing.T) {
	for _, valid := range []string{"API_KEY", "_TOKEN", "A1"} {
		if !envNameRe.MatchString(valid) {
			t.Fatalf("valid env name %q rejected", valid)
		}
	}
	for _, invalid := range []string{"", "1TOKEN", "BAD-NAME", "A=B"} {
		if envNameRe.MatchString(invalid) {
			t.Fatalf("invalid env name %q accepted", invalid)
		}
	}
}
