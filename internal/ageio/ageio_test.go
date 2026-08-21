package ageio

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestPassphraseBounds(t *testing.T) {
	for _, invalid := range []string{"short", strings.Repeat("x", MaxPassphraseLen+1)} {
		if err := ValidatePassphrase(invalid); err == nil {
			t.Fatalf("invalid passphrase length %d accepted", len(invalid))
		}
	}
	if err := ValidatePassphrase("valid-passphrase"); err != nil {
		t.Fatalf("valid passphrase rejected: %v", err)
	}
}

func TestOversizedKeyMetadataRejected(t *testing.T) {
	dir := t.TempDir()
	identity := filepath.Join(dir, "identity")
	if err := os.WriteFile(identity, make([]byte, MaxIdentityFileLen+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentityEncrypted(identity, "valid-passphrase"); err == nil {
		t.Fatal("oversized identity file accepted")
	}
	recipients := filepath.Join(dir, "recipients")
	if err := os.WriteFile(recipients, make([]byte, MaxRecipientsFileLen+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecipients(recipients); err == nil {
		t.Fatal("oversized recipients file accepted")
	}
}

func TestIdentityRoundTrip(t *testing.T) {
	dir := t.TempDir()
	idFile := filepath.Join(dir, "identities.age")
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveIdentityEncrypted(idFile, id, "correct horse"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentityEncrypted(idFile, "wrong"); err == nil {
		t.Fatal("expected error with wrong passphrase")
	}
	loaded, err := LoadIdentityEncrypted(idFile, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.String() != id.String() {
		t.Fatal("loaded identity differs from saved")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	id, _ := GenerateIdentity()
	ct, err := Encrypt([]age.Recipient{id.Recipient()}, []byte("s3cret\n"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt(id, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "s3cret\n" {
		t.Fatalf("got %q", pt)
	}
	other, _ := GenerateIdentity()
	if _, err := Decrypt(other, ct); err == nil {
		t.Fatal("expected decrypt failure with wrong identity")
	}
}

func TestRecipientsFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "recipients.txt")
	id, _ := GenerateIdentity()
	if err := SaveRecipients(f, id.Recipient()); err != nil {
		t.Fatal(err)
	}
	recs, err := LoadRecipients(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d recipients", len(recs))
	}
	ct, err := Encrypt(recs, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := Decrypt(id, ct); err != nil || string(pt) != "x" {
		t.Fatalf("roundtrip via recipients file failed: %v %q", err, pt)
	}
}
