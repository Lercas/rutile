// Package ageio wraps filippo.io/age: identity generation, passphrase
// (scrypt) protection of the identity file, and store encrypt/decrypt.
package ageio

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/Lercas/rutile/internal/atomicfile"
)

const MaxPassphraseLen = 4096

const (
	MaxIdentityFileLen   = 2 << 20
	MaxRecipientsFileLen = 64 << 10
)

func readLimitedFile(path string, max int64) ([]byte, error) {
	return atomicfile.ReadLimited(path, max)
}

func ValidatePassphrase(passphrase string) error {
	if len(passphrase) < 8 {
		return errors.New("passphrase must be at least 8 bytes")
	}
	if len(passphrase) > MaxPassphraseLen {
		return errors.New("passphrase is too long (max 4096 bytes)")
	}
	return nil
}

// WriteFileAtomic durably replaces path with data from a same-directory temp
// file, so a crash cannot leave a truncated key metadata file.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	return atomicfile.Write(path, data, mode)
}

// GenerateIdentity creates a fresh X25519 identity.
func GenerateIdentity() (*age.X25519Identity, error) {
	return age.GenerateX25519Identity()
}

// SaveIdentityEncrypted writes the identity's secret key to path, encrypted
// with a passphrase-derived (scrypt) key.
func SaveIdentityEncrypted(path string, id *age.X25519Identity, passphrase string) error {
	if err := ValidatePassphrase(passphrase); err != nil {
		return err
	}
	rec, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rec)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, id.String()+"\n"); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return WriteFileAtomic(path, buf.Bytes(), 0o600)
}

// LoadIdentityEncrypted decrypts the identity file with the passphrase.
func LoadIdentityEncrypted(path, passphrase string) (*age.X25519Identity, error) {
	if err := ValidatePassphrase(passphrase); err != nil {
		return nil, err
	}
	data, err := readLimitedFile(path, MaxIdentityFileLen)
	if err != nil {
		return nil, err
	}
	sid, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(data), sid)
	if err != nil {
		return nil, fmt.Errorf("wrong passphrase or corrupted identity file: %w", err)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return age.ParseX25519Identity(strings.TrimSpace(string(raw)))
}

// SaveRecipients writes the public recipients file.
func SaveRecipients(path string, recipients ...age.Recipient) error {
	var b strings.Builder
	for _, r := range recipients {
		s, ok := r.(fmt.Stringer)
		if !ok {
			return fmt.Errorf("recipient %T cannot be serialized", r)
		}
		b.WriteString(s.String() + "\n")
	}
	return WriteFileAtomic(path, []byte(b.String()), 0o600)
}

// LoadRecipients parses the recipients file.
func LoadRecipients(path string) ([]age.Recipient, error) {
	data, err := readLimitedFile(path, MaxRecipientsFileLen)
	if err != nil {
		return nil, err
	}
	return age.ParseRecipients(bytes.NewReader(data))
}

// Encrypt encrypts plaintext for the given recipients.
func Encrypt(recipients []age.Recipient, plaintext []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decrypt decrypts ciphertext with the given identity.
func Decrypt(id age.Identity, ciphertext []byte) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), id)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}
