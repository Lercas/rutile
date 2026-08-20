// Package store manages the tree of encrypted secret files
// (store/<path>.age), mirroring the pass/passage on-disk layout.
package store

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Lercas/rutile/internal/atomicfile"
)

var ErrNotFound = errors.New("secret not found")

var validSegment = regexp.MustCompile(`^[a-zA-Z0-9._@-]+$`)

const (
	MaxPathLen    = 1024
	MaxSegmentLen = 255
	// MaxSecretValueLen leaves headroom inside the 4 MiB JSONL RPC frame even
	// when every input byte requires a six-byte JSON escape.
	MaxSecretValueLen = 512 << 10
	MaxCiphertextLen  = MaxSecretValueLen + 64<<10
)

type Store struct {
	dir string
}

func New(dir string) *Store { return &Store{dir: dir} }

// ValidatePath rejects traversal and odd characters. Paths look like
// "dev/nasoc/api-key": slash-separated segments, no leading/trailing slash.
func ValidatePath(p string) error {
	if p == "" {
		return errors.New("empty secret path")
	}
	if len(p) > MaxPathLen {
		return errors.New("secret path is too long (max 1024 bytes)")
	}
	if strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return errors.New("secret path must not start or end with '/'")
	}
	for _, seg := range strings.Split(p, "/") {
		if len(seg) > MaxSegmentLen {
			return errors.New("secret path segment is too long (max 255 bytes)")
		}
		if seg == "." || seg == ".." || !validSegment.MatchString(seg) {
			return errors.New("secret path segments may only contain letters, digits, '.', '_', '@', '-'")
		}
	}
	return nil
}

func ValidateSecretValue(value string) error {
	if len(value) > MaxSecretValueLen {
		return errors.New("secret value is too large (max 512 KiB)")
	}
	return nil
}

func relativeFile(p string) string { return filepath.FromSlash(p) + ".age" }

func (s *Store) openRoot(create bool) (*os.Root, error) {
	if create {
		if err := os.MkdirAll(s.dir, 0o700); err != nil {
			return nil, err
		}
	}
	st, err := os.Lstat(s.dir)
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return nil, fmt.Errorf("store root must be a real directory: %s", s.dir)
	}
	return os.OpenRoot(s.dir)
}

func (s *Store) Write(p string, ciphertext []byte) error {
	if err := ValidatePath(p); err != nil {
		return err
	}
	root, err := s.openRoot(true)
	if err != nil {
		return err
	}
	defer root.Close()
	return atomicfile.WriteRoot(root, relativeFile(p), ciphertext, 0o600)
}

func (s *Store) Read(p string) ([]byte, error) {
	if err := ValidatePath(p); err != nil {
		return nil, err
	}
	root, err := s.openRoot(false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.Open(relativeFile(p))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxCiphertextLen+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxCiphertextLen {
		return nil, errors.New("encrypted secret is too large")
	}
	return data, nil
}

func (s *Store) Exists(p string) bool {
	if ValidatePath(p) != nil {
		return false
	}
	root, err := s.openRoot(false)
	if err != nil {
		return false
	}
	defer root.Close()
	st, err := root.Lstat(relativeFile(p))
	return err == nil && st.Mode().IsRegular()
}

func (s *Store) Remove(p string) error {
	if err := ValidatePath(p); err != nil {
		return err
	}
	root, err := s.openRoot(false)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	defer root.Close()
	rel := relativeFile(p)
	err = root.Remove(rel)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	// prune now-empty parent directories up to the store root
	for d := filepath.Dir(rel); d != "."; d = filepath.Dir(d) {
		if root.Remove(d) != nil {
			break
		}
	}
	return nil
}

// List returns all secret paths, optionally filtered by prefix.
func (s *Store) List(prefix string) ([]string, error) {
	root, err := s.openRoot(false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	var out []string
	err = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic link is not allowed in encrypted store: %s", path)
		}
		if d.IsDir() || !strings.HasSuffix(path, ".age") {
			return nil
		}
		p := strings.TrimSuffix(filepath.ToSlash(path), ".age")
		if prefix == "" || p == prefix || strings.HasPrefix(p, prefix+"/") {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}
