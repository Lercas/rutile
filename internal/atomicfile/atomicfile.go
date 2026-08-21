// Package atomicfile provides durable same-directory file replacement.
package atomicfile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ReadLimited reads one regular non-symlink file with an allocation bound.
func ReadLimited(path string, max int64) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing non-regular or symbolic-link file: %s", path)
	}
	if st.Size() > max {
		return nil, fmt.Errorf("%s is too large (max %d bytes)", path, max)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s grew beyond %d bytes while reading", path, max)
	}
	return b, nil
}

// Write replaces path only after data and its parent directory have been
// synced. A unique temporary file makes concurrent writers safe from sharing
// or truncating the same staging path.
func Write(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".rutile-atomic-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// WriteRoot is the root-confined counterpart of Write. Parent creation and
// replacement are both resolved beneath root, so a symlink cannot redirect a
// security-state write outside the opened tree.
func WriteRoot(root *os.Root, path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := root.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var tmp *os.File
	var tmpName string
	for range 10 {
		random := make([]byte, 12)
		if _, err := rand.Read(random); err != nil {
			return err
		}
		tmpName = filepath.Join(dir, ".rutile-atomic-"+hex.EncodeToString(random))
		f, err := root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return err
		}
		tmp = f
		break
	}
	if tmp == nil {
		return errors.New("could not allocate a unique atomic staging file")
	}
	defer root.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := root.Rename(tmpName, path); err != nil {
		return err
	}
	d, err := root.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// WriteExclusive durably creates path and never replaces an existing file.
func WriteExclusive(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".rutile-exclusive-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpName, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
