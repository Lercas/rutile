package atomicfile

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestWriteAtomicUnderConcurrency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.yaml")
	a := bytes.Repeat([]byte("a"), 64*1024)
	b := bytes.Repeat([]byte("b"), 64*1024)
	var wg sync.WaitGroup
	for _, data := range [][]byte{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := Write(path, data, 0o600); err != nil {
				t.Errorf("Write: %v", err)
			}
		}()
	}
	wg.Wait()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, a) && !bytes.Equal(got, b) {
		t.Fatal("concurrent write produced partial or interleaved content")
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v", st.Mode().Perm())
	}
}

func TestReadLimitedRejectsOversizeAndSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state")
	if err := os.WriteFile(path, []byte("abcd"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadLimited(path, 4); err != nil || string(got) != "abcd" {
		t.Fatalf("bounded read=%q err=%v", got, err)
	}
	if _, err := ReadLimited(path, 3); err == nil {
		t.Fatal("oversized file accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLimited(link, 4); err == nil {
		t.Fatal("symbolic-link file accepted")
	}
}
