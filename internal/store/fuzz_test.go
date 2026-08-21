package store

import (
	"path/filepath"
	"strings"
	"testing"
)

// FuzzValidatePath asserts the core safety invariant: any accepted path
// must resolve strictly inside the store root.
func FuzzValidatePath(f *testing.F) {
	for _, seed := range []string{
		"dev/a", "../x", "a/../../b", "a//b", "/abs", "a/./b",
		"..", ".", "a\x00b", "семь", "a/b/c/d/e", "~/x", "a\\..\\b",
	} {
		f.Add(seed)
	}
	root := "/store/root"
	f.Fuzz(func(t *testing.T, p string) {
		if err := ValidatePath(p); err != nil {
			return
		}
		resolved := filepath.Clean(filepath.Join(root, filepath.FromSlash(p)+".age"))
		if !strings.HasPrefix(resolved, root+string(filepath.Separator)) {
			t.Fatalf("accepted path %q escapes the store root: %s", p, resolved)
		}
	})
}
