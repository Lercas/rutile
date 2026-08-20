package gitsync

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitCommitAndRuntimeIgnores(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	custom := "# user patterns\nprivate-notes.txt\n"
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(custom), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	ignore, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{"audit.log", "requests.yaml", "delegations.yaml", ".rutile-atomic-*"} {
		if strings.Count(string(ignore), pattern) != 1 {
			t.Fatalf("missing runtime ignore %q", pattern)
		}
	}
	if !strings.HasPrefix(string(ignore), custom) {
		t.Fatalf("custom ignore content was replaced: %q", ignore)
	}
	if err := os.WriteFile(filepath.Join(dir, "recipients.txt"), []byte("recipient\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Commit(dir, "test state"); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("git", "-C", dir, "log", "-1", "--pretty=%s").Output()
	if err != nil || strings.TrimSpace(string(out)) != "test state" {
		t.Fatalf("last commit=%q err=%v", out, err)
	}
}
