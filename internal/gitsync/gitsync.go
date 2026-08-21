// Package gitsync versions the rutile home directory with git by
// shelling out to the git binary (same approach as pass/passage/gopass).
// All operations are best-effort: a missing git binary disables versioning
// but never blocks secret operations.
package gitsync

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Lercas/rutile/internal/atomicfile"
)

var runtimeIgnorePatterns = []string{
	"daemon.sock", "daemon.log", "audit.log", "audit-*.log",
	"requests.yaml", "delegations.yaml", "identities.age.bak*",
	".edit-*", ".rutile-atomic-*", "*.tmp",
}

func gitAvailable() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

func run(dir string, args ...string) error {
	// a committer identity is supplied inline so auto-commits work on
	// machines (CI runners, fresh hosts) with no global git config
	full := append([]string{"-c", "user.name=rutile", "-c", "user.email=rutile@localhost"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git %v: %s", args, out)
	}
	return nil
}

func mergeRuntimeIgnores(existing []byte) []byte {
	text := string(existing)
	seen := make(map[string]bool)
	for _, line := range strings.Split(text, "\n") {
		seen[strings.TrimSpace(line)] = true
	}
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	for _, pattern := range runtimeIgnorePatterns {
		if !seen[pattern] {
			text += pattern + "\n"
		}
	}
	return []byte(text)
}

// Init creates the repo and merges required runtime ignores without replacing
// any pre-existing user patterns.
func Init(dir string) error {
	if !gitAvailable() {
		return nil
	}
	// runtime/local-only state: the audit chain is per-machine (syncing it
	// between hosts guarantees merge conflicts), requests are transient
	ignorePath := filepath.Join(dir, ".gitignore")
	existing, err := atomicfile.ReadLimited(ignorePath, 1<<20)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := atomicfile.Write(ignorePath, mergeRuntimeIgnores(existing), 0o600); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		return nil
	}
	if err := run(dir, "init", "-q"); err != nil {
		return err
	}
	return Commit(dir, "init rutile store")
}

// Commit stages everything and commits; a clean tree is not an error.
func Commit(dir, message string) error {
	if !gitAvailable() {
		return nil
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return nil
	}
	if err := run(dir, "add", "-A"); err != nil {
		return err
	}
	if err := exec.Command("git", "-C", dir, "diff", "--cached", "--quiet").Run(); err == nil {
		return nil // nothing staged
	}
	return run(dir, "commit", "-q", "-m", message)
}

// Passthrough runs an arbitrary git command in dir, wired to the terminal.
func Passthrough(dir string, args []string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}
