package agents

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestAddVerifyMetadata(t *testing.T) {
	s := New(t.TempDir())
	token, err := s.Add("bot", "test bot", "ci", time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Get("bot")
	if err != nil {
		t.Fatal(err)
	}
	if a.Type != "ci" || !a.LocalOnly || a.ExpiresAt == nil {
		t.Fatalf("metadata lost: %+v", a)
	}
	if err := s.Verify("bot", token, ""); err != nil {
		t.Fatalf("local verify: %v", err)
	}
	// local-only token must be rejected on the HTTP transport
	if err := s.Verify("bot", token, "http"); err == nil {
		t.Fatal("local-only token accepted over http")
	}
	if _, err := s.FindByToken(token); err == nil {
		t.Fatal("local-only token resolvable at the HTTP door")
	}
	if err := s.Verify("bot", "rtl_wrong", ""); err == nil {
		t.Fatal("wrong token accepted")
	}
}

func TestExpiry(t *testing.T) {
	s := New(t.TempDir())
	token, err := s.Add("shortlived", "", "", time.Millisecond, false)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if err := s.Verify("shortlived", token, ""); err == nil {
		t.Fatal("expired token accepted")
	}
	if _, err := s.FindByToken(token); err == nil {
		t.Fatal("expired token resolvable at the HTTP door")
	}
}

func TestParseTTL(t *testing.T) {
	cases := map[string]time.Duration{"30d": 720 * time.Hour, "12h": 12 * time.Hour, "45m": 45 * time.Minute}
	for in, want := range cases {
		got, err := ParseTTL(in)
		if err != nil || got != want {
			t.Errorf("ParseTTL(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "d", "-3d", "0d", "-1h", "0s", "x"} {
		if _, err := ParseTTL(bad); err == nil {
			t.Errorf("ParseTTL(%q) accepted", bad)
		}
	}
}

func TestConcurrentAddSameNameReturnsOneToken(t *testing.T) {
	s := New(t.TempDir())
	const workers = 16
	var wg sync.WaitGroup
	results := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Add("same", "", "", 0, false)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful concurrent registrations=%d, want 1", successes)
	}
}

func TestEmbeddedAgentNameMustMatchFilename(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if _, err := s.Add("bot", "", "", 0, false); err != nil {
		t.Fatal(err)
	}
	a, err := s.Get("bot")
	if err != nil {
		t.Fatal(err)
	}
	a.Name = "admin"
	b, err := yaml.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bot.yaml"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("bot"); err == nil {
		t.Fatal("agent file with mismatched embedded name was accepted")
	}
	if _, err := s.List(); err == nil {
		t.Fatal("agent listing silently skipped corrupted identity state")
	}
}
