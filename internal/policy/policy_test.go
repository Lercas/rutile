package policy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Load(filepath.Join(t.TempDir(), "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPermanentRuleWinsRegardlessOfCreationOrder(t *testing.T) {
	for _, oneTimeFirst := range []bool{false, true} {
		name := "permanent-first"
		if oneTimeFirst {
			name = "one-time-first"
		}
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			addPermanent := func() {
				if _, err := s.Add("ci", "deploy/**", 0, false); err != nil {
					t.Fatal(err)
				}
			}
			addOneTime := func() {
				if _, err := s.Add("ci", "deploy/token", 0, true); err != nil {
					t.Fatal(err)
				}
			}
			if oneTimeFirst {
				addOneTime()
				addPermanent()
			} else {
				addPermanent()
				addOneTime()
			}
			d, _ := s.Evaluate("ci", "deploy/token")
			if !d.Allowed || d.OneTimePattern != "" {
				t.Fatalf("permanent rule should win without consumption: %+v", d)
			}
			if err := s.Consume("ci", "deploy/token", d.OneTimePattern); err != nil {
				t.Fatal(err)
			}
			for _, rule := range s.List() {
				if rule.OneTime && rule.Consumed {
					t.Fatal("one-time rule was consumed by a permanent grant")
				}
			}
		})
	}
}

func TestConsumeSaveFailureKeepsGrantActive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("ci", "deploy/token", 0, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Consume("ci", "deploy/token", "deploy/token"); err == nil {
		t.Fatal("expected persistence failure")
	}
	d, _ := s.Evaluate("ci", "deploy/token")
	if !d.Allowed {
		t.Fatal("failed persistence mutated in-memory grant")
	}
	if err := s.Consume("ci", "deploy/token", "missing"); !errors.Is(err, ErrGrantConsumed) {
		t.Fatalf("want ErrGrantConsumed, got %v", err)
	}
}

func TestEvaluateGlobs(t *testing.T) {
	s := newStore(t)
	if _, err := s.Add("claude", "dev/**", 0, false); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		agent, path string
		want        bool
	}{
		{"claude", "dev/nasoc/api-key", true},
		{"claude", "dev/x", true},
		{"claude", "prod/db", false},
		{"other", "dev/x", false},
	}
	for _, c := range cases {
		d, err := s.Evaluate(c.agent, c.path)
		if err != nil {
			t.Fatal(err)
		}
		if d.Allowed != c.want {
			t.Errorf("%s %s: got %v (%s), want %v", c.agent, c.path, d.Allowed, d.Reason, c.want)
		}
	}
}

func TestOneTimeConsumed(t *testing.T) {
	s := newStore(t)
	if _, err := s.Add("ci", "deploy/token", 0, true); err != nil {
		t.Fatal(err)
	}
	d1, _ := s.Evaluate("ci", "deploy/token")
	if !d1.Allowed {
		t.Fatal("first read should be allowed")
	}
	// Evaluate alone must not consume (e.g. store turned out to be locked)
	if d, _ := s.Evaluate("ci", "deploy/token"); !d.Allowed {
		t.Fatal("evaluate must not consume the one-time rule")
	}
	if err := s.Consume("ci", "deploy/token", "deploy/token"); err != nil {
		t.Fatal(err)
	}
	d2, _ := s.Evaluate("ci", "deploy/token")
	if d2.Allowed {
		t.Fatal("read after consume should be denied")
	}
	if d2.Reason != "rule_expired_or_consumed" {
		t.Errorf("reason = %s", d2.Reason)
	}
}

func TestExpiry(t *testing.T) {
	s := newStore(t)
	r, err := s.Add("claude", "dev/**", time.Millisecond, false)
	if err != nil {
		t.Fatal(err)
	}
	if r.ExpiresAt == nil {
		t.Fatal("expected expires_at")
	}
	time.Sleep(5 * time.Millisecond)
	d, _ := s.Evaluate("claude", "dev/x")
	if d.Allowed {
		t.Fatal("expired rule should not grant")
	}
}

func TestPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	s1, _ := Load(path)
	s1.Add("claude", "dev/**", 0, false)
	s2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := s2.Evaluate("claude", "dev/y"); !d.Allowed {
		t.Fatal("rule not persisted")
	}
	if n, _ := s2.Remove("claude", ""); n != 1 {
		t.Fatalf("removed %d", n)
	}
	s3, _ := Load(path)
	if d, _ := s3.Evaluate("claude", "dev/y"); d.Allowed {
		t.Fatal("removal not persisted")
	}
}
