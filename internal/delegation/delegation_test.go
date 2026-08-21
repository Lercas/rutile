package delegation

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lercas/rutile/internal/store"
)

func TestDelegationLifecycleAndBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delegations.yaml")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	d, token, err := s.Create("parent", "worker", []string{"dev/**"}, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.ID) != 32 || d.ExpiresAt.Sub(d.CreatedAt) != MaxTTL {
		t.Fatalf("bad delegation id/ttl: %+v", d)
	}
	found, err := s.FindByToken(token)
	if err != nil || found.ID != d.ID {
		t.Fatalf("find=%+v err=%v", found, err)
	}
	reloaded, err := Load(path)
	if err != nil || len(reloaded.List()) != 1 {
		t.Fatalf("delegation not persisted: %+v err=%v", reloaded.List(), err)
	}
	if err := reloaded.Revoke(d.ID, "other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other parent revoked delegation: %v", err)
	}
	if err := reloaded.Revoke(d.ID, "parent"); err != nil {
		t.Fatal(err)
	}
	if _, err := reloaded.FindByToken(token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked token still valid: %v", err)
	}
}

func TestActiveDelegationQuotas(t *testing.T) {
	now := time.Now().UTC()
	t.Run("per parent", func(t *testing.T) {
		s, err := Load(filepath.Join(t.TempDir(), "delegations.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < MaxActivePerParent; i++ {
			s.items = append(s.items, Delegation{ID: fmt.Sprint(i), Parent: "parent", ExpiresAt: now.Add(time.Hour)})
		}
		if _, _, err := s.Create("parent", "worker", []string{"dev/**"}, time.Minute); err == nil {
			t.Fatal("per-parent delegation quota was not enforced")
		}
	})
	t.Run("total", func(t *testing.T) {
		s, err := Load(filepath.Join(t.TempDir(), "delegations.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < MaxActiveTotal; i++ {
			s.items = append(s.items, Delegation{ID: fmt.Sprint(i), Parent: fmt.Sprintf("parent-%d", i), ExpiresAt: now.Add(time.Hour)})
		}
		if _, _, err := s.Create("new-parent", "worker", []string{"dev/**"}, time.Minute); err == nil {
			t.Fatal("total delegation quota was not enforced")
		}
	})
	t.Run("expired entries do not count", func(t *testing.T) {
		s, err := Load(filepath.Join(t.TempDir(), "delegations.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < MaxActivePerParent; i++ {
			s.items = append(s.items, Delegation{ID: fmt.Sprint(i), Parent: "parent", ExpiresAt: now.Add(-time.Hour)})
		}
		if _, _, err := s.Create("parent", "worker", []string{"dev/**"}, time.Minute); err != nil {
			t.Fatalf("expired delegations exhausted quota: %v", err)
		}
	})
}

func TestDelegationPatternValidation(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "delegations.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	tooMany := make([]string, 65)
	for i := range tooMany {
		tooMany[i] = "dev/**"
	}
	tests := []struct {
		name     string
		patterns []string
	}{
		{name: "too many", patterns: tooMany},
		{name: "too long", patterns: []string{strings.Repeat("a", store.MaxPathLen+1)}},
		{name: "too many bytes", patterns: []string{
			strings.Repeat("a", 1024), strings.Repeat("b", 1024), strings.Repeat("c", 1024),
			strings.Repeat("d", 1024), "extra",
		}},
		{name: "invalid syntax", patterns: []string{"dev/["}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := s.Create("parent", "worker", tt.patterns, time.Minute); err == nil {
				t.Fatalf("accepted invalid patterns: %#v", tt.patterns)
			}
		})
	}
	if _, _, err := s.Create("parent", "worker", []string{"dev/**"}, time.Minute); err != nil {
		t.Fatalf("rejected valid control pattern: %v", err)
	}
}
