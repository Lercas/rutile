package requests

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestRequestLifecyclePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requests.yaml")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Add("bot", "prod/db", "deploy")
	if err != nil {
		t.Fatal(err)
	}
	dup, err := s.Add("bot", "prod/db", "different reason")
	if err != nil || dup.ID != r.ID {
		t.Fatalf("duplicate=%+v err=%v", dup, err)
	}
	if len(r.ID) != 32 {
		t.Fatalf("request id has %d hex chars, want 32", len(r.ID))
	}
	taken, err := s.Take(r.ID)
	if err != nil || taken.ID != r.ID {
		t.Fatalf("take=%+v err=%v", taken, err)
	}
	if err := s.Restore(taken); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(path)
	if err != nil || len(reloaded.List()) != 1 || reloaded.List()[0].ID != r.ID {
		t.Fatalf("restored request not persisted: %+v err=%v", reloaded.List(), err)
	}
}

func TestPendingRequestQuotas(t *testing.T) {
	t.Run("per agent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "requests.yaml")
		s, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < MaxPendingPerAgent; i++ {
			s.items = append(s.items, Request{
				ID: fmt.Sprintf("%032x", i), Agent: "bot", Path: fmt.Sprintf("dev/%d", i), CreatedAt: time.Now(),
			})
		}
		if _, err := s.Add("bot", "dev/overflow", "quota probe"); err == nil {
			t.Fatal("per-agent pending request quota was not enforced")
		}
	})

	t.Run("total", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "requests.yaml")
		s, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < MaxPendingTotal; i++ {
			s.items = append(s.items, Request{
				ID: fmt.Sprintf("%032x", i), Agent: fmt.Sprintf("bot-%d", i), Path: fmt.Sprintf("dev/%d", i), CreatedAt: time.Now(),
			})
		}
		if _, err := s.Add("new-bot", "dev/overflow", "quota probe"); err == nil {
			t.Fatal("total pending request quota was not enforced")
		}
	})
}
