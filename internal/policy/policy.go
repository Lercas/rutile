// Package policy stores and evaluates agent access rules (policy.yaml).
// A rule grants one agent read access to paths matching one doublestar
// pattern; it may expire (--for) or be consumed after a single read
// (--one-time). Humans (CLI) bypass policy entirely.
package policy

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Lercas/rutile/internal/atomicfile"
	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"
)

var ErrGrantConsumed = errors.New("one-time grant is no longer active")

const MaxPolicyFileLen = 4 << 20

type Rule struct {
	Agent     string     `yaml:"agent"`
	Pattern   string     `yaml:"pattern"`
	OneTime   bool       `yaml:"one_time,omitempty"`
	Consumed  bool       `yaml:"consumed,omitempty"`
	CreatedAt time.Time  `yaml:"created_at"`
	ExpiresAt *time.Time `yaml:"expires_at,omitempty"`
}

func (r Rule) active(now time.Time) bool {
	if r.OneTime && r.Consumed {
		return false
	}
	if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
		return false
	}
	return true
}

type policyFile struct {
	Version int    `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

type Store struct {
	mu    sync.Mutex
	path  string
	rules []Rule
}

func Load(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := atomicfile.ReadLimited(path, MaxPolicyFileLen)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var pf policyFile
	if err := yaml.Unmarshal(b, &pf); err != nil {
		return nil, fmt.Errorf("invalid policy file: %w", err)
	}
	s.rules = pf.Rules
	return s, nil
}

func (s *Store) save(rules []Rule) error {
	b, err := yaml.Marshal(policyFile{Version: 1, Rules: rules})
	if err != nil {
		return err
	}
	if len(b) > MaxPolicyFileLen {
		return errors.New("policy state exceeds 4 MiB limit")
	}
	return atomicfile.Write(s.path, b, 0o600)
}

func (s *Store) Add(agent, pattern string, ttl time.Duration, oneTime bool) (Rule, error) {
	if _, err := doublestar.Match(pattern, "x"); err != nil {
		return Rule{}, fmt.Errorf("invalid pattern %q: %w", pattern, err)
	}
	r := Rule{
		Agent:     agent,
		Pattern:   pattern,
		OneTime:   oneTime,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if ttl > 0 {
		t := r.CreatedAt.Add(ttl)
		r.ExpiresAt = &t
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := append(append([]Rule(nil), s.rules...), r)
	if err := s.save(next); err != nil {
		return Rule{}, err
	}
	s.rules = next
	return r, nil
}

// Remove deletes rules for agent; pattern=="" removes all of the agent's rules.
func (s *Store) Remove(agent, pattern string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := make([]Rule, 0, len(s.rules))
	removed := 0
	for _, r := range s.rules {
		if r.Agent == agent && (pattern == "" || r.Pattern == pattern) {
			removed++
			continue
		}
		kept = append(kept, r)
	}
	if removed == 0 {
		return 0, nil
	}
	if err := s.save(kept); err != nil {
		return 0, err
	}
	s.rules = kept
	return removed, nil
}

func (s *Store) List() []Rule {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Rule(nil), s.rules...)
}

// Decision explains an Evaluate outcome.
type Decision struct {
	Allowed        bool
	Reason         string
	OneTimePattern string
}

// Evaluate checks read access without consuming one-time rules — call
// Consume only after the secret has been found and decrypted, but before it
// is returned, so locked/missing reads do not burn a grant and concurrent
// successful reads linearize on durable consumption.
func (s *Store) Evaluate(agent, path string) (Decision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	sawInactive := false
	var oneTimePattern string
	for i := range s.rules {
		r := &s.rules[i]
		if r.Agent != agent {
			continue
		}
		ok, _ := doublestar.Match(r.Pattern, path)
		if !ok {
			continue
		}
		if !r.active(now) {
			sawInactive = true
			continue
		}
		if r.OneTime {
			// Remember a one-time grant, but keep looking: any permanent
			// matching rule must win regardless of creation order so a read that
			// is already permanently allowed cannot burn a limited grant.
			if oneTimePattern == "" {
				oneTimePattern = r.Pattern
			}
			continue
		}
		return Decision{Allowed: true, Reason: "rule:" + r.Pattern}, nil
	}
	if oneTimePattern != "" {
		return Decision{Allowed: true, Reason: "one_time:" + oneTimePattern, OneTimePattern: oneTimePattern}, nil
	}
	if sawInactive {
		return Decision{Reason: "rule_expired_or_consumed"}, nil
	}
	return Decision{Reason: "no_matching_rule"}, nil
}

// Consume marks the first active one-time rule matching agent+path as
// consumed. A path served under a permanent rule is a no-op.
func (s *Store) Consume(agent, path, pattern string) error {
	if pattern == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	next := append([]Rule(nil), s.rules...)
	for i := range next {
		r := &next[i]
		if r.Agent != agent || r.Pattern != pattern || !r.OneTime || !r.active(now) {
			continue
		}
		if ok, _ := doublestar.Match(r.Pattern, path); ok {
			r.Consumed = true
			if err := s.save(next); err != nil {
				return err
			}
			s.rules = next
			return nil
		}
	}
	return ErrGrantConsumed
}

// Allowed reports non-consuming visibility (for list filtering).
func (s *Store) Allowed(agent, path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for _, r := range s.rules {
		if r.Agent != agent || !r.active(now) {
			continue
		}
		if ok, _ := doublestar.Match(r.Pattern, path); ok {
			return true
		}
	}
	return false
}
