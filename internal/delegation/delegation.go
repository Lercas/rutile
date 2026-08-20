// Package delegation implements scoped sub-agent tokens: a registered agent
// mints a short-lived child token limited to a subset of paths. The child's
// effective access is the INTERSECTION of its patterns and the parent's
// live policy, so revoking or restricting the parent instantly applies to
// every child. Depth is 1: a delegated token cannot delegate further.
package delegation

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/Lercas/rutile/internal/atomicfile"
	"github.com/Lercas/rutile/internal/store"
	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"
)

const (
	TokenPrefix          = "rtl_d_"
	MaxTTL               = 24 * time.Hour
	DefaultTTL           = time.Hour
	MaxActiveTotal       = 1000
	MaxActivePerParent   = 100
	MaxPatternBytes      = 4096
	MaxDelegationFileLen = 8 << 20
)

var (
	ErrNotFound = errors.New("delegation not found")
	ErrExpired  = errors.New("delegation expired")
	validLabel  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	ErrBadLabel = errors.New("delegation label must be lowercase letters, digits, '-', '_'")
)

type Delegation struct {
	ID        string    `yaml:"id"`
	Parent    string    `yaml:"parent"`
	Label     string    `yaml:"label"`
	TokenHash string    `yaml:"token_hash"`
	TokenPfx  string    `yaml:"token_prefix"`
	Patterns  []string  `yaml:"patterns"`
	CreatedAt time.Time `yaml:"created_at"`
	ExpiresAt time.Time `yaml:"expires_at"`
}

func (d Delegation) Expired(now time.Time) bool { return now.After(d.ExpiresAt) }

type delegFile struct {
	Delegations []Delegation `yaml:"delegations"`
}

type Store struct {
	mu    sync.Mutex
	path  string
	items []Delegation
}

func Load(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := atomicfile.ReadLimited(path, MaxDelegationFileLen)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var f delegFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	s.items = f.Delegations
	return s, nil
}

func (s *Store) save(items []Delegation) error {
	b, err := yaml.Marshal(delegFile{Delegations: items})
	if err != nil {
		return err
	}
	if len(b) > MaxDelegationFileLen {
		return errors.New("delegation state exceeds 8 MiB limit")
	}
	return atomicfile.Write(s.path, b, 0o600)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Create mints a child token for parent. TTL is clamped to (0, MaxTTL].
func (s *Store) Create(parent, label string, patterns []string, ttl time.Duration) (Delegation, string, error) {
	if !validLabel.MatchString(label) {
		return Delegation{}, "", ErrBadLabel
	}
	if len(patterns) == 0 {
		return Delegation{}, "", errors.New("at least one path pattern is required")
	}
	if len(patterns) > 64 {
		return Delegation{}, "", errors.New("too many path patterns (max 64)")
	}
	patternBytes := 0
	for _, pattern := range patterns {
		if pattern == "" || len(pattern) > store.MaxPathLen {
			return Delegation{}, "", errors.New("delegation pattern is empty or too long")
		}
		if _, err := doublestar.Match(pattern, "probe/path"); err != nil {
			return Delegation{}, "", errors.New("invalid delegation pattern: " + pattern)
		}
		patternBytes += len(pattern)
	}
	if patternBytes > MaxPatternBytes {
		return Delegation{}, "", errors.New("delegation patterns exceed 4096 bytes in total")
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if ttl > MaxTTL {
		ttl = MaxTTL
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return Delegation{}, "", err
	}
	token := TokenPrefix + hex.EncodeToString(raw)
	idb := make([]byte, 16)
	if _, err := rand.Read(idb); err != nil {
		return Delegation{}, "", err
	}
	now := time.Now().UTC().Truncate(time.Second)
	d := Delegation{
		ID: hex.EncodeToString(idb), Parent: parent, Label: label,
		TokenHash: hashToken(token), TokenPfx: token[:len(TokenPrefix)+8],
		Patterns:  append([]string(nil), patterns...),
		CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	live := s.live(time.Now().UTC())
	if len(live) >= MaxActiveTotal {
		return Delegation{}, "", errors.New("active delegation limit reached")
	}
	perParent := 0
	for _, existing := range live {
		if existing.Parent == parent {
			perParent++
		}
	}
	if perParent >= MaxActivePerParent {
		return Delegation{}, "", errors.New("active delegation limit reached for parent")
	}
	next := append(live, d)
	if err := s.save(next); err != nil {
		return Delegation{}, "", err
	}
	s.items = next
	return d, token, nil
}

// live returns a copy without expired entries; callers hold s.mu.
func (s *Store) live(now time.Time) []Delegation {
	kept := make([]Delegation, 0, len(s.items))
	for _, d := range s.items {
		if !d.Expired(now) {
			kept = append(kept, d)
		}
	}
	return kept
}

// FindByToken resolves a live delegation by its bearer token.
func (s *Store) FindByToken(token string) (Delegation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hashToken(token)
	now := time.Now().UTC()
	for _, d := range s.items {
		if subtle.ConstantTimeCompare([]byte(d.TokenHash), []byte(h)) == 1 {
			if d.Expired(now) {
				return Delegation{}, ErrExpired
			}
			return d, nil
		}
	}
	return Delegation{}, ErrNotFound
}

func (s *Store) List() []Delegation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.live(time.Now().UTC())
}

// Revoke removes one delegation. parent=="" allows any (human); otherwise
// only the parent's own children may be revoked.
func (s *Store) Revoke(id, parent string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, d := range s.items {
		if d.ID == id {
			if parent != "" && d.Parent != parent {
				return ErrNotFound
			}
			next := append([]Delegation(nil), s.items[:i]...)
			next = append(next, s.items[i+1:]...)
			if err := s.save(next); err != nil {
				return err
			}
			s.items = next
			return nil
		}
	}
	return ErrNotFound
}

// RevokeByParent kills every child of an agent (used on agent_revoke).
func (s *Store) RevokeByParent(parent string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := make([]Delegation, 0, len(s.items))
	n := 0
	for _, d := range s.items {
		if d.Parent == parent {
			n++
			continue
		}
		kept = append(kept, d)
	}
	if n == 0 {
		return 0, nil
	}
	if err := s.save(kept); err != nil {
		return 0, err
	}
	s.items = kept
	return n, nil
}
