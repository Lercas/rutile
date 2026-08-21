// Package agents manages registered AI-agent identities (agents/<name>.yaml).
// Bootstrap tokens are shown once at creation; only their sha256 is stored.
package agents

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Lercas/rutile/internal/atomicfile"
	"gopkg.in/yaml.v3"
)

var (
	ErrNotFound  = errors.New("agent not found")
	ErrExists    = errors.New("agent already exists")
	ErrBadToken  = errors.New("invalid agent token")
	validName    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	ErrBadName   = errors.New("agent name must be lowercase letters, digits, '-', '_'")
	tokenPrefixL = 12
)

const MaxAgentFileLen = 64 << 10

type Agent struct {
	Name        string     `yaml:"name"`
	Description string     `yaml:"description,omitempty"`
	Type        string     `yaml:"type,omitempty"` // e.g. claude-code, cursor, ci, framework
	TokenHash   string     `yaml:"token_hash"`
	TokenPrefix string     `yaml:"token_prefix"`
	CreatedAt   time.Time  `yaml:"created_at"`
	ExpiresAt   *time.Time `yaml:"expires_at,omitempty"` // nil = does not expire
	LocalOnly   bool       `yaml:"local_only,omitempty"` // token rejected on the HTTP transport
	Disabled    bool       `yaml:"disabled"`
	LastUsedAt  *time.Time `yaml:"last_used_at,omitempty"`
}

// Usable reports why an agent may not authenticate right now. transport is
// "" for local (stdio/CLI) callers and "http" for the network transport.
func (a Agent) Usable(transport string, now time.Time) error {
	if a.Disabled {
		return ErrBadToken
	}
	if a.ExpiresAt != nil && now.After(*a.ExpiresAt) {
		return ErrBadToken
	}
	if a.LocalOnly && transport == "http" {
		return ErrBadToken
	}
	return nil
}

// ParseTTL parses durations like "12h", "30m" and additionally "30d".
func ParseTTL(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n <= 0 {
			return 0, errors.New("bad duration: " + s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, errors.New("bad duration: " + s)
	}
	return d, nil
}

type Store struct {
	mu  sync.Mutex
	dir string
}

func New(dir string) *Store { return &Store{dir: dir} }

func ValidateName(name string) error {
	if !validName.MatchString(name) {
		return ErrBadName
	}
	return nil
}

func (s *Store) file(name string) string { return filepath.Join(s.dir, name+".yaml") }

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Add registers a new agent and returns its bootstrap token (shown once).
// ttl==0 means the token never expires.
func (s *Store) Add(name, description, agentType string, ttl time.Duration, localOnly bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ValidateName(name); err != nil {
		return "", err
	}
	if _, err := os.Stat(s.file(name)); err == nil {
		return "", ErrExists
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := "rtl_" + hex.EncodeToString(raw)
	a := Agent{
		Name:        name,
		Description: description,
		Type:        agentType,
		LocalOnly:   localOnly,
		TokenHash:   hashToken(token),
		TokenPrefix: token[:tokenPrefixL],
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
	}
	if ttl > 0 {
		t := a.CreatedAt.Add(ttl)
		a.ExpiresAt = &t
	}
	if err := s.save(a); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Store) save(a Agent) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	b, err := yaml.Marshal(a)
	if err != nil {
		return err
	}
	return atomicfile.Write(s.file(a.Name), b, 0o600)
}

func (s *Store) get(name string) (Agent, error) {
	var a Agent
	if err := ValidateName(name); err != nil {
		return a, err
	}
	b, err := atomicfile.ReadLimited(s.file(name), MaxAgentFileLen)
	if err != nil {
		return a, ErrNotFound
	}
	if err := yaml.Unmarshal(b, &a); err != nil {
		return a, fmt.Errorf("corrupted agent file %s: %w", name, err)
	}
	if a.Name != name {
		return Agent{}, fmt.Errorf("corrupted agent file %s: embedded name is %q", name, a.Name)
	}
	return a, nil
}

func (s *Store) Get(name string) (Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.get(name)
}

// Verify checks name+token+constraints and stamps last_used_at on success.
// transport is "" for local callers and "http" for the network transport.
func (s *Store) Verify(name, token, transport string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.get(name)
	if err != nil {
		return ErrBadToken
	}
	if err := a.Usable(transport, time.Now().UTC()); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(a.TokenHash), []byte(hashToken(token))) != 1 {
		return ErrBadToken
	}
	// stamp last_used at most once a minute to avoid a yaml write per call
	now := time.Now().UTC().Truncate(time.Second)
	if a.LastUsedAt == nil || now.Sub(*a.LastUsedAt) > time.Minute {
		a.LastUsedAt = &now
		_ = s.save(a) // best-effort stamp
	}
	return nil
}

// FindByToken resolves an agent by its bearer token (used by the MCP HTTP
// transport, where only the Authorization header identifies the caller).
func (s *Store) FindByToken(token string) (Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.list()
	if err != nil {
		return Agent{}, err
	}
	h := hashToken(token)
	now := time.Now().UTC()
	for _, a := range list {
		if a.Usable("http", now) == nil && subtle.ConstantTimeCompare([]byte(a.TokenHash), []byte(h)) == 1 {
			return a, nil
		}
	}
	return Agent{}, ErrBadToken
}

func (s *Store) list() ([]Agent, error) {
	entries, err := os.ReadDir(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Agent
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		a, err := s.get(strings.TrimSuffix(e.Name(), ".yaml"))
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) List() ([]Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.list()
}

// Revoke deletes the agent's registration file.
func (s *Store) Revoke(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ValidateName(name); err != nil {
		return err
	}
	if err := os.Remove(s.file(name)); err != nil {
		return ErrNotFound
	}
	return nil
}
