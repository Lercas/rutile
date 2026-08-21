// Package requests keeps the queue of pending access requests filed by
// agents (requests.yaml). An agent that hits a policy denial can ask for
// access with a reason; the human approves or rejects it from the CLI.
package requests

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/Lercas/rutile/internal/atomicfile"
	"gopkg.in/yaml.v3"
)

var ErrNotFound = errors.New("request not found")

const (
	MaxPendingTotal    = 1000
	MaxPendingPerAgent = 100
	MaxRequestFileLen  = 4 << 20
)

type Request struct {
	ID        string    `yaml:"id"`
	Agent     string    `yaml:"agent"`
	Path      string    `yaml:"path"`
	Reason    string    `yaml:"reason,omitempty"`
	CreatedAt time.Time `yaml:"created_at"`
}

type reqFile struct {
	Requests []Request `yaml:"requests"`
}

type Store struct {
	mu    sync.Mutex
	path  string
	items []Request
}

func Load(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := atomicfile.ReadLimited(path, MaxRequestFileLen)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var rf reqFile
	if err := yaml.Unmarshal(b, &rf); err != nil {
		return nil, err
	}
	s.items = rf.Requests
	return s, nil
}

func (s *Store) save(items []Request) error {
	b, err := yaml.Marshal(reqFile{Requests: items})
	if err != nil {
		return err
	}
	if len(b) > MaxRequestFileLen {
		return errors.New("pending request state exceeds 4 MiB limit")
	}
	return atomicfile.Write(s.path, b, 0o600)
}

// Add files a request; a duplicate pending agent+path returns the existing one.
func (s *Store) Add(agent, path, reason string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.items {
		if r.Agent == agent && r.Path == path {
			return r, nil
		}
	}
	if len(s.items) >= MaxPendingTotal {
		return Request{}, errors.New("pending request limit reached")
	}
	perAgent := 0
	for _, r := range s.items {
		if r.Agent == agent {
			perAgent++
		}
	}
	if perAgent >= MaxPendingPerAgent {
		return Request{}, errors.New("pending request limit reached for agent")
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return Request{}, err
	}
	r := Request{
		ID: hex.EncodeToString(b), Agent: agent, Path: path, Reason: reason,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	next := append(append([]Request(nil), s.items...), r)
	if err := s.save(next); err != nil {
		return Request{}, err
	}
	s.items = next
	return r, nil
}

func (s *Store) List() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.items...)
}

// Take removes the request by id and returns it.
func (s *Store) Take(id string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, r := range s.items {
		if r.ID == id {
			next := append([]Request(nil), s.items[:i]...)
			next = append(next, s.items[i+1:]...)
			if err := s.save(next); err != nil {
				return Request{}, err
			}
			s.items = next
			return r, nil
		}
	}
	return Request{}, ErrNotFound
}

// Restore puts a previously taken request back without changing its id or
// creation time. It is used to roll back a failed approval transaction.
func (s *Store) Restore(r Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.items {
		if existing.ID == r.ID || (existing.Agent == r.Agent && existing.Path == r.Path) {
			return nil
		}
	}
	next := append(append([]Request(nil), s.items...), r)
	if err := s.save(next); err != nil {
		return err
	}
	s.items = next
	return nil
}
