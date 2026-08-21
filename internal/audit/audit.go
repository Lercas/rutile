// Package audit maintains the append-only, hash-chained JSONL audit log.
// Each line's hash covers the previous line's hash, making silent
// modification or deletion of history detectable by Verify.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Lercas/rutile/internal/atomicfile"
)

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

type Entry struct {
	Seq       int64     `json:"seq"`
	TS        time.Time `json:"ts"`
	ActorType string    `json:"actor_type"` // "human" | "agent"
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Path      string    `json:"path,omitempty"`
	Result    string    `json:"result"` // "granted" | "denied" | "error"
	Reason    string    `json:"reason,omitempty"`
	Note      string    `json:"note,omitempty"` // caller-supplied purpose (agent's reason)
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
}

// entryHash hashes prev_hash || canonical JSON of the entry with Hash cleared.
func entryHash(e Entry) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	sum := sha256.Sum256(append([]byte(e.PrevHash), b...))
	return hex.EncodeToString(sum[:])
}

type Log struct {
	mu              sync.Mutex
	path            string
	lastSeq         int64
	lastHash        string
	failed          error
	appendRecord    func(string, []byte, os.FileMode) error
	writeCheckpoint func(string, []byte, os.FileMode) error
}

// Open loads chain state from the last line of the log (if any).
func Open(path string) (*Log, error) {
	l := &Log{
		path: path, lastHash: genesisHash,
		appendRecord: durableAppend, writeCheckpoint: atomicfile.Write,
	}
	if _, err := Verify(path); err != nil {
		return nil, fmt.Errorf("refusing to open invalid audit chain: %w", err)
	}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var last string
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			last = sc.Text()
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if last != "" {
		var e Entry
		if err := json.Unmarshal([]byte(last), &e); err != nil {
			return nil, fmt.Errorf("corrupted audit log last line: %w", err)
		}
		l.lastSeq, l.lastHash = e.Seq, e.Hash
	}
	return l, nil
}

// Append writes one entry, filling seq/ts/hash-chain fields.
func (l *Log) Append(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failed != nil {
		return fmt.Errorf("audit log requires reopen after a persistence failure: %w", l.failed)
	}
	e.Seq = l.lastSeq + 1
	e.TS = time.Now().UTC().Truncate(time.Second)
	e.PrevHash = l.lastHash
	e.Hash = entryHash(e)
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := l.appendRecord(l.path, append(b, '\n'), 0o600); err != nil {
		// A write or fsync error can be reported after some or all bytes reached
		// the file. Do not guess which state won: fail-stop until Open verifies
		// the on-disk chain and reconstructs lastSeq/lastHash.
		l.failed = err
		return err
	}
	l.lastSeq, l.lastHash = e.Seq, e.Hash
	return nil
}

func durableAppend(path string, data []byte, mode os.FileMode) error {
	// Create exclusively first so we know whether the parent directory entry
	// also needs an fsync. Without that sync, the first successfully returned
	// audit record could disappear after a crash even though the file was synced.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, mode)
	created := err == nil
	if errors.Is(err, fs.ErrExist) {
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, mode)
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if !created {
		return nil
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Rotate verifies the current log, archives it next to itself and starts a
// fresh chain whose first entry is a checkpoint carrying the archive's
// final hash — so the chains stay linked across files.
func (l *Log) Rotate() (archive string, entries int64, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failed != nil {
		return "", 0, fmt.Errorf("audit log requires reopen after a persistence failure: %w", l.failed)
	}
	n, err := Verify(l.path)
	if err != nil {
		return "", n, fmt.Errorf("refusing to rotate a broken chain: %w", err)
	}
	if n == 0 {
		return "", 0, errors.New("audit log is empty, nothing to rotate")
	}
	finalHash := l.lastHash
	base := strings.TrimSuffix(l.path, ".log")
	archive = fmt.Sprintf("%s-%s.log", base, time.Now().UTC().Format("20060102-150405.000000000"))
	if err := copyArchive(l.path, archive); err != nil {
		return "", n, err
	}
	e := Entry{
		ActorType: "human", Actor: "cli", Action: "checkpoint", Result: "granted",
		Reason: "archive:" + archive, Note: "prev_chain_final:" + finalHash,
	}
	e.Seq = 1
	e.TS = time.Now().UTC().Truncate(time.Second)
	e.PrevHash = genesisHash
	e.Hash = entryHash(e)
	b, _ := json.Marshal(e)
	if err := l.writeCheckpoint(l.path, append(b, '\n'), 0o600); err != nil {
		// Atomic replacement can report a directory-fsync error after rename.
		// Require reopen so either the old chain or the checkpoint becomes the
		// sole authoritative in-memory state.
		l.failed = err
		return archive, n, err
	}
	l.lastSeq, l.lastHash = 1, e.Hash
	return archive, n, nil
}

// copyArchive durably creates an archive without moving or truncating the
// active log. A failed checkpoint replacement therefore leaves the original
// chain intact and appendable.
func copyArchive(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".rutile-audit-archive-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpName, dst); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Verify re-walks the whole chain; returns entry count, or the seq at which
// the chain breaks.
func Verify(path string) (int64, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	prev := genesisHash
	var n int64
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return n, fmt.Errorf("entry %d: invalid JSON: %w", n+1, err)
		}
		if e.Seq != n+1 {
			return n, fmt.Errorf("entry seq %d: expected seq %d (missing or reordered lines)", e.Seq, n+1)
		}
		if e.PrevHash != prev {
			return n, fmt.Errorf("entry seq %d: chain broken (prev_hash mismatch)", e.Seq)
		}
		if entryHash(e) != e.Hash {
			return n, fmt.Errorf("entry seq %d: hash mismatch (entry modified)", e.Seq)
		}
		prev = e.Hash
		n++
	}
	return n, sc.Err()
}

// Tail returns up to n last entries.
func Tail(path string, n int) ([]Entry, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var all []Entry
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue
		}
		all = append(all, e)
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return all, sc.Err()
}
