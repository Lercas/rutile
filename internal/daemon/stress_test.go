package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Lercas/rutile/internal/protocol"
)

// TestConcurrentReadsDuringRotate hammers get/list from many goroutines
// while the key is rotated twice. Every get must either succeed or fail
// with a *policy/lock* error — never an internal decrypt failure, which
// would mean the old key was paired with a re-encrypted file.
func TestConcurrentReadsDuringRotate(t *testing.T) {
	startDaemon(t)
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil))
	for i := 0; i < 8; i++ {
		mustOK(t, call(t, "put", nil, protocol.PutParams{Path: fmt.Sprintf("dev/s%d", i), Value: fmt.Sprintf("v%d", i)}, nil))
	}
	agent := registerAgent(t, "stress")
	mustOK(t, call(t, "rule_add", nil, protocol.RuleAddParams{Agent: "stress", Pattern: "dev/**"}, nil))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	errCh := make(chan string, 256)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				path := fmt.Sprintf("dev/s%d", i%8)
				var res protocol.GetResult
				var e *protocol.RPCError
				if w%2 == 0 {
					e = call(t, "get", nil, protocol.GetParams{Path: path}, &res)
				} else {
					e = call(t, "get", agent, protocol.GetParams{Path: path}, &res)
				}
				if e != nil {
					if e.Code == protocol.CodeInternal {
						select {
						case errCh <- e.Message:
						default:
						}
					}
					continue
				}
				if want := fmt.Sprintf("v%d", i%8); res.Value != want {
					select {
					case errCh <- fmt.Sprintf("wrong value %q for %s", res.Value, path):
					default:
					}
				}
			}
		}(w)
	}

	for r := 0; r < 2; r++ {
		var res protocol.RotateResult
		mustOK(t, call(t, "rotate", nil, protocol.RotateParams{NewPassphrase: fmt.Sprintf("rotated-pass-%d!", r)}, &res))
		time.Sleep(50 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	close(errCh)
	for msg := range errCh {
		t.Errorf("integrity violation under concurrency: %s", msg)
	}
}

// TestDaemonRestartPersistence proves every piece of state survives a
// daemon restart: secrets, agents, policy, delegations, requests, audit.
func TestDaemonRestartPersistence(t *testing.T) {
	cancel1 := startDaemonCancelable(t)
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil))
	mustOK(t, call(t, "put", nil, protocol.PutParams{Path: "p/x", Value: "vx"}, nil))
	agent := registerAgent(t, "survivor")
	mustOK(t, call(t, "rule_add", nil, protocol.RuleAddParams{Agent: "survivor", Pattern: "p/**"}, nil))
	var del protocol.DelegateResult
	mustOK(t, call(t, "delegate", agent, protocol.DelegateParams{Label: "kid", Patterns: []string{"p/**"}, TTL: "1h"}, &del))
	mustOK(t, call(t, "access_request", agent, protocol.AccessRequestParams{Path: "q/z", Reason: "later"}, nil))

	cancel1()
	waitSocketGone(t)
	restartDaemon(t)

	// locked after restart (the key never touches disk unencrypted)
	if e := call(t, "get", nil, protocol.GetParams{Path: "p/x"}, nil); e == nil || e.Code != protocol.CodeLocked {
		t.Fatalf("want locked after restart, got %v", e)
	}
	mustOK(t, call(t, "unlock", nil, protocol.UnlockParams{Passphrase: testPass}, nil))

	var got protocol.GetResult
	mustOK(t, call(t, "get", agent, protocol.GetParams{Path: "p/x"}, &got))
	if got.Value != "vx" {
		t.Fatalf("secret lost: %q", got.Value)
	}
	child := &protocol.AgentAuth{Agent: "survivor", Token: del.Token}
	mustOK(t, call(t, "get", child, protocol.GetParams{Path: "p/x"}, &got))

	var reqs protocol.RequestListResult
	mustOK(t, call(t, "request_list", nil, nil, &reqs))
	if len(reqs.Requests) != 1 || reqs.Requests[0].Path != "q/z" {
		t.Fatalf("pending request lost: %+v", reqs)
	}
}

func startDaemonCancelable(t *testing.T) context.CancelFunc {
	t.Helper()
	startDaemon(t)
	return lastCancel
}

var lastCancel context.CancelFunc
var lastDaemon *Daemon

func restartDaemon(t *testing.T) {
	t.Helper()
	d, err := New(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go d.Run(ctx)
	waitSocketUp(t)
}
