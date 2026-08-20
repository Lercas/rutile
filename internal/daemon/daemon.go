// Package daemon is the trust boundary of rutile: it alone holds the
// decrypted age identity in memory (ssh-agent model), serves the unix
// socket, enforces policy for agents and delegated sub-agents, and writes
// the audit log.
package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/bmatcuk/doublestar/v4"

	"github.com/Lercas/rutile/internal/ageio"
	"github.com/Lercas/rutile/internal/agents"
	"github.com/Lercas/rutile/internal/atomicfile"
	"github.com/Lercas/rutile/internal/audit"
	"github.com/Lercas/rutile/internal/delegation"
	"github.com/Lercas/rutile/internal/gitsync"
	"github.com/Lercas/rutile/internal/paths"
	"github.com/Lercas/rutile/internal/peercred"
	"github.com/Lercas/rutile/internal/policy"
	"github.com/Lercas/rutile/internal/protocol"
	"github.com/Lercas/rutile/internal/requests"
	"github.com/Lercas/rutile/internal/store"
)

const DefaultIdleTimeout = 30 * time.Minute

const (
	maxReasonLen = 2048
	maxTokenLen  = 128
	maxCertLen   = 2048
	maxRequestID = 128
	maxMethodLen = 64
)

// caller is the resolved identity of one request.
type caller struct {
	human    bool
	agent    string   // parent agent name (for delegated callers too)
	label    string   // delegation label; "" for a direct agent
	patterns []string // delegation scope; nil for a direct agent
}

func (c caller) delegated() bool { return c.label != "" }

// name is the audit actor: "cli", "claude" or "claude>worker".
func (c caller) name() string {
	if c.human {
		return "cli"
	}
	if c.delegated() {
		return c.agent + ">" + c.label
	}
	return c.agent
}

func (c caller) actorType() string {
	if c.human {
		return "human"
	}
	return "agent"
}

type Daemon struct {
	// SocketMode is applied to the unix socket (default 0600). System mode
	// uses 0660 plus a dedicated group.
	SocketMode os.FileMode
	// AdminUID, when >= 0, restricts human-privileged (Auth == nil) calls to
	// that uid (and root), verified via peer credentials. -1 (default) allows
	// the daemon's own uid and root.
	AdminUID int

	mu          sync.Mutex
	identity    age.Identity
	recipients  []age.Recipient
	lastUsed    time.Time
	idleTimeout time.Duration

	// rw serializes key rotation against secret reads/writes: rotate takes
	// the write lock while re-encrypting the store, so a concurrent get can
	// never pair the old key with a freshly re-encrypted file.
	rw sync.RWMutex

	store               *store.Store
	rotateWrite         func(string, []byte) error
	rotateIdentityWrite func(string, *age.X25519Identity, string) error
	agents              *agents.Store
	policy              *policy.Store
	requests            *requests.Store
	delegations         *delegation.Store
	audit               *audit.Log
	log                 *slog.Logger

	handlers map[string]handler
}

type handler func(params json.RawMessage, c caller) (any, *protocol.RPCError)

func New(log *slog.Logger, idleTimeout time.Duration) (*Daemon, error) {
	if idleTimeout <= 0 {
		idleTimeout = DefaultIdleTimeout
	}
	pol, err := policy.Load(paths.PolicyFile())
	if err != nil {
		return nil, err
	}
	reqs, err := requests.Load(paths.RequestsFile())
	if err != nil {
		return nil, err
	}
	dels, err := delegation.Load(paths.DelegationsFile())
	if err != nil {
		return nil, err
	}
	aud, err := audit.Open(paths.AuditFile())
	if err != nil {
		return nil, err
	}
	d := &Daemon{
		SocketMode:  0o600,
		AdminUID:    -1,
		idleTimeout: idleTimeout,
		store:       store.New(paths.StoreDir()),
		agents:      agents.New(paths.AgentsDir()),
		policy:      pol,
		requests:    reqs,
		delegations: dels,
		audit:       aud,
		log:         log,
	}
	d.rotateWrite = d.store.Write
	d.rotateIdentityWrite = ageio.SaveIdentityEncrypted
	d.handlers = map[string]handler{
		"unlock":            d.handleUnlock,
		"lock":              d.handleLock,
		"status":            d.handleStatus,
		"get":               d.handleGet,
		"list":              d.handleList,
		"put":               d.handlePut,
		"del":               d.handleDel,
		"agent_add":         d.handleAgentAdd,
		"agent_list":        d.handleAgentList,
		"agent_revoke":      d.handleAgentRevoke,
		"rule_add":          d.handleRuleAdd,
		"rule_del":          d.handleRuleDel,
		"rule_list":         d.handleRuleList,
		"access_request":    d.handleAccessRequest,
		"request_list":      d.handleRequestList,
		"request_resolve":   d.handleRequestResolve,
		"delegate":          d.handleDelegate,
		"delegation_list":   d.handleDelegationList,
		"delegation_revoke": d.handleDelegationRevoke,
		"rotate":            d.handleRotate,
		"audit_rotate":      d.handleAuditRotate,
	}
	return d, nil
}

// Run serves the socket until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	sock := paths.SocketPath()
	if err := prepareSocketPath(sock); err != nil {
		return err
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	defer ln.Close()
	if err := os.Chmod(sock, d.SocketMode); err != nil {
		return err
	}
	d.log.Info("daemon started", "socket", sock, "idle_timeout", d.idleTimeout.String())

	go d.idleLocker(ctx)
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go d.serveConn(conn)
	}
}

// prepareSocketPath removes only a socket that is provably stale. A failed
// dial can also mean permission denial, timeout, or an unrelated regular file;
// none of those are authority to unlink the path.
func prepareSocketPath(sock string) error {
	before, err := os.Lstat(sock)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect daemon socket %s: %w", sock, err)
	}
	if before.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove non-socket path configured as daemon socket: %s", sock)
	}
	conn, dialErr := net.DialTimeout("unix", sock, 300*time.Millisecond)
	if dialErr == nil {
		conn.Close()
		return fmt.Errorf("another daemon is already running on %s", sock)
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) && !errors.Is(dialErr, os.ErrNotExist) {
		return fmt.Errorf("cannot prove daemon socket %s is stale; refusing to remove it: %w", sock, dialErr)
	}
	after, err := os.Lstat(sock)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reinspect daemon socket %s: %w", sock, err)
	}
	if after.Mode()&os.ModeSocket == 0 || !os.SameFile(before, after) {
		return fmt.Errorf("daemon socket path %s changed while checking it; refusing to remove it", sock)
	}
	if err := os.Remove(sock); err != nil {
		return fmt.Errorf("remove stale daemon socket %s: %w", sock, err)
	}
	return nil
}

func (d *Daemon) idleLocker(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.mu.Lock()
			if d.identity != nil && time.Since(d.lastUsed) > d.idleTimeout {
				d.identity = nil
				d.recipients = nil
				d.log.Info("auto-locked after idle timeout")
				d.mu.Unlock()
				if err := d.audit.Append(audit.Entry{ActorType: "human", Actor: "daemon", Action: "auto_lock", Result: "granted"}); err != nil {
					d.log.Error("audit append failed", "action", "auto_lock", "err", err)
				}
				continue
			}
			d.mu.Unlock()
		}
	}
}

func (d *Daemon) serveConn(conn net.Conn) {
	defer conn.Close()
	peerUID, credErr := peercred.UID(conn)
	// an idle or wedged client must not pin a goroutine forever
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(conn)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var req protocol.Request
		resp := protocol.Response{}
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			resp.Error = &protocol.RPCError{Code: protocol.CodeBadRequest, Message: "invalid JSON"}
			_ = enc.Encode(resp)
			continue
		}
		if rpcErr := validateRequestEnvelope(req); rpcErr != nil {
			resp.Error = rpcErr
			_ = enc.Encode(resp)
			continue
		}
		resp.ID = req.ID
		result, rpcErr := d.dispatch(req, peerUID, credErr == nil)
		if rpcErr != nil {
			resp.Error = rpcErr
		} else {
			b, err := json.Marshal(result)
			if err != nil {
				resp.Error = &protocol.RPCError{Code: protocol.CodeInternal, Message: err.Error()}
			} else {
				resp.Result = b
			}
		}
		if err := enc.Encode(resp); err != nil {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
	}
}

func validateRequestEnvelope(req protocol.Request) *protocol.RPCError {
	if req.ID == "" || len(req.ID) > maxRequestID {
		return &protocol.RPCError{Code: protocol.CodeBadRequest, Message: "request id is empty or too long"}
	}
	if req.Method == "" || len(req.Method) > maxMethodLen {
		return &protocol.RPCError{Code: protocol.CodeBadRequest, Message: "request method is empty or too long"}
	}
	return nil
}

// resolveCaller authenticates the request: no Auth = human (trusted via the
// 0600 socket), a rtl_d_ token = delegated sub-agent, otherwise a direct
// registered agent.
func (d *Daemon) resolveCaller(auth *protocol.AgentAuth, peerUID uint32, credOK bool) (caller, *protocol.RPCError) {
	if auth == nil {
		if e := d.checkHumanPeer(peerUID, credOK); e != nil {
			return caller{}, e
		}
		return caller{human: true}, nil
	}
	if agents.ValidateName(auth.Agent) != nil || len(auth.Token) > maxTokenLen || len(auth.Cert) > maxCertLen || (auth.Transport != "" && auth.Transport != "http") {
		if e := d.appendAudit(audit.Entry{ActorType: "agent", Actor: "<invalid>", Action: "auth", Result: "denied", Reason: "malformed_auth_metadata"}); e != nil {
			return caller{}, e
		}
		return caller{}, &protocol.RPCError{Code: protocol.CodeInvalidToken, Message: "malformed agent authentication metadata"}
	}
	// mTLS/SPIFFE identity asserted by rutile's own HTTP door: no bearer,
	// the agent is named by its verified client certificate.
	if auth.Token == "" && auth.Cert != "" {
		if !certAssertionMatchesAgent(auth.Cert, auth.Agent) {
			if e := d.appendAudit(audit.Entry{ActorType: "agent", Actor: auth.Agent, Action: "auth", Result: "denied", Reason: "certificate_agent_mismatch"}); e != nil {
				return caller{}, e
			}
			return caller{}, &protocol.RPCError{Code: protocol.CodeInvalidToken, Message: "certificate identity does not match the asserted agent"}
		}
		// Cert is an assertion made by rutile's HTTP/mTLS frontend. In system
		// mode the unix socket may be group-readable, so never accept that
		// assertion from an arbitrary socket peer: only the daemon owner (the
		// uid under which the trusted frontend must run) or root may stamp it.
		if !credOK || (int64(peerUID) != int64(os.Getuid()) && peerUID != 0) {
			if e := d.appendAudit(audit.Entry{ActorType: "agent", Actor: auth.Agent, Action: "auth", Result: "denied", Reason: "untrusted_cert_assertion"}); e != nil {
				return caller{}, e
			}
			return caller{}, &protocol.RPCError{Code: protocol.CodeInvalidToken, Message: "certificate identity was asserted by an untrusted local peer"}
		}
		a, err := d.agents.Get(auth.Agent)
		if err != nil || a.Usable(auth.Transport, time.Now().UTC()) != nil {
			if e := d.appendAudit(audit.Entry{ActorType: "agent", Actor: auth.Agent, Action: "auth", Result: "denied", Reason: "mtls_unknown_agent"}); e != nil {
				return caller{}, e
			}
			return caller{}, &protocol.RPCError{Code: protocol.CodeInvalidToken, Message: "no usable agent for certificate identity " + auth.Cert}
		}
		return caller{agent: a.Name}, nil
	}
	if strings.HasPrefix(auth.Token, delegation.TokenPrefix) {
		del, err := d.delegations.FindByToken(auth.Token)
		if err != nil {
			msg := "unknown or expired delegated token"
			if e := d.appendAudit(audit.Entry{ActorType: "agent", Actor: auth.Agent, Action: "auth", Result: "denied", Reason: "bad_delegation"}); e != nil {
				return caller{}, e
			}
			return caller{}, &protocol.RPCError{Code: protocol.CodeInvalidToken, Message: msg}
		}
		// the parent must still be usable: a revoked, disabled, expired or
		// (over HTTP) local-only parent kills its children too
		if a, err := d.agents.Get(del.Parent); err != nil || a.Usable(auth.Transport, time.Now().UTC()) != nil {
			if e := d.appendAudit(audit.Entry{ActorType: "agent", Actor: del.Parent + ">" + del.Label, Action: "auth", Result: "denied", Reason: "parent_revoked"}); e != nil {
				return caller{}, e
			}
			return caller{}, &protocol.RPCError{Code: protocol.CodeInvalidToken, Message: "parent agent revoked or disabled"}
		}
		return caller{agent: del.Parent, label: del.Label, patterns: del.Patterns}, nil
	}
	if err := d.agents.Verify(auth.Agent, auth.Token, auth.Transport); err != nil {
		if e := d.appendAudit(audit.Entry{ActorType: "agent", Actor: auth.Agent, Action: "auth", Result: "denied", Reason: "invalid_token"}); e != nil {
			return caller{}, e
		}
		return caller{}, &protocol.RPCError{Code: protocol.CodeInvalidToken, Message: "unknown agent or bad token"}
	}
	return caller{agent: auth.Agent}, nil
}

func certAssertionMatchesAgent(certID, agent string) bool {
	u, err := url.Parse(certID)
	if err != nil || u.Scheme != "spiffe" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return false
	}
	parts := strings.Split(u.Path, "/")
	return len(parts) == 3 && parts[0] == "" && parts[1] == "agent" && parts[2] == agent
}

func (d *Daemon) appendAudit(e audit.Entry) *protocol.RPCError {
	if err := d.audit.Append(e); err != nil {
		d.log.Error("audit append failed", "action", e.Action, "actor", e.Actor, "err", err)
		return &protocol.RPCError{Code: protocol.CodeInternal, Message: "audit log unavailable; refusing unaudited operation"}
	}
	return nil
}

func (d *Daemon) dispatch(req protocol.Request, peerUID uint32, credOK bool) (any, *protocol.RPCError) {
	h, ok := d.handlers[req.Method]
	if !ok {
		return nil, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: "unknown method " + req.Method}
	}
	c, rpcErr := d.resolveCaller(req.Auth, peerUID, credOK)
	if rpcErr != nil {
		return nil, rpcErr
	}
	d.touch()
	return h(req.Params, c)
}

// checkHumanPeer gates human-privileged (no-Auth) requests by peer uid.
func (d *Daemon) checkHumanPeer(peerUID uint32, credOK bool) *protocol.RPCError {
	if d.AdminUID >= 0 {
		// explicit admin uid → fail closed: креды обязаны читаться
		if !credOK || (int64(peerUID) != int64(d.AdminUID) && peerUID != 0) {
			return &protocol.RPCError{Code: protocol.CodeForbidden,
				Message: fmt.Sprintf("human operations are restricted to uid %d on this daemon", d.AdminUID)}
		}
		return nil
	}
	// default: the daemon's own uid and root; unreadable creds fall back to
	// the 0600 socket permissions that already gate access
	if credOK && int64(peerUID) != int64(os.Getuid()) && peerUID != 0 {
		return &protocol.RPCError{Code: protocol.CodeForbidden,
			Message: "human operations are allowed only for the daemon owner"}
	}
	return nil
}

func (d *Daemon) touch() {
	d.mu.Lock()
	d.lastUsed = time.Now()
	d.mu.Unlock()
}

func decode[T any](params json.RawMessage) (T, *protocol.RPCError) {
	var v T
	if err := json.Unmarshal(params, &v); err != nil {
		return v, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: "bad params: " + err.Error()}
	}
	return v, nil
}

func validateReason(reason string) *protocol.RPCError {
	if len(reason) > maxReasonLen {
		return &protocol.RPCError{Code: protocol.CodeBadRequest, Message: "reason is too long (max 2048 bytes)"}
	}
	return nil
}

func humanOnly(c caller) *protocol.RPCError {
	if !c.human {
		return &protocol.RPCError{Code: protocol.CodeForbidden, Message: "agents have read-only access; this operation is human-only"}
	}
	return nil
}

// inDelegationScope reports whether a delegated caller's patterns admit path.
func (c caller) inDelegationScope(path string) bool {
	if !c.delegated() {
		return true
	}
	for _, p := range c.patterns {
		if ok, _ := doublestar.Match(p, path); ok {
			return true
		}
	}
	return false
}

// --- handlers ---

func (d *Daemon) handleUnlock(params json.RawMessage, c caller) (any, *protocol.RPCError) {
	if e := humanOnly(c); e != nil {
		return nil, e
	}
	p, e := decode[protocol.UnlockParams](params)
	if e != nil {
		return nil, e
	}
	if err := ageio.ValidatePassphrase(p.Passphrase); err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: err.Error()}
	}
	id, err := ageio.LoadIdentityEncrypted(paths.IdentityFile(), p.Passphrase)
	if err != nil {
		if e := d.appendAudit(audit.Entry{ActorType: "human", Actor: "cli", Action: "unlock", Result: "denied", Reason: "bad_passphrase"}); e != nil {
			return nil, e
		}
		return nil, &protocol.RPCError{Code: protocol.CodeDenied, Message: "wrong passphrase"}
	}
	recs, err := ageio.LoadRecipients(paths.RecipientsFile())
	if err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: "cannot load recipients: " + err.Error()}
	}
	if e := d.appendAudit(audit.Entry{ActorType: "human", Actor: "cli", Action: "unlock", Result: "granted"}); e != nil {
		return nil, e
	}
	d.mu.Lock()
	d.identity = id
	d.recipients = recs
	d.mu.Unlock()
	return protocol.UnlockResult{Unlocked: true}, nil
}

func (d *Daemon) handleLock(_ json.RawMessage, c caller) (any, *protocol.RPCError) {
	if e := humanOnly(c); e != nil {
		return nil, e
	}
	if e := d.appendAudit(audit.Entry{ActorType: "human", Actor: "cli", Action: "lock", Result: "granted"}); e != nil {
		return nil, e
	}
	d.mu.Lock()
	d.identity = nil
	d.recipients = nil
	d.mu.Unlock()
	return protocol.UnlockResult{Unlocked: false}, nil
}

func (d *Daemon) handleStatus(_ json.RawMessage, _ caller) (any, *protocol.RPCError) {
	d.mu.Lock()
	unlocked := d.identity != nil
	var locksAt *time.Time
	if unlocked {
		t := d.lastUsed.Add(d.idleTimeout)
		locksAt = &t
	}
	d.mu.Unlock()
	all, _ := d.store.List("")
	return protocol.StatusResult{
		Unlocked: unlocked, LocksAt: locksAt, StoreDir: paths.StoreDir(),
		SecretCount: len(all), PendingRequests: len(d.requests.List()),
	}, nil
}

func (d *Daemon) crypto() (age.Identity, []age.Recipient, *protocol.RPCError) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.identity == nil {
		return nil, nil, &protocol.RPCError{Code: protocol.CodeLocked, Message: "store is locked — run 'rutile unlock'"}
	}
	return d.identity, d.recipients, nil
}

func (d *Daemon) handleGet(params json.RawMessage, c caller) (any, *protocol.RPCError) {
	p, e := decode[protocol.GetParams](params)
	if e != nil {
		return nil, e
	}
	if err := store.ValidatePath(p.Path); err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: err.Error()}
	}
	if e := validateReason(p.Reason); e != nil {
		return nil, e
	}
	d.rw.RLock()
	defer d.rw.RUnlock()
	deny := func(code, reason, msg string) (any, *protocol.RPCError) {
		if e := d.appendAudit(audit.Entry{ActorType: c.actorType(), Actor: c.name(), Action: "get", Path: p.Path, Result: "denied", Reason: reason, Note: p.Reason}); e != nil {
			return nil, e
		}
		return nil, &protocol.RPCError{Code: code, Message: msg}
	}
	var dec policy.Decision
	if !c.human {
		// a delegated caller is first bounded by its own patterns...
		if !c.inDelegationScope(p.Path) {
			return deny(protocol.CodeDenied, "delegation_scope",
				fmt.Sprintf("path %q is outside this delegated token's scope %v", p.Path, c.patterns))
		}
		// ...and then, like any agent, by the PARENT's live policy
		var err error
		dec, err = d.policy.Evaluate(c.agent, p.Path)
		if err != nil {
			return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: err.Error()}
		}
		if !dec.Allowed {
			return deny(protocol.CodeDenied, dec.Reason,
				fmt.Sprintf("access to %q denied (%s) — file a request with the request_access tool, or ask the human to run: rutile allow %s %q", p.Path, dec.Reason, c.agent, p.Path))
		}
	}
	id, _, rpcErr := d.crypto()
	if rpcErr != nil {
		return deny(rpcErr.Code, "locked", rpcErr.Message)
	}
	ct, err := d.store.Read(p.Path)
	if errors.Is(err, store.ErrNotFound) {
		return deny(protocol.CodeNotFound, "not_found", "no secret at "+p.Path)
	}
	if err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: err.Error()}
	}
	pt, err := ageio.Decrypt(id, ct)
	if err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: "decrypt failed: " + err.Error()}
	}
	// Consume only after successful decryption, but before disclosure. The
	// durable consume is the linearization point for concurrent one-time reads.
	if !c.human && dec.OneTimePattern != "" {
		if err := d.policy.Consume(c.agent, p.Path, dec.OneTimePattern); err != nil {
			if errors.Is(err, policy.ErrGrantConsumed) {
				return deny(protocol.CodeDenied, "one_time_race", "one-time grant was already consumed by another request")
			}
			return deny(protocol.CodeInternal, "one_time_persist_failed", "could not durably consume one-time grant; refusing to disclose the secret")
		}
	}
	if e := d.appendAudit(audit.Entry{ActorType: c.actorType(), Actor: c.name(), Action: "get", Path: p.Path, Result: "granted", Note: p.Reason}); e != nil {
		return nil, e
	}
	return protocol.GetResult{Value: string(pt)}, nil
}

func (d *Daemon) handleList(params json.RawMessage, c caller) (any, *protocol.RPCError) {
	p, e := decode[protocol.ListParams](params)
	if e != nil {
		return nil, e
	}
	if p.Prefix != "" {
		if err := store.ValidatePath(p.Prefix); err != nil {
			return nil, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: err.Error()}
		}
	}
	all, err := d.store.List(p.Prefix)
	if err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: err.Error()}
	}
	if !c.human {
		visible := all[:0]
		for _, path := range all {
			if c.inDelegationScope(path) && d.policy.Allowed(c.agent, path) {
				visible = append(visible, path)
			}
		}
		all = visible
	}
	if e := d.appendAudit(audit.Entry{ActorType: c.actorType(), Actor: c.name(), Action: "list", Path: p.Prefix, Result: "granted"}); e != nil {
		return nil, e
	}
	return protocol.ListResult{Paths: all}, nil
}

func (d *Daemon) handlePut(params json.RawMessage, c caller) (any, *protocol.RPCError) {
	if e := humanOnly(c); e != nil {
		return nil, e
	}
	p, e := decode[protocol.PutParams](params)
	if e != nil {
		return nil, e
	}
	if err := store.ValidatePath(p.Path); err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: err.Error()}
	}
	if err := store.ValidateSecretValue(p.Value); err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: err.Error()}
	}
	d.rw.RLock()
	defer d.rw.RUnlock()
	_, recs, rpcErr := d.crypto()
	if rpcErr != nil {
		return nil, rpcErr
	}
	ct, err := ageio.Encrypt(recs, []byte(p.Value))
	if err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: err.Error()}
	}
	if err := d.store.Write(p.Path, ct); err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: err.Error()}
	}
	if e := d.appendAudit(audit.Entry{ActorType: "human", Actor: "cli", Action: "put", Path: p.Path, Result: "granted"}); e != nil {
		return nil, e
	}
	if err := gitsync.Commit(paths.Dir(), "put "+p.Path); err != nil {
		d.log.Warn("git commit failed", "err", err)
	}
	return protocol.PutResult{Path: p.Path}, nil
}

func (d *Daemon) handleDel(params json.RawMessage, c caller) (any, *protocol.RPCError) {
	if e := humanOnly(c); e != nil {
		return nil, e
	}
	p, e := decode[protocol.DelParams](params)
	if e != nil {
		return nil, e
	}
	d.rw.RLock()
	defer d.rw.RUnlock()
	if err := d.store.Remove(p.Path); errors.Is(err, store.ErrNotFound) {
		return nil, &protocol.RPCError{Code: protocol.CodeNotFound, Message: "no secret at " + p.Path}
	} else if err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: err.Error()}
	}
	if e := d.appendAudit(audit.Entry{ActorType: "human", Actor: "cli", Action: "del", Path: p.Path, Result: "granted"}); e != nil {
		return nil, e
	}
	if err := gitsync.Commit(paths.Dir(), "del "+p.Path); err != nil {
		d.log.Warn("git commit failed", "err", err)
	}
	return protocol.DelResult{Path: p.Path}, nil
}

func (d *Daemon) handleAgentAdd(params json.RawMessage, c caller) (any, *protocol.RPCError) {
	if e := humanOnly(c); e != nil {
		return nil, e
	}
	p, e := decode[protocol.AgentAddParams](params)
	if e != nil {
		return nil, e
	}
	var ttl time.Duration
	if p.Expires != "" {
		var err error
		if ttl, err = agents.ParseTTL(p.Expires); err != nil {
			return nil, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: err.Error()}
		}
	}
	token, err := d.agents.Add(p.Name, p.Description, p.Type, ttl, p.LocalOnly)
	if err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: err.Error()}
	}
	if e := d.appendAudit(audit.Entry{ActorType: "human", Actor: "cli", Action: "agent_add", Path: p.Name, Result: "granted"}); e != nil {
		return nil, e
	}
	_ = gitsync.Commit(paths.Dir(), "agent add "+p.Name)
	return protocol.AgentAddResult{Name: p.Name, Token: token}, nil
}

func (d *Daemon) handleAgentList(_ json.RawMessage, c caller) (any, *protocol.RPCError) {
	if e := humanOnly(c); e != nil {
		return nil, e
	}
	list, err := d.agents.List()
	if err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: err.Error()}
	}
	out := protocol.AgentListResult{}
	for _, a := range list {
		out.Agents = append(out.Agents, protocol.AgentInfo{
			Name: a.Name, Description: a.Description, Type: a.Type, TokenPrefix: a.TokenPrefix,
			CreatedAt: a.CreatedAt, ExpiresAt: a.ExpiresAt, LocalOnly: a.LocalOnly,
			Disabled: a.Disabled, LastUsedAt: a.LastUsedAt,
		})
	}
	return out, nil
}

func (d *Daemon) handleAgentRevoke(params json.RawMessage, c caller) (any, *protocol.RPCError) {
	if e := humanOnly(c); e != nil {
		return nil, e
	}
	p, e := decode[protocol.AgentRevokeParams](params)
	if e != nil {
		return nil, e
	}
	if err := d.agents.Revoke(p.Name); err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeNotFound, Message: err.Error()}
	}
	if _, err := d.policy.Remove(p.Name, ""); err != nil {
		d.log.Warn("removing revoked agent's rules failed", "err", err)
	}
	if n, err := d.delegations.RevokeByParent(p.Name); err != nil {
		d.log.Warn("revoking agent's delegations failed", "err", err)
	} else if n > 0 {
		d.log.Info("revoked delegations of removed agent", "agent", p.Name, "count", n)
	}
	if e := d.appendAudit(audit.Entry{ActorType: "human", Actor: "cli", Action: "agent_revoke", Path: p.Name, Result: "granted"}); e != nil {
		return nil, e
	}
	_ = gitsync.Commit(paths.Dir(), "agent revoke "+p.Name)
	return protocol.OKResult{OK: true}, nil
}

func (d *Daemon) handleRuleAdd(params json.RawMessage, c caller) (any, *protocol.RPCError) {
	if e := humanOnly(c); e != nil {
		return nil, e
	}
	p, e := decode[protocol.RuleAddParams](params)
	if e != nil {
		return nil, e
	}
	if _, err := d.agents.Get(p.Agent); err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeNotFound, Message: "unknown agent " + p.Agent + " — register it first: rutile agent add " + p.Agent}
	}
	var ttl time.Duration
	if p.For != "" {
		var err error
		if ttl, err = time.ParseDuration(p.For); err != nil || ttl <= 0 {
			return nil, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: "bad duration: " + p.For}
		}
	}
	if p.Pattern == "" || len(p.Pattern) > store.MaxPathLen {
		return nil, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: "policy pattern is empty or too long"}
	}
	r, err := d.policy.Add(p.Agent, p.Pattern, ttl, p.OneTime)
	if err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: err.Error()}
	}
	if e := d.appendAudit(audit.Entry{ActorType: "human", Actor: "cli", Action: "allow", Path: p.Agent + " " + p.Pattern, Result: "granted"}); e != nil {
		return nil, e
	}
	_ = gitsync.Commit(paths.Dir(), "allow "+p.Agent+" "+p.Pattern)
	return ruleInfo(r), nil
}

func (d *Daemon) handleRuleDel(params json.RawMessage, c caller) (any, *protocol.RPCError) {
	if e := humanOnly(c); e != nil {
		return nil, e
	}
	p, e := decode[protocol.RuleDelParams](params)
	if e != nil {
		return nil, e
	}
	if len(p.Pattern) > store.MaxPathLen {
		return nil, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: "policy pattern is too long"}
	}
	n, err := d.policy.Remove(p.Agent, p.Pattern)
	if err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: err.Error()}
	}
	if e := d.appendAudit(audit.Entry{ActorType: "human", Actor: "cli", Action: "deny", Path: p.Agent + " " + p.Pattern, Result: "granted"}); e != nil {
		return nil, e
	}
	_ = gitsync.Commit(paths.Dir(), "deny "+p.Agent+" "+p.Pattern)
	return protocol.RuleDelResult{Removed: n}, nil
}

func (d *Daemon) handleRuleList(_ json.RawMessage, c caller) (any, *protocol.RPCError) {
	if e := humanOnly(c); e != nil {
		return nil, e
	}
	out := protocol.RuleListResult{}
	for _, r := range d.policy.List() {
		out.Rules = append(out.Rules, ruleInfo(r))
	}
	return out, nil
}

func (d *Daemon) handleAccessRequest(params json.RawMessage, c caller) (any, *protocol.RPCError) {
	if c.human {
		return nil, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: "access_request is for agents; humans use 'rutile allow'"}
	}
	if c.delegated() {
		return nil, &protocol.RPCError{Code: protocol.CodeForbidden, Message: "delegated tokens cannot file access requests; ask the parent agent"}
	}
	p, e := decode[protocol.AccessRequestParams](params)
	if e != nil {
		return nil, e
	}
	if err := store.ValidatePath(p.Path); err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: err.Error()}
	}
	if e := validateReason(p.Reason); e != nil {
		return nil, e
	}
	r, err := d.requests.Add(c.agent, p.Path, p.Reason)
	if err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: err.Error()}
	}
	if e := d.appendAudit(audit.Entry{ActorType: "agent", Actor: c.agent, Action: "access_request", Path: p.Path, Result: "granted", Reason: "id:" + r.ID, Note: p.Reason}); e != nil {
		return nil, e
	}
	return protocol.AccessRequestResult{ID: r.ID, Status: "pending"}, nil
}

func (d *Daemon) handleRequestList(_ json.RawMessage, c caller) (any, *protocol.RPCError) {
	if e := humanOnly(c); e != nil {
		return nil, e
	}
	out := protocol.RequestListResult{}
	for _, r := range d.requests.List() {
		out.Requests = append(out.Requests, protocol.RequestInfo{
			ID: r.ID, Agent: r.Agent, Path: r.Path, Reason: r.Reason, CreatedAt: r.CreatedAt,
		})
	}
	return out, nil
}

func (d *Daemon) handleRequestResolve(params json.RawMessage, c caller) (any, *protocol.RPCError) {
	if e := humanOnly(c); e != nil {
		return nil, e
	}
	p, e := decode[protocol.RequestResolveParams](params)
	if e != nil {
		return nil, e
	}
	var ttl time.Duration
	if p.Approve && p.For != "" {
		var err error
		if ttl, err = time.ParseDuration(p.For); err != nil || ttl <= 0 {
			return nil, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: "bad duration: " + p.For}
		}
	}
	r, err := d.requests.Take(p.ID)
	if err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeNotFound, Message: "no pending request " + p.ID}
	}
	res := protocol.RequestResolveResult{ID: r.ID, Approved: p.Approve}
	if p.Approve {
		rule, err := d.policy.Add(r.Agent, r.Path, ttl, p.OneTime)
		if err != nil {
			if restoreErr := d.requests.Restore(r); restoreErr != nil {
				d.log.Error("restoring request after failed approval", "id", r.ID, "err", restoreErr)
				return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: "approval failed and pending request could not be restored"}
			}
			return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: err.Error()}
		}
		ri := ruleInfo(rule)
		res.Rule = &ri
		if e := d.appendAudit(audit.Entry{ActorType: "human", Actor: "cli", Action: "approve", Path: r.Agent + " " + r.Path, Result: "granted", Reason: "id:" + r.ID}); e != nil {
			return nil, e
		}
		_ = gitsync.Commit(paths.Dir(), "approve "+r.Agent+" "+r.Path)
	} else {
		if e := d.appendAudit(audit.Entry{ActorType: "human", Actor: "cli", Action: "reject", Path: r.Agent + " " + r.Path, Result: "granted", Reason: "id:" + r.ID}); e != nil {
			return nil, e
		}
	}
	return res, nil
}

func (d *Daemon) handleDelegate(params json.RawMessage, c caller) (any, *protocol.RPCError) {
	if c.human {
		return nil, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: "delegate is for agents; humans use 'rutile agent add' + 'rutile allow'"}
	}
	if c.delegated() {
		return nil, &protocol.RPCError{Code: protocol.CodeForbidden, Message: "delegated tokens cannot delegate further (depth limit is 1)"}
	}
	p, e := decode[protocol.DelegateParams](params)
	if e != nil {
		return nil, e
	}
	var ttl time.Duration
	if p.TTL != "" {
		var err error
		if ttl, err = time.ParseDuration(p.TTL); err != nil || ttl <= 0 {
			return nil, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: "bad ttl: " + p.TTL}
		}
	}
	del, token, err := d.delegations.Create(c.agent, p.Label, p.Patterns, ttl)
	if err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: err.Error()}
	}
	if e := d.appendAudit(audit.Entry{
		ActorType: "agent", Actor: c.agent, Action: "delegate",
		Path: p.Label + " " + strings.Join(p.Patterns, ","), Result: "granted", Reason: "id:" + del.ID,
	}); e != nil {
		return nil, e
	}
	return protocol.DelegateResult{ID: del.ID, Token: token, ExpiresAt: del.ExpiresAt}, nil
}

func (d *Daemon) handleDelegationList(_ json.RawMessage, c caller) (any, *protocol.RPCError) {
	if e := humanOnly(c); e != nil {
		return nil, e
	}
	out := protocol.DelegationListResult{}
	for _, del := range d.delegations.List() {
		out.Delegations = append(out.Delegations, protocol.DelegationInfo{
			ID: del.ID, Parent: del.Parent, Label: del.Label, TokenPfx: del.TokenPfx,
			Patterns: del.Patterns, CreatedAt: del.CreatedAt, ExpiresAt: del.ExpiresAt,
		})
	}
	return out, nil
}

func (d *Daemon) handleDelegationRevoke(params json.RawMessage, c caller) (any, *protocol.RPCError) {
	p, e := decode[protocol.DelegationRevokeParams](params)
	if e != nil {
		return nil, e
	}
	parent := "" // human may revoke anything
	if !c.human {
		if c.delegated() {
			return nil, &protocol.RPCError{Code: protocol.CodeForbidden, Message: "delegated tokens cannot revoke delegations"}
		}
		parent = c.agent // an agent may revoke only its own children
	}
	if err := d.delegations.Revoke(p.ID, parent); err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeNotFound, Message: "no delegation " + p.ID}
	}
	if e := d.appendAudit(audit.Entry{ActorType: c.actorType(), Actor: c.name(), Action: "delegation_revoke", Path: p.ID, Result: "granted"}); e != nil {
		return nil, e
	}
	return protocol.OKResult{OK: true}, nil
}

// handleRotate re-encrypts the whole store under a fresh identity.
// Rotation uses a dual-recipient transition. Every secret is first encrypted
// to both the old and new keys. Only then does the identity switch to the new
// key, after which a second pass removes the old recipient. At every crash
// point the identity currently on disk can decrypt every store file.
func (d *Daemon) handleRotate(params json.RawMessage, c caller) (any, *protocol.RPCError) {
	if e := humanOnly(c); e != nil {
		return nil, e
	}
	p, e := decode[protocol.RotateParams](params)
	if e != nil {
		return nil, e
	}
	if err := ageio.ValidatePassphrase(p.NewPassphrase); err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeBadRequest, Message: err.Error()}
	}
	d.rw.Lock()
	defer d.rw.Unlock()
	oldID, oldRecs, rpcErr := d.crypto()
	if rpcErr != nil {
		return nil, rpcErr
	}
	newID, err := ageio.GenerateIdentity()
	if err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: err.Error()}
	}
	// decrypt everything up front: abort untouched on any failure
	all, err := d.store.List("")
	if err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: err.Error()}
	}
	plain := make(map[string][]byte, len(all))
	for _, path := range all {
		ct, err := d.store.Read(path)
		if err != nil {
			return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: "read " + path + ": " + err.Error()}
		}
		pt, err := ageio.Decrypt(oldID, ct)
		if err != nil {
			return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: "decrypt " + path + ": " + err.Error()}
		}
		plain[path] = pt
	}
	data, err := os.ReadFile(paths.IdentityFile())
	if err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: "read old identity: " + err.Error()}
	}
	backupPath, err := writeIdentityBackup(data)
	if err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: "backup old identity: " + err.Error()}
	}
	newRecs := []age.Recipient{newID.Recipient()}
	transitionRecs := append(append([]age.Recipient(nil), oldRecs...), newID.Recipient())
	// Phase 1: make every ciphertext readable by either identity while the
	// old identity and recipients remain authoritative.
	for path, pt := range plain {
		ct, err := ageio.Encrypt(transitionRecs, pt)
		if err != nil {
			return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: "transition encrypt " + path + ": " + err.Error()}
		}
		if err := d.rotateWrite(path, ct); err != nil {
			return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: "transition write " + path + ": " + err.Error()}
		}
	}
	// During the metadata switch, writes also target both recipients. Thus
	// either the old or new identity file is always compatible with the store.
	if err := ageio.SaveRecipients(paths.RecipientsFile(), transitionRecs...); err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: "save transition recipients: " + err.Error()}
	}
	if err := d.rotateIdentityWrite(paths.IdentityFile(), newID, p.NewPassphrase); err != nil {
		// Atomic replacement can report a directory-fsync error after rename.
		// Reconcile from disk before deciding which identity is authoritative;
		// otherwise later writes could use the old recipient while restart loads
		// the new identity.
		onDisk, loadErr := ageio.LoadIdentityEncrypted(paths.IdentityFile(), p.NewPassphrase)
		if loadErr == nil && onDisk.String() == newID.String() {
			d.mu.Lock()
			d.identity = newID
			d.recipients = transitionRecs
			d.mu.Unlock()
			return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: "identity switch reached disk despite a persistence error; the new passphrase is active and the store remains in a safe dual-recipient state; fix storage and rerun rotate: " + err.Error()}
		}
		return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: "save new identity: " + err.Error()}
	}
	d.mu.Lock()
	d.identity = newID
	d.recipients = transitionRecs
	d.mu.Unlock()
	// Phase 2: now that the new identity is authoritative, remove the old
	// recipient from every ciphertext. A failure leaves a readable mixture of
	// dual-recipient and new-only files and can safely be retried.
	for path, pt := range plain {
		ct, err := ageio.Encrypt(newRecs, pt)
		if err != nil {
			return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: "rotation is in a safe transition state and the new passphrase is active; fix the error and rerun rotate: final encrypt " + path + ": " + err.Error()}
		}
		if err := d.rotateWrite(path, ct); err != nil {
			return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: "rotation is in a safe transition state and the new passphrase is active; fix the error and rerun rotate: final write " + path + ": " + err.Error()}
		}
	}
	if err := ageio.SaveRecipients(paths.RecipientsFile(), newRecs...); err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: "rotation is in a safe transition state and the new passphrase is active; fix the error and rerun rotate: save final recipients: " + err.Error()}
	}
	d.mu.Lock()
	d.recipients = newRecs
	d.mu.Unlock()
	if e := d.appendAudit(audit.Entry{ActorType: "human", Actor: "cli", Action: "rotate", Result: "granted", Reason: fmt.Sprintf("reencrypted:%d", len(plain))}); e != nil {
		return nil, e
	}
	_ = gitsync.Commit(paths.Dir(), "rotate keys")
	return protocol.RotateResult{Reencrypted: len(plain), Backup: backupPath}, nil
}

func writeIdentityBackup(data []byte) (string, error) {
	base := paths.IdentityFile() + ".bak"
	if existing, err := os.ReadFile(base); err == nil {
		if bytes.Equal(existing, data) {
			return base, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	} else if err := atomicfile.WriteExclusive(base, data, 0o600); err == nil {
		return base, nil
	} else if !errors.Is(err, os.ErrExist) {
		return "", err
	}
	for range 10 {
		candidate := fmt.Sprintf("%s-%s", base, time.Now().UTC().Format("20060102-150405.000000000"))
		if err := atomicfile.WriteExclusive(candidate, data, 0o600); err == nil {
			return candidate, nil
		} else if !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
	return "", errors.New("could not allocate a unique identity backup path")
}

func (d *Daemon) handleAuditRotate(_ json.RawMessage, c caller) (any, *protocol.RPCError) {
	if e := humanOnly(c); e != nil {
		return nil, e
	}
	archive, n, err := d.audit.Rotate()
	if err != nil {
		return nil, &protocol.RPCError{Code: protocol.CodeInternal, Message: err.Error()}
	}
	return protocol.AuditRotateResult{Archive: archive, Entries: n}, nil
}

func ruleInfo(r policy.Rule) protocol.RuleInfo {
	return protocol.RuleInfo{
		Agent: r.Agent, Pattern: r.Pattern, OneTime: r.OneTime, Consumed: r.Consumed,
		CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
	}
}
