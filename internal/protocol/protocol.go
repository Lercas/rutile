// Package protocol defines the newline-delimited JSON wire protocol spoken
// over the daemon's unix socket, shared by the daemon and all clients.
package protocol

import (
	"encoding/json"
	"time"
)

type Request struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Auth   *AgentAuth      `json:"auth,omitempty"` // nil => human CLI caller
	Params json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	ID     string          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *RPCError       `json:"error,omitempty"`
}

type RPCError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string { return e.Code + ": " + e.Message }

// Error codes.
const (
	CodeLocked       = "locked"
	CodeDenied       = "policy_denied"
	CodeNotFound     = "not_found"
	CodeInvalidToken = "invalid_token"
	CodeBadRequest   = "bad_request"
	CodeInternal     = "internal"
	CodeForbidden    = "forbidden" // write ops attempted by an agent
)

type AgentAuth struct {
	Agent string `json:"agent"`
	Token string `json:"token"`
	// Transport is set by rutile's own MCP HTTP server ("http"); empty means
	// a local caller. Used to enforce local-only tokens.
	Transport string `json:"transport,omitempty"`
	// Cert carries an mTLS/SPIFFE identity asserted by rutile's own HTTP
	// server after client-certificate verification (e.g. a SPIFFE ID). When
	// set with an empty Token, the daemon authenticates the agent by name
	// without a bearer token.
	Cert string `json:"cert,omitempty"`
}

// --- method params/results ---

type UnlockParams struct {
	Passphrase string `json:"passphrase"`
}
type UnlockResult struct {
	Unlocked bool `json:"unlocked"`
}

type StatusResult struct {
	Unlocked        bool       `json:"unlocked"`
	LocksAt         *time.Time `json:"locks_at,omitempty"`
	StoreDir        string     `json:"store_dir"`
	SecretCount     int        `json:"secret_count"`
	PendingRequests int        `json:"pending_requests"`
}

type GetParams struct {
	Path   string `json:"path"`
	Reason string `json:"reason,omitempty"` // agent-supplied purpose, recorded in the audit log
}
type GetResult struct {
	Value string `json:"value"`
}

type ListParams struct {
	Prefix string `json:"prefix,omitempty"`
}
type ListResult struct {
	Paths []string `json:"paths"`
}

type PutParams struct {
	Path  string `json:"path"`
	Value string `json:"value"`
}
type PutResult struct {
	Path string `json:"path"`
}

type DelParams struct {
	Path string `json:"path"`
}
type DelResult struct {
	Path string `json:"path"`
}

type AgentAddParams struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type,omitempty"`    // claude-code | cursor | ci | framework | custom …
	Expires     string `json:"expires,omitempty"` // "30d", "12h"; empty = never
	LocalOnly   bool   `json:"local_only,omitempty"`
}
type AgentAddResult struct {
	Name  string `json:"name"`
	Token string `json:"token"` // shown once, never stored in plaintext
}

type AgentInfo struct {
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Type        string     `json:"type,omitempty"`
	TokenPrefix string     `json:"token_prefix"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LocalOnly   bool       `json:"local_only,omitempty"`
	Disabled    bool       `json:"disabled"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}
type AgentListResult struct {
	Agents []AgentInfo `json:"agents"`
}

type AgentRevokeParams struct {
	Name string `json:"name"`
}
type OKResult struct {
	OK bool `json:"ok"`
}

type RuleAddParams struct {
	Agent   string `json:"agent"`
	Pattern string `json:"pattern"`
	For     string `json:"for,omitempty"` // duration, e.g. "1h"; empty = permanent
	OneTime bool   `json:"one_time,omitempty"`
}

type RuleDelParams struct {
	Agent   string `json:"agent"`
	Pattern string `json:"pattern,omitempty"` // empty = all rules for agent
}
type RuleDelResult struct {
	Removed int `json:"removed"`
}

type RuleInfo struct {
	Agent     string     `json:"agent"`
	Pattern   string     `json:"pattern"`
	OneTime   bool       `json:"one_time,omitempty"`
	Consumed  bool       `json:"consumed,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}
type RuleListResult struct {
	Rules []RuleInfo `json:"rules"`
}

type AccessRequestParams struct {
	Path   string `json:"path"`
	Reason string `json:"reason,omitempty"`
}
type AccessRequestResult struct {
	ID     string `json:"id"`
	Status string `json:"status"` // always "pending"
}

type RequestInfo struct {
	ID        string    `json:"id"`
	Agent     string    `json:"agent"`
	Path      string    `json:"path"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
type RequestListResult struct {
	Requests []RequestInfo `json:"requests"`
}

type RequestResolveParams struct {
	ID      string `json:"id"`
	Approve bool   `json:"approve"`
	For     string `json:"for,omitempty"`
	OneTime bool   `json:"one_time,omitempty"`
}
type RequestResolveResult struct {
	ID       string    `json:"id"`
	Approved bool      `json:"approved"`
	Rule     *RuleInfo `json:"rule,omitempty"`
}

type DelegateParams struct {
	Label    string   `json:"label"`
	Patterns []string `json:"patterns"`
	TTL      string   `json:"ttl,omitempty"` // duration; default 1h, capped 24h
}
type DelegateResult struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"` // shown once
	ExpiresAt time.Time `json:"expires_at"`
}

type DelegationInfo struct {
	ID        string    `json:"id"`
	Parent    string    `json:"parent"`
	Label     string    `json:"label"`
	TokenPfx  string    `json:"token_prefix"`
	Patterns  []string  `json:"patterns"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}
type DelegationListResult struct {
	Delegations []DelegationInfo `json:"delegations"`
}
type DelegationRevokeParams struct {
	ID string `json:"id"`
}

type RotateParams struct {
	NewPassphrase string `json:"new_passphrase"`
}
type RotateResult struct {
	Reencrypted int    `json:"reencrypted"`
	Backup      string `json:"backup,omitempty"`
}

type AuditRotateResult struct {
	Archive string `json:"archive"`
	Entries int64  `json:"entries"`
}
