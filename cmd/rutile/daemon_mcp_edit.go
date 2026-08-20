package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/Lercas/rutile/internal/agents"
	"github.com/Lercas/rutile/internal/daemon"
	"github.com/Lercas/rutile/internal/ipc"
	"github.com/Lercas/rutile/internal/paths"
	"github.com/Lercas/rutile/internal/protocol"
	"github.com/Lercas/rutile/internal/ratelimit"
	"github.com/Lercas/rutile/internal/store"
)

func cmdDaemon() *cobra.Command {
	var idle time.Duration
	var socketMode string
	var adminUID int
	c := &cobra.Command{
		Use:    "daemon",
		Short:  "Запустить демона в foreground (обычно стартует сам)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			log := slog.New(slog.NewTextHandler(os.Stderr, nil))
			d, err := daemon.New(log, idle)
			if err != nil {
				return err
			}
			mode, err := strconv.ParseUint(socketMode, 8, 32)
			if err != nil {
				return fmt.Errorf("bad --socket-mode %q: ожидается восьмеричное, например 0600", socketMode)
			}
			if mode != 0o600 && mode != 0o660 {
				return fmt.Errorf("unsafe --socket-mode %q: allowed values are 0600 and 0660", socketMode)
			}
			if mode == 0o660 && adminUID < 0 {
				return errors.New("--socket-mode 0660 requires --admin-uid so group peers cannot perform human operations")
			}
			if adminUID < -1 || int64(adminUID) > int64(^uint32(0)) {
				return fmt.Errorf("bad --admin-uid %d: expected -1 or a valid uint32 uid", adminUID)
			}
			d.SocketMode = os.FileMode(mode)
			d.AdminUID = adminUID
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return d.Run(ctx)
		},
	}
	c.Flags().DurationVar(&idle, "idle-timeout", daemon.DefaultIdleTimeout, "авто-блокировка после простоя")
	c.Flags().StringVar(&socketMode, "socket-mode", "0600", "права сокета (system mode: 0660 + группа)")
	c.Flags().IntVar(&adminUID, "admin-uid", -1, "uid, которому разрешены human-операции (peer-cred check); -1 = владелец демона")
	return c
}

// --- MCP server mode: a thin client of the daemon for AI agents ---

func agentAuthFromEnv() (*protocol.AgentAuth, error) {
	name, token := os.Getenv("RUTILE_AGENT"), os.Getenv("RUTILE_TOKEN")
	if name == "" || token == "" {
		return nil, errors.New("RUTILE_AGENT and RUTILE_TOKEN env vars are required (get them via: rutile agent add <name>)")
	}
	return &protocol.AgentAuth{Agent: name, Token: token}, nil
}

type getSecretIn struct {
	Path   string `json:"path" jsonschema:"secret path, e.g. dev/myproject/api-key"`
	Reason string `json:"reason,omitempty" jsonschema:"short purpose of this read; recorded in the human's audit log"`
}
type getSecretOut struct {
	Value string `json:"value"`
}
type listSecretsIn struct {
	Prefix string `json:"prefix,omitempty" jsonschema:"optional path prefix filter"`
}
type listSecretsOut struct {
	Paths []string `json:"paths"`
}
type requestAccessIn struct {
	Path   string `json:"path" jsonschema:"secret path to request access to"`
	Reason string `json:"reason" jsonschema:"why access is needed; the human sees this when deciding"`
}
type requestAccessOut struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}
type delegateIn struct {
	Label    string   `json:"label" jsonschema:"short name of the sub-agent, e.g. worker-1"`
	Patterns []string `json:"patterns" jsonschema:"path globs the sub-token may read, e.g. dev/build/**"`
	TTL      string   `json:"ttl,omitempty" jsonschema:"lifetime like 30m or 2h; default 1h, max 24h"`
}
type delegateOut struct {
	ID        string `json:"id"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}
type storeStatusIn struct{}
type storeStatusOut struct {
	Unlocked       bool `json:"unlocked"`
	VisibleSecrets int  `json:"visible_secrets"`
}

var readOnly = &mcp.ToolAnnotations{ReadOnlyHint: true}

const maxMCPRequestBody int64 = 1 << 20

// newMCPServer builds the tool surface for one authenticated agent.
func newMCPServer(auth *protocol.AgentAuth) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "rutile", Version: version}, nil)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_secret",
		Description: "Fetch a secret value from the rutile store. Pass a short `reason` — it lands in the human's audit log. On policy denial use request_access instead of retrying.",
		Annotations: readOnly,
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getSecretIn) (*mcp.CallToolResult, getSecretOut, error) {
		var res protocol.GetResult
		if err := ipc.Call("get", auth, protocol.GetParams{Path: in.Path, Reason: in.Reason}, &res); err != nil {
			return nil, getSecretOut{}, mcpFriendly(err)
		}
		return nil, getSecretOut{Value: res.Value}, nil
	})
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_secrets",
		Description: "List secret paths this agent is currently allowed to read.",
		Annotations: readOnly,
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listSecretsIn) (*mcp.CallToolResult, listSecretsOut, error) {
		var res protocol.ListResult
		if err := ipc.Call("list", auth, protocol.ListParams{Prefix: in.Prefix}, &res); err != nil {
			return nil, listSecretsOut{}, mcpFriendly(err)
		}
		if res.Paths == nil {
			res.Paths = []string{}
		}
		return nil, listSecretsOut{Paths: res.Paths}, nil
	})
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "request_access",
		Description: "File a pending access request for a secret path this agent cannot read yet. The human reviews it with 'rutile requests' and approves or rejects. Returns immediately; do not poll — tell the user a request is waiting.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in requestAccessIn) (*mcp.CallToolResult, requestAccessOut, error) {
		var res protocol.AccessRequestResult
		if err := ipc.Call("access_request", auth, protocol.AccessRequestParams{Path: in.Path, Reason: in.Reason}, &res); err != nil {
			return nil, requestAccessOut{}, mcpFriendly(err)
		}
		return nil, requestAccessOut{
			ID:      res.ID,
			Status:  res.Status,
			Message: "Request " + res.ID + " is pending. Tell the user to review it: rutile requests && rutile approve " + res.ID,
		}, nil
	})
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "delegate_access",
		Description: "Mint a short-lived sub-token for a helper/sub-agent, limited to a SUBSET of this agent's paths. The child's access = its patterns ∩ this agent's live policy; it cannot delegate further or file requests. Pass the token to the sub-agent via its RUTILE_TOKEN env; never print it into shared context.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in delegateIn) (*mcp.CallToolResult, delegateOut, error) {
		var res protocol.DelegateResult
		p := protocol.DelegateParams{Label: in.Label, Patterns: in.Patterns, TTL: in.TTL}
		if err := ipc.Call("delegate", auth, p, &res); err != nil {
			return nil, delegateOut{}, mcpFriendly(err)
		}
		return nil, delegateOut{ID: res.ID, Token: res.Token, ExpiresAt: res.ExpiresAt.Format(time.RFC3339)}, nil
	})
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "store_status",
		Description: "Check whether the secret store is unlocked and how many secrets this agent can see. Cheap; call before asking the user to unlock.",
		Annotations: readOnly,
	}, func(ctx context.Context, req *mcp.CallToolRequest, in storeStatusIn) (*mcp.CallToolResult, storeStatusOut, error) {
		var st protocol.StatusResult
		if err := ipc.Call("status", auth, nil, &st); err != nil {
			return nil, storeStatusOut{}, mcpFriendly(err)
		}
		var visible protocol.ListResult
		if err := ipc.Call("list", auth, protocol.ListParams{}, &visible); err != nil {
			return nil, storeStatusOut{}, mcpFriendly(err)
		}
		return nil, storeStatusOut{Unlocked: st.Unlocked, VisibleSecrets: len(visible.Paths)}, nil
	})
	return srv
}

func cmdMCP() *cobra.Command {
	var httpAddr, tlsCert, tlsKey, tlsClientCA, spiffeTrustDomain string
	var insecure bool
	var rateLimit int
	c := &cobra.Command{
		Use:    "mcp",
		Short:  "Запустить MCP-сервер для AI-агента (stdio; --http для сетевых агентов)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			if httpAddr != "" {
				return serveMCPHTTP(httpAddr, tlsCert, tlsKey, tlsClientCA, spiffeTrustDomain, insecure, rateLimit)
			}
			auth, err := agentAuthFromEnv()
			if err != nil {
				return err
			}
			return newMCPServer(auth).Run(context.Background(), &mcp.StdioTransport{})
		},
	}
	c.Flags().StringVar(&httpAddr, "http", "", "слушать HTTP (например 0.0.0.0:7997); агент передаёт токен в Authorization: Bearer")
	c.Flags().StringVar(&tlsCert, "tls-cert", "", "PEM-сертификат: включает HTTPS (обязателен для не-loopback)")
	c.Flags().StringVar(&tlsKey, "tls-key", "", "PEM-ключ сертификата")
	c.Flags().BoolVar(&insecure, "insecure", false, "явно разрешить не-loopback HTTP без TLS (не рекомендуется)")
	c.Flags().StringVar(&tlsClientCA, "tls-client-ca", "", "PEM CA клиентских сертификатов: включает mTLS; SPIFFE ID вида spiffe://…/agent/<name> аутентифицирует агента без Bearer")
	c.Flags().StringVar(&spiffeTrustDomain, "spiffe-trust-domain", "", "разрешённый SPIFFE trust domain для certificate-only agent identity")
	c.Flags().IntVar(&rateLimit, "rate-limit", 120, "запросов в минуту с одного IP (burst = половина); 0 — без лимита")
	return c
}

// serveMCPHTTP exposes the same tools over streamable HTTP. The caller is
// identified per request by "Authorization: Bearer rtl_..." — this is what
// lets other agent frameworks and remote (a2a-style) setups talk to
// rutile, each under its own token and policy.
func validateSPIFFETrustDomain(domain string) error {
	if domain == "" || len(domain) > 255 {
		return errors.New("SPIFFE trust domain must be 1..255 characters")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 {
			return errors.New("SPIFFE trust domain contains an empty or oversized DNS label")
		}
		for i, r := range label {
			alnum := r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
			if !alnum && (r != '-' || i == 0 || i == len(label)-1) {
				return errors.New("SPIFFE trust domain must use lowercase DNS labels")
			}
		}
	}
	return nil
}

// certAgentName maps a verified client certificate to an agent name only
// when its SPIFFE URI belongs to the explicitly configured trust domain.
func certAgentName(cert *x509.Certificate, trustDomain string) (name, id string) {
	if trustDomain == "" {
		return "", ""
	}
	for _, u := range cert.URIs {
		if u.Scheme != "spiffe" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || !strings.EqualFold(u.Host, trustDomain) {
			continue
		}
		parts := strings.Split(u.Path, "/")
		if len(parts) == 3 && parts[0] == "" && parts[1] == "agent" && agents.ValidateName(parts[2]) == nil {
			return parts[2], u.String()
		}
	}
	return "", ""
}

func serveMCPHTTP(addr, tlsCert, tlsKey, tlsClientCA, spiffeTrustDomain string, insecure bool, ratePerMin int) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("bad --http address %q: %w", addr, err)
	}
	withTLS := tlsCert != "" || tlsKey != ""
	if withTLS && (tlsCert == "" || tlsKey == "") {
		return errors.New("--tls-cert и --tls-key задаются вместе")
	}
	if tlsClientCA != "" && !withTLS {
		return errors.New("--tls-client-ca требует --tls-cert/--tls-key")
	}
	if spiffeTrustDomain != "" {
		if tlsClientCA == "" {
			return errors.New("--spiffe-trust-domain requires --tls-client-ca")
		}
		if err := validateSPIFFETrustDomain(spiffeTrustDomain); err != nil {
			return err
		}
	}
	if ratePerMin < 0 {
		return errors.New("--rate-limit must be zero or a positive number of requests per minute")
	}
	loopback := host == "localhost"
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		loopback = true
	}
	if !loopback && !withTLS {
		if !insecure {
			return errors.New("не-loopback адрес без TLS: токены пойдут открытым текстом.\n" +
				"Задайте --tls-cert/--tls-key, либо явно подтвердите риск флагом --insecure (например, внутри SSH-туннеля)")
		}
		fmt.Fprintln(os.Stderr, "⚠ ВНИМАНИЕ: --insecure на не-loopback адресе — токены передаются открытым текстом")
	}
	reg := agents.New(paths.AgentsDir())
	mcpHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		// mTLS/SPIFFE identity first: a verified client cert in the configured
		// trust domain authenticates without a bearer token.
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			if name, id := certAgentName(r.TLS.PeerCertificates[0], spiffeTrustDomain); name != "" {
				if a, err := reg.Get(name); err == nil && a.Usable("http", time.Now().UTC()) == nil {
					return newMCPServer(&protocol.AgentAuth{Agent: a.Name, Cert: id, Transport: "http"})
				}
				return nil
			}
		}
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			return nil // -> 400 from the SDK handler
		}
		a, err := reg.FindByToken(strings.TrimSpace(token))
		if err != nil {
			return nil
		}
		// Transport is stamped here so the daemon can enforce local-only tokens.
		return newMCPServer(&protocol.AgentAuth{Agent: a.Name, Token: strings.TrimSpace(token), Transport: "http"})
	}, nil)

	var handler http.Handler = mcpHandler
	if ratePerMin > 0 {
		rl := ratelimit.New(ratePerMin, ratePerMin/2)
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			if !rl.Allow(host) {
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			mcpHandler.ServeHTTP(w, r)
		})
	}
	handler = limitRequestBody(handler, maxMCPRequestBody)

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	if withTLS {
		if tlsClientCA != "" {
			caPEM, err := os.ReadFile(tlsClientCA)
			if err != nil {
				return err
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				return errors.New("no certificates parsed from --tls-client-ca")
			}
			srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
			if spiffeTrustDomain != "" {
				fmt.Fprintf(os.Stderr, "rutile MCP: https://%s (mTLS; SPIFFE spiffe://%s/agent/<name> or Bearer)\n", addr, spiffeTrustDomain)
			} else {
				fmt.Fprintf(os.Stderr, "rutile MCP: https://%s (mTLS; Bearer required because --spiffe-trust-domain is unset)\n", addr)
			}
		} else {
			fmt.Fprintf(os.Stderr, "rutile MCP: https://%s (Authorization: Bearer <token>)\n", addr)
		}
		if srv.TLSConfig == nil {
			srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		return srv.ListenAndServeTLS(tlsCert, tlsKey)
	}
	fmt.Fprintf(os.Stderr, "rutile MCP: http://%s (Authorization: Bearer <token>)\n", addr)
	return srv.ListenAndServe()
}

func limitRequestBody(next http.Handler, maxBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// mcpFriendly rewrites daemon errors into instructions the agent can relay.
func mcpFriendly(err error) error {
	var rpcErr *protocol.RPCError
	if errors.As(err, &rpcErr) && rpcErr.Code == protocol.CodeLocked {
		return errors.New("the secret store is locked — ask the user to run 'rutile unlock' in a terminal, then retry")
	}
	return err
}

// --- edit via $EDITOR ---

func runEdit(cmd *cobra.Command, args []string) error {
	if err := requireInit(); err != nil {
		return err
	}
	path := args[0]
	var current protocol.GetResult
	err := callUnlocked("get", protocol.GetParams{Path: path}, &current)
	var rpcErr *protocol.RPCError
	if err != nil && !(errors.As(err, &rpcErr) && rpcErr.Code == protocol.CodeNotFound) {
		return err
	}
	// Plaintext must not touch the world-shared temp dir: keep the working
	// copy inside the 0700 store home and best-effort shred it afterwards.
	tmp, err := os.CreateTemp(paths.Dir(), ".edit-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if st, err := os.Stat(tmpName); err == nil {
			_ = os.WriteFile(tmpName, make([]byte, st.Size()), 0o600)
		}
		os.Remove(tmpName)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(current.Value); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	ec := exec.Command(editor, tmpName)
	ec.Stdin, ec.Stdout, ec.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := ec.Run(); err != nil {
		return err
	}
	st, err := os.Stat(tmpName)
	if err != nil {
		return err
	}
	if st.Size() > int64(store.MaxSecretValueLen) {
		return fmt.Errorf("secret value is too large (max 512 KiB)")
	}
	edited, err := os.ReadFile(tmpName)
	if err != nil {
		return err
	}
	value := string(edited)
	if value == current.Value {
		fmt.Println("без изменений")
		return nil
	}
	if err := callUnlocked("put", protocol.PutParams{Path: path, Value: value}, nil); err != nil {
		return err
	}
	fmt.Println("сохранено:", path)
	return nil
}
