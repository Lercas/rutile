// Package ipc is the client side of the daemon's unix socket, including
// gpg-agent-style auto-spawn: if no daemon is running, the client starts
// one in the background and waits for the socket to come up.
package ipc

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/Lercas/rutile/internal/paths"
	"github.com/Lercas/rutile/internal/protocol"
)

func dial() (net.Conn, error) {
	return net.DialTimeout("unix", paths.SocketPath(), time.Second)
}

// EnsureDaemon spawns `rutile daemon` detached if the socket is dead.
func EnsureDaemon() error {
	if conn, err := dial(); err == nil {
		conn.Close()
		return nil
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	logf, err := os.OpenFile(paths.DaemonLogFile(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	cmd := exec.Command(self, "daemon")
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cannot start daemon: %w", err)
	}
	go cmd.Wait() // reap if it exits while we're still alive
	for i := 0; i < 40; i++ {
		time.Sleep(50 * time.Millisecond)
		if conn, err := dial(); err == nil {
			conn.Close()
			return nil
		}
	}
	return fmt.Errorf("daemon did not come up; see %s", paths.DaemonLogFile())
}

func reqID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Call performs one request/response round-trip, auto-spawning the daemon.
// auth==nil means a human CLI call.
func Call(method string, auth *protocol.AgentAuth, params, out any) error {
	if err := EnsureDaemon(); err != nil {
		return err
	}
	conn, err := dial()
	if err != nil {
		return err
	}
	defer conn.Close()

	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		raw = b
	} else {
		raw = json.RawMessage(`{}`)
	}
	id, err := reqID()
	if err != nil {
		return fmt.Errorf("generate request id: %w", err)
	}
	req := protocol.Request{ID: id, Method: method, Auth: auth, Params: raw}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return err
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return err
		}
		return fmt.Errorf("daemon closed connection")
	}
	var resp protocol.Response
	if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
		return err
	}
	if resp.Error != nil {
		return resp.Error
	}
	if out != nil {
		return json.Unmarshal(resp.Result, out)
	}
	return nil
}
