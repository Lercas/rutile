// Package paths resolves all on-disk locations of the rutile home
// directory. Everything lives under $RUTILE_DIR (default ~/.rutile).
package paths

import (
	"os"
	"path/filepath"
)

func Dir() string {
	if d := os.Getenv("RUTILE_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".rutile"
	}
	return filepath.Join(home, ".rutile")
}

func StoreDir() string        { return filepath.Join(Dir(), "store") }
func IdentityFile() string    { return filepath.Join(Dir(), "identities.age") }
func RecipientsFile() string  { return filepath.Join(Dir(), "recipients.txt") }
func AgentsDir() string       { return filepath.Join(Dir(), "agents") }
func PolicyFile() string      { return filepath.Join(Dir(), "policy.yaml") }
func RequestsFile() string    { return filepath.Join(Dir(), "requests.yaml") }
func DelegationsFile() string { return filepath.Join(Dir(), "delegations.yaml") }
func AuditFile() string       { return filepath.Join(Dir(), "audit.log") }
func SocketPath() string {
	if s := os.Getenv("RUTILE_SOCKET"); s != "" {
		return s
	}
	return filepath.Join(Dir(), "daemon.sock")
}
func DaemonLogFile() string { return filepath.Join(Dir(), "daemon.log") }

// Initialized reports whether `rutile init` has been run.
func Initialized() bool {
	_, err := os.Stat(IdentityFile())
	return err == nil
}
