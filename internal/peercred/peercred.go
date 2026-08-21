// Package peercred resolves the uid of the process on the other end of a
// unix socket connection (SO_PEERCRED on Linux, LOCAL_PEERCRED on Darwin).
// It backs "system mode": a daemon running under a dedicated uid can limit
// human-privileged operations to an explicit admin uid.
package peercred

import (
	"errors"
	"net"
)

var ErrUnavailable = errors.New("peer credentials unavailable")

// UID returns the peer process uid of a unix-socket connection.
func UID(conn net.Conn) (uint32, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, ErrUnavailable
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, ErrUnavailable
	}
	var uid uint32
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		uid, opErr = peerUID(fd)
	}); err != nil {
		return 0, ErrUnavailable
	}
	if opErr != nil {
		return 0, ErrUnavailable
	}
	return uid, nil
}
