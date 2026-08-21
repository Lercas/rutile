//go:build darwin || linux

package peercred

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestUIDFromUnixPeer(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "peer.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	result := make(chan error, 1)
	go func() {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			conn.Close()
		}
		result <- err
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	uid, err := UID(conn)
	if err != nil || uid != uint32(os.Getuid()) {
		t.Fatalf("uid=%d want=%d err=%v", uid, os.Getuid(), err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
