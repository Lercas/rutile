//go:build darwin

package peercred

import "golang.org/x/sys/unix"

func peerUID(fd uintptr) (uint32, error) {
	x, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	return x.Uid, nil
}
