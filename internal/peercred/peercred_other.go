//go:build !linux && !darwin

package peercred

func peerUID(fd uintptr) (uint32, error) { return 0, ErrUnavailable }
