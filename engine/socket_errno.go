//go:build unix

package engine

import (
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

func socketErrnoName(errno syscall.Errno) string {
	if name := unix.ErrnoName(errno); name != "" {
		return name
	}
	return strconv.Itoa(int(errno))
}
