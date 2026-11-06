package engine

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// setQUICDontFragment refuses socket creation if probes could fragment.
func setQUICDontFragment(network, _ string, raw syscall.RawConn) error {
	level, option := unix.IPPROTO_IP, unix.IP_DONTFRAG
	if network == "udp6" {
		level, option = unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), level, option, 1)
	}); err != nil {
		return err
	}
	return sockErr
}

var dontFragmentControl = setQUICDontFragment
