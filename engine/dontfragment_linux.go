package engine

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// setQUICDontFragment refuses socket creation if probes could fragment.
func setQUICDontFragment(network, _ string, raw syscall.RawConn) error {
	level, option := unix.IPPROTO_IP, unix.IP_MTU_DISCOVER
	if network == "udp6" {
		level, option = unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), level, option, unix.IP_PMTUDISC_DO)
	}); err != nil {
		return err
	}
	return sockErr
}

var dontFragmentControl = setQUICDontFragment
