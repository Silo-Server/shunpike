package engine

import (
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDontFragmentOnSocket(t *testing.T) {
	lc := net.ListenConfig{Control: dontFragmentControl}
	pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	raw, err := pc.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var value int
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		value, socketErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER)
	}); err != nil {
		t.Fatal(err)
	}
	if socketErr != nil || value != unix.IP_PMTUDISC_DO {
		t.Fatalf("DF=%d error=%v, want IP_PMTUDISC_DO", value, socketErr)
	}
}
