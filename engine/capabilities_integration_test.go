//go:build linux

package engine

import (
	"context"
	"net"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

type countedSocket struct {
	net.PacketConn
	writes int
	closed bool
	rcvbuf int
	sndbuf int
	t      *testing.T
}

func (c *countedSocket) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writes++
	return c.PacketConn.WriteTo(p, addr)
}

func (c *countedSocket) SyscallConn() (syscall.RawConn, error) {
	return c.PacketConn.(syscall.Conn).SyscallConn()
}

func (c *countedSocket) Close() error {
	c.closed = true
	raw, err := c.SyscallConn()
	if err != nil {
		c.t.Error(err)
	} else if err := raw.Control(func(fd uintptr) {
		var err error
		c.rcvbuf, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		if err != nil {
			c.t.Error(err)
		}
		c.sndbuf, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
		if err != nil {
			c.t.Error(err)
		}
	}); err != nil {
		c.t.Error(err)
	}
	return c.PacketConn.Close()
}

func TestProbeCapabilitiesSendsNothing(t *testing.T) {
	oldListen := listenCapabilities
	var sockets []*countedSocket
	listenCapabilities = func(ctx context.Context, network, address string) (net.PacketConn, error) {
		if network != "udp4" && network != "udp6" {
			t.Fatalf("network = %q; want udp4 or udp6", network)
		}
		if address != "127.0.0.1:0" && address != "[::1]:0" {
			t.Fatalf("address = %q; want loopback with ephemeral port", address)
		}
		pc, err := oldListen(ctx, network, address)
		if err != nil {
			return nil, err
		}
		if pc.(*net.UDPConn).RemoteAddr() != nil {
			t.Fatal("capability socket is connected; want unconnected")
		}
		c := &countedSocket{PacketConn: pc, t: t}
		sockets = append(sockets, c)
		return c, nil
	}
	t.Cleanup(func() { listenCapabilities = oldListen })
	got, err := ProbeCapabilities(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Platform != runtime.GOOS || got.BBRSender != "bbr3" {
		t.Errorf("report = %+v; want Linux and bbr3", got)
	}
	for name, support := range map[string]Support{"GSO": got.GSO, "GRO": got.GRO, "DF": got.DF} {
		if support != Supported && support != Unsupported {
			t.Errorf("%s support = %v; want Supported or Unsupported", name, support)
		}
	}
	if len(sockets) == 0 {
		t.Fatal("opened no sockets; want a local capability probe")
	}
	for _, socket := range sockets {
		if socket.writes != 0 || !socket.closed {
			t.Errorf("writes = %d, closed = %v; want 0, true", socket.writes, socket.closed)
		}
	}
	for name, buffer := range map[string]struct {
		report BufferReport
		grant  int
	}{
		"receive": {got.ReceiveBuffer, sockets[0].rcvbuf},
		"send":    {got.SendBuffer, sockets[0].sndbuf},
	} {
		if buffer.report.Requested != SocketBufferBytes || buffer.report.Granted != buffer.grant || buffer.grant <= 0 {
			t.Errorf("%s buffer = %+v; want request %d, raw grant %d", name, buffer.report, SocketBufferBytes, buffer.grant)
		}
		if buffer.report.Forced == (buffer.report.ForceErrno != "") {
			t.Errorf("%s buffer = %+v; want exactly one force outcome", name, buffer.report)
		}
	}
}
