package engine

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
	"tailscale.com/types/logger"
)

func socketCapabilities(pc net.PacketConn, network string, logf logger.Logf) CapabilityReport {
	var report CapabilityReport
	socket, ok := pc.(syscall.Conn)
	if !ok {
		logf("capability socket has no syscall connection")
		return report
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		logf("capability socket syscall connection: %v", err)
		return report
	}
	if err := raw.Control(func(fd uintptr) {
		_, gsoErr := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		_, groErr := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO)
		report.GSO = socketSupport("GSO", gsoErr, logf)
		report.GRO = socketSupport("GRO", groErr, logf)

		level, option, value := unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO
		if network == "udp6" {
			level, option, value = unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO
		}
		report.DF = socketSupport("DF", unix.SetsockoptInt(int(fd), level, option, value), logf)
		report.ReceiveBuffer = socketBuffer(int(fd), unix.SO_RCVBUF, unix.SO_RCVBUFFORCE, logf)
		report.SendBuffer = socketBuffer(int(fd), unix.SO_SNDBUF, unix.SO_SNDBUFFORCE, logf)
	}); err != nil {
		logf("capability socket control: %v", err)
	}
	return report
}

func socketSupport(feature string, err error, logf logger.Logf) Support {
	if err == nil {
		return Supported
	}
	if errors.Is(err, unix.ENOPROTOOPT) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL) {
		return Unsupported
	}
	logf("capability %s is unknown: %v", feature, err)
	return SupportUnknown
}

func socketBuffer(fd, option, forceOption int, logf logger.Logf) BufferReport {
	report := BufferReport{Requested: SocketBufferBytes}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, forceOption, SocketBufferBytes); err == nil {
		report.Forced = true
	} else {
		var errno syscall.Errno
		if errors.As(err, &errno) {
			report.ForceErrno = socketErrnoName(errno)
		}
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, option, SocketBufferBytes); err != nil {
			logf("capability buffer option %d: %v", option, err)
		}
	}
	granted, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, option)
	if err != nil {
		logf("capability buffer readback option %d: %v", option, err)
	} else {
		report.Granted = granted
	}
	return report
}
