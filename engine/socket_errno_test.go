//go:build unix

package engine

import (
	"syscall"
	"testing"
)

func TestSocketErrnoName(t *testing.T) {
	for _, tt := range []struct {
		name  string
		errno syscall.Errno
		want  string
	}{
		{"known", syscall.EPERM, "EPERM"},
		{"unknown", syscall.Errno(4095), "4095"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := socketErrnoName(tt.errno); got != tt.want {
				t.Errorf("socketErrnoName(%d) = %q; want %q", tt.errno, got, tt.want)
			}
		})
	}
}
