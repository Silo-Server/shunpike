//go:build !linux && !darwin

package engine

import "syscall"

var dontFragmentControl func(string, string, syscall.RawConn) error
