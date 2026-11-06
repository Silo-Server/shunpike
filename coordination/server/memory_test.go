package server_test

import (
	"github.com/darthShadow/shunpike/coordination/server"
	"github.com/darthShadow/shunpike/coordination/server/storetest"
	"testing"
)

func TestMemoryStoreConformance(t *testing.T) {
	storetest.Run(t, func(*testing.T) server.Store { return server.NewMemoryStore() })
}
