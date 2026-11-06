package engine

import (
	"bytes"
	"net"
	"testing"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/types/key"
)

type segmentBind struct {
	fixtureBind
	calls     int
	datagrams [][]byte
}

func (b *segmentBind) Send(bufs [][]byte, _ conn.Endpoint, offset int) error {
	b.calls++
	for _, buf := range bufs {
		if offset != 8 {
			panic("missing Geneve headroom")
		}
		// Model the relay writing its header after all segment copies exist.
		copy(buf[:offset], bytes.Repeat([]byte{0xff}, offset))
	}
	for _, buf := range bufs {
		b.datagrams = append(b.datagrams, bytes.Clone(buf[offset:]))
	}
	return nil
}
func TestSegmentedWrite(t *testing.T) {
	b := &segmentBind{fixtureBind: fixtureBind{closed: make(chan struct{})}}
	p := newPacketConn(b, nil, nil)
	defer func() { _ = p.Close() }()
	k := key.NewNode().Public()
	p.setPeers(map[key.NodePublic]conn.Endpoint{k: fixtureEndpoint{}})
	if p.SupportsGSO() {
		t.Fatal("GSO enabled by default")
	}
	p.SetGSO(true)
	if !p.SupportsGSO() {
		t.Fatal("GSO flag ignored")
	}
	payload := []byte("abcdefghij")
	n, err := p.WriteSegments(payload, Addr{Key: nodeKey(k)}, 4)
	if err != nil || n != len(payload) {
		t.Fatalf("write %d, %v", n, err)
	}
	if b.calls != 1 || len(b.datagrams) != 3 {
		t.Fatalf("sends=%d datagrams=%d", b.calls, len(b.datagrams))
	}
	for i, want := range []string{"abcd", "efgh", "ij"} {
		if string(b.datagrams[i]) != want {
			t.Fatalf("segment %d=%q, want %q", i, b.datagrams[i], want)
		}
	}
	if !bytes.Equal(payload, []byte("abcdefghij")) {
		t.Fatal("caller buffer modified")
	}
	c := p.Counters()
	if c.BindSends != 1 || c.SendDatagrams != 3 || c.MeanDatagramsPerSend != 3 {
		t.Fatalf("counters=%+v", c)
	}
	p.SetGSO(false)
	if _, err := p.WriteTo([]byte("old"), Addr{Key: nodeKey(k)}); err != nil {
		t.Fatal(err)
	}
	if b.calls != 2 || string(b.datagrams[3]) != "old" {
		t.Fatal("legacy path changed")
	}
	if _, err := p.WriteSegments(payload, &net.IPAddr{}, 4); err == nil {
		t.Fatal("accepted wrong address")
	}
}
